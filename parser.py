"""
parser.py - Log ingestion, GeoIP enrichment, correlation engine
"""
import re, sqlite3, requests, time, os
from datetime import datetime
from collections import defaultdict

DB_PATH = "data/siem.db"
GEOIP_URL = "http://ip-api.com/json/{ip}?fields=country,city,isp,lat,lon,status"
BRUTE_FORCE_THRESHOLD = 5

SUSPICIOUS_PATHS = [
    r"\.env", r"wp-admin", r"phpmyadmin", r"\.php\b",
    r"etc/passwd", r"cmd=", r"exec\(", r"union.*select",
    r"<script", r"\.\./", r"shell\.", r"backup\.",
]
SUSPICIOUS_UA = ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "python-requests", "curl"]

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source TEXT, ip TEXT,
            event_type TEXT, detail TEXT, severity TEXT, score INTEGER
        );
        CREATE TABLE IF NOT EXISTS ip_stats (
            ip TEXT PRIMARY KEY, fail_count INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0, web_hits INTEGER DEFAULT 0,
            suspicious_hits INTEGER DEFAULT 0, severity TEXT DEFAULT 'INFO',
            country TEXT DEFAULT '', city TEXT DEFAULT '', isp TEXT DEFAULT '',
            lat REAL DEFAULT 0, lon REAL DEFAULT 0, last_seen TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, ip TEXT, rule TEXT, description TEXT, severity TEXT
        );
    """)
    conn.commit()
    conn.close()

def geoip_lookup(ip, cache={}):
    if ip in cache:
        return cache[ip]
    if ip.startswith(("10.", "192.168.", "127.", "172.")):
        cache[ip] = {"country": "Internal", "city": "", "isp": "LAN", "lat": 0, "lon": 0}
        return cache[ip]
    try:
        r = requests.get(GEOIP_URL.format(ip=ip), timeout=3)
        data = r.json()
        if data.get("status") == "success":
            result = {k: data.get(k, "") for k in ["country","city","isp","lat","lon"]}
            cache[ip] = result
            time.sleep(0.05)
            return result
    except Exception:
        pass
    cache[ip] = {"country": "Unknown", "city": "", "isp": "", "lat": 0, "lon": 0}
    return cache[ip]

AUTH_FAIL_RE    = re.compile(r"(\w+\s+\d+\s+[\d:]+).*Failed password for (\S+) from ([\d.]+)")
AUTH_INVALID_RE = re.compile(r"(\w+\s+\d+\s+[\d:]+).*Invalid user (\S+) from ([\d.]+)")
AUTH_SUCCESS_RE = re.compile(r"(\w+\s+\d+\s+[\d:]+).*Accepted (\S+) for (\S+) from ([\d.]+)")

def parse_auth_log(path):
    events = []
    if not os.path.exists(path):
        return events
    with open(path, errors="ignore") as f:
        for line in f:
            m = AUTH_FAIL_RE.search(line)
            if m:
                events.append({"timestamp": m.group(1), "source": "auth.log", "ip": m.group(3),
                    "event_type": "SSH_FAIL", "detail": f"Failed password for: {m.group(2)}", "severity": "MEDIUM", "score": 2})
                continue
            m = AUTH_INVALID_RE.search(line)
            if m:
                events.append({"timestamp": m.group(1), "source": "auth.log", "ip": m.group(3),
                    "event_type": "SSH_INVALID_USER", "detail": f"Invalid user: {m.group(2)}", "severity": "MEDIUM", "score": 2})
                continue
            m = AUTH_SUCCESS_RE.search(line)
            if m:
                events.append({"timestamp": m.group(1), "source": "auth.log", "ip": m.group(4),
                    "event_type": "SSH_SUCCESS", "detail": f"Login accepted ({m.group(2)}) for {m.group(3)}", "severity": "INFO", "score": 0})
    return events

APACHE_RE = re.compile(r'([\d.]+) .+ \[(.+?)\] "(\w+) (.+?) HTTP.+?" (\d+) (\d+) ".+?" "(.+?)"')

def parse_apache_log(path):
    events = []
    if not os.path.exists(path):
        return events
    with open(path, errors="ignore") as f:
        for line in f:
            m = APACHE_RE.search(line)
            if not m:
                continue
            ip, ts, method, path_hit, code, size, ua = m.groups()
            severity, score, flags = "INFO", 0, []
            for pattern in SUSPICIOUS_PATHS:
                if re.search(pattern, path_hit, re.IGNORECASE):
                    flags.append("suspicious_path"); severity = "HIGH"; score = 3; break
            for sus_ua in SUSPICIOUS_UA:
                if sus_ua.lower() in ua.lower():
                    flags.append(f"scanner:{sus_ua}"); severity = "HIGH"; score = 3; break
            event_type = "WEB_SCAN" if flags else "WEB_ACCESS"
            detail = f"{method} {path_hit[:80]} [{code}]"
            if flags:
                detail += f" | {', '.join(flags)}"
            events.append({"timestamp": ts, "source": "apache.log", "ip": ip,
                "event_type": event_type, "detail": detail, "severity": severity, "score": score})
    return events

def apply_correlation_rules(conn, ip_stats):
    c = conn.cursor()
    alerts = []
    for ip, stats in ip_stats.items():
        fails, success, web, sus_web = (
            stats["fail_count"], stats["success_count"],
            stats["web_hits"],   stats["suspicious_hits"]
        )
        if fails >= 20:
            alerts.append((datetime.now().isoformat(), ip, "BRUTE_FORCE_SSH",
                f"SSH brute force: {fails} failed login attempts", "CRITICAL"))
        elif fails >= BRUTE_FORCE_THRESHOLD:
            alerts.append((datetime.now().isoformat(), ip, "BRUTE_FORCE_SSH",
                f"SSH brute force: {fails} failed login attempts", "HIGH"))
        if fails >= 3 and sus_web >= 3:
            alerts.append((datetime.now().isoformat(), ip, "CORRELATED_ATTACK",
                f"Multi-vector attack: {fails} SSH fails + {sus_web} suspicious web hits", "CRITICAL"))
        if success >= 1 and fails >= 5:
            alerts.append((datetime.now().isoformat(), ip, "SUCCESSFUL_BRUTE_FORCE",
                f"SSH login SUCCEEDED after {fails} failures — POSSIBLE COMPROMISE", "CRITICAL"))
        if sus_web >= 10:
            alerts.append((datetime.now().isoformat(), ip, "WEB_SCANNER",
                f"Automated web scanner detected: {sus_web} suspicious requests", "HIGH"))
    if alerts:
        c.executemany("INSERT INTO alerts (timestamp,ip,rule,description,severity) VALUES (?,?,?,?,?)", alerts)
        conn.commit()
    return len(alerts)

def ingest(auth_path="/var/log/auth.log", apache_path="/var/log/apache2/access.log", demo_mode=False):
    if demo_mode:
        auth_path = "logs/auth.log"
        apache_path = "logs/apache.log"
    print("[*] Initialising database...")
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript("DELETE FROM events; DELETE FROM ip_stats; DELETE FROM alerts;")
    conn.commit()
    print("[*] Parsing auth.log...")
    auth_events = parse_auth_log(auth_path)
    print(f"    -> {len(auth_events)} events")
    print("[*] Parsing apache.log...")
    web_events = parse_apache_log(apache_path)
    print(f"    -> {len(web_events)} events")
    all_events = auth_events + web_events
    ip_stats = defaultdict(lambda: {"fail_count":0,"success_count":0,"web_hits":0,"suspicious_hits":0,"severity":"INFO","last_seen":""})
    rows = []
    for ev in all_events:
        ip = ev["ip"]
        if ev["event_type"] == "SSH_FAIL": ip_stats[ip]["fail_count"] += 1
        elif ev["event_type"] == "SSH_SUCCESS": ip_stats[ip]["success_count"] += 1
        elif ev["event_type"] == "WEB_SCAN": ip_stats[ip]["web_hits"] += 1; ip_stats[ip]["suspicious_hits"] += 1
        elif ev["event_type"] == "WEB_ACCESS": ip_stats[ip]["web_hits"] += 1
        ip_stats[ip]["last_seen"] = ev["timestamp"]
        rows.append((ev["timestamp"],ev["source"],ip,ev["event_type"],ev["detail"],ev["severity"],ev["score"]))
    c.executemany("INSERT INTO events (timestamp,source,ip,event_type,detail,severity,score) VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit()
    unique_ips = list(ip_stats.keys())
    print(f"[*] GeoIP lookup for {len(unique_ips)} unique IPs...")
    for i, ip in enumerate(unique_ips):
        geo = geoip_lookup(ip)
        stats = ip_stats[ip]
        if stats["fail_count"] >= 20 or (stats["fail_count"] >= 3 and stats["suspicious_hits"] >= 3):
            sev = "CRITICAL"
        elif stats["fail_count"] >= BRUTE_FORCE_THRESHOLD or stats["suspicious_hits"] >= 5:
            sev = "HIGH"
        elif stats["fail_count"] >= 2 or stats["suspicious_hits"] >= 1:
            sev = "MEDIUM"
        else:
            sev = "INFO"
        ip_stats[ip]["severity"] = sev
        c.execute("INSERT OR REPLACE INTO ip_stats (ip,fail_count,success_count,web_hits,suspicious_hits,severity,country,city,isp,lat,lon,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (ip, stats["fail_count"], stats["success_count"], stats["web_hits"], stats["suspicious_hits"],
             sev, geo["country"], geo["city"], geo["isp"], geo["lat"], geo["lon"], stats["last_seen"]))
        if (i+1) % 5 == 0:
            print(f"    -> {i+1}/{len(unique_ips)} IPs enriched")
    conn.commit()
    print("[*] Running correlation rules...")
    n = apply_correlation_rules(conn, ip_stats)
    print(f"    -> {n} alerts generated")
    conn.close()
    print("[+] Ingest complete.")

if __name__ == "__main__":
    import sys
    ingest(demo_mode="--demo" in sys.argv)
