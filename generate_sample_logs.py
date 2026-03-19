"""
generate_sample_logs.py
-----------------------
Generates realistic sample auth.log and apache.log files for testing.
Run this on Kali if /var/log/auth.log is empty or for demo purposes.

Usage: python3 generate_sample_logs.py
"""

import random
import os
from datetime import datetime, timedelta

ATTACKER_IPS = [
    "45.33.32.156", "192.168.1.105", "103.207.39.212",
    "185.220.101.45", "194.165.16.11", "31.184.198.23",
    "91.240.118.172", "198.199.105.93", "167.94.138.52",
    "45.142.212.100", "89.248.165.145", "162.55.32.12"
]
NORMAL_IPS = [
    "10.0.0.5", "10.0.0.6", "192.168.1.2", "192.168.1.3"
]
USERS = ["root", "admin", "ubuntu", "oracle", "pi", "test", "user", "deploy"]
MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "python-requests/2.28.0",
    "curl/7.88.1",
    "Nmap Scripting Engine",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
]
PATHS = [
    "/", "/index.php", "/wp-admin/", "/admin/", "/.env",
    "/phpmyadmin/", "/login", "/api/v1/users", "/config.php",
    "/etc/passwd", "/wp-login.php", "/../../../etc/passwd",
    "/shell.php", "/uploads/shell.php", "/backup.zip",
    "/api/users?id=1 OR 1=1", "/search?q=<script>alert(1)</script>",
]

def random_time(base, spread_hours=24):
    delta = timedelta(seconds=random.randint(0, spread_hours * 3600))
    return base - delta

def fmt_auth_time(dt):
    return f"{MONTHS[dt.month-1]} {dt.day:2d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"

def fmt_apache_time(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def generate_auth_log(path, base_time):
    lines = []
    hostname = "kali"

    # Brute force attacks from malicious IPs
    for ip in ATTACKER_IPS[:6]:
        count = random.randint(20, 80)
        for _ in range(count):
            t = random_time(base_time)
            user = random.choice(USERS)
            port = random.randint(30000, 65000)
            lines.append(
                f"{fmt_auth_time(t)} {hostname} sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {user} from {ip} port {port} ssh2\n"
            )
        # Occasionally succeed (suspicious)
        if random.random() > 0.7:
            t = random_time(base_time, 2)
            lines.append(
                f"{fmt_auth_time(t)} {hostname} sshd[{random.randint(1000,9999)}]: "
                f"Accepted password for root from {ip} port {random.randint(30000,65000)} ssh2\n"
            )

    # Invalid user attempts
    for ip in ATTACKER_IPS[6:]:
        count = random.randint(10, 40)
        for _ in range(count):
            t = random_time(base_time)
            user = random.choice(USERS)
            lines.append(
                f"{fmt_auth_time(t)} {hostname} sshd[{random.randint(1000,9999)}]: "
                f"Invalid user {user} from {ip} port {random.randint(30000,65000)}\n"
            )

    # Normal successful logins
    for ip in NORMAL_IPS:
        for _ in range(random.randint(2, 5)):
            t = random_time(base_time)
            lines.append(
                f"{fmt_auth_time(t)} {hostname} sshd[{random.randint(1000,9999)}]: "
                f"Accepted publickey for kali from {ip} port {random.randint(30000,65000)} ssh2\n"
            )

    random.shuffle(lines)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.writelines(lines)
    print(f"[+] Generated {len(lines)} auth.log entries -> {path}")

def generate_apache_log(path, base_time):
    lines = []
    codes = [200, 200, 200, 301, 404, 403, 500, 200]

    for ip in ATTACKER_IPS:
        count = random.randint(15, 50)
        for _ in range(count):
            t = random_time(base_time)
            path_hit = random.choice(PATHS)
            code = random.choice([200, 403, 404, 500])
            size = random.randint(200, 9000)
            ua = random.choice(UA_LIST)
            lines.append(
                f'{ip} - - [{fmt_apache_time(t)}] '
                f'"GET {path_hit} HTTP/1.1" {code} {size} "-" "{ua}"\n'
            )

    for ip in NORMAL_IPS:
        for _ in range(random.randint(5, 15)):
            t = random_time(base_time)
            code = random.choice(codes)
            size = random.randint(500, 5000)
            lines.append(
                f'{ip} - - [{fmt_apache_time(t)}] '
                f'"GET / HTTP/1.1" {code} {size} "-" "Mozilla/5.0"\n'
            )

    random.shuffle(lines)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.writelines(lines)
    print(f"[+] Generated {len(lines)} apache.log entries -> {path}")

if __name__ == "__main__":
    base = datetime.now()
    generate_auth_log("logs/auth.log", base)
    generate_apache_log("logs/apache.log", base)
    print("[+] Sample logs ready. Run: python3 app.py")
