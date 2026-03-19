"""
app.py - Flask server + REST API for the SIEM dashboard
Usage:
    python3 app.py --demo    (sample logs)
    python3 app.py           (real /var/log/ — run as root)
"""
import sys, sqlite3, os
from flask import Flask, render_template, jsonify, request
from parser import ingest, init_db

app = Flask(__name__)
DB_PATH = "data/siem.db"
DEMO_MODE = "--demo" in sys.argv

def query_db(sql, args=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/summary")
def api_summary():
    return jsonify({
        "total_events":    query_db("SELECT COUNT(*) AS n FROM events")[0]["n"],
        "total_alerts":    query_db("SELECT COUNT(*) AS n FROM alerts")[0]["n"],
        "critical_alerts": query_db("SELECT COUNT(*) AS n FROM alerts WHERE severity='CRITICAL'")[0]["n"],
        "high_alerts":     query_db("SELECT COUNT(*) AS n FROM alerts WHERE severity='HIGH'")[0]["n"],
        "unique_ips":      query_db("SELECT COUNT(*) AS n FROM ip_stats")[0]["n"],
        "critical_ips":    query_db("SELECT COUNT(*) AS n FROM ip_stats WHERE severity='CRITICAL'")[0]["n"],
        "top_attacker":    (query_db("SELECT ip FROM ip_stats ORDER BY fail_count+suspicious_hits DESC LIMIT 1") or [{"ip":"—"}])[0]["ip"],
    })

@app.route("/api/alerts")
def api_alerts():
    return jsonify(query_db("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50"))

@app.route("/api/top_ips")
def api_top_ips():
    return jsonify(query_db("""
        SELECT ip,fail_count,success_count,web_hits,suspicious_hits,
               severity,country,city,isp,last_seen
        FROM ip_stats ORDER BY fail_count+suspicious_hits DESC LIMIT 20"""))

@app.route("/api/event_types")
def api_event_types():
    return jsonify(query_db("SELECT event_type,COUNT(*) AS count FROM events GROUP BY event_type ORDER BY count DESC"))

@app.route("/api/severity_breakdown")
def api_severity_breakdown():
    return jsonify(query_db("SELECT severity,COUNT(*) AS count FROM events GROUP BY severity ORDER BY count DESC"))

@app.route("/api/timeline")
def api_timeline():
    rows = query_db("""
        SELECT SUBSTR(timestamp,1,13) AS hour_bucket, COUNT(*) AS count,
               SUM(CASE WHEN severity IN ('CRITICAL','HIGH') THEN 1 ELSE 0 END) AS high_count
        FROM events GROUP BY hour_bucket ORDER BY hour_bucket DESC LIMIT 24""")
    return jsonify(list(reversed(rows)))

@app.route("/api/geo")
def api_geo():
    return jsonify(query_db("""
        SELECT ip,country,city,isp,severity,fail_count,suspicious_hits,lat,lon
        FROM ip_stats WHERE country!='' AND country!='Internal'
        ORDER BY fail_count+suspicious_hits DESC LIMIT 30"""))

@app.route("/api/events")
def api_events():
    page, per_page = int(request.args.get("page",1)), 25
    sev = request.args.get("severity","")
    src = request.args.get("source","")
    clauses, args = [], []
    if sev: clauses.append("severity=?"); args.append(sev)
    if src: clauses.append("source=?"); args.append(src)
    where = ("WHERE "+" AND ".join(clauses)) if clauses else ""
    total = query_db(f"SELECT COUNT(*) AS n FROM events {where}", args)[0]["n"]
    rows  = query_db(f"SELECT * FROM events {where} ORDER BY rowid DESC LIMIT ? OFFSET ?", args+[per_page,(page-1)*per_page])
    return jsonify({"total":total,"page":page,"events":rows})

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    try:
        ingest(demo_mode=DEMO_MODE)
        return jsonify({"status":"ok","message":"Logs re-ingested"})
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}), 500

if __name__ == "__main__":
    print(f"[*] SIEM Dashboard starting (demo={DEMO_MODE})")
    if not os.path.exists(DB_PATH):
        init_db()
        ingest(demo_mode=DEMO_MODE)
    app.run(host="0.0.0.0", port=5000, debug=False)
