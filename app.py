from flask import Flask, jsonify, render_template, request
from database import init_db, get_events, get_stats, clear_events, add_event
from monitor import IDSMonitor
from datetime import datetime, timezone

app = Flask(__name__)
init_db()
monitor = IDSMonitor()

@app.route("/")
def index():
    return render_template("index.html")

@app.get("/api/status")
def api_status():
    return jsonify(monitor.status())

@app.get("/api/events")
def api_events():
    limit = min(int(request.args.get("limit", 100)), 500)
    return jsonify(get_events(limit))

@app.get("/api/stats")
def api_stats():
    return jsonify(get_stats())

@app.post("/api/start")
def api_start():
    data = request.get_json(silent=True) or {}
    interface = (data.get("interface") or "").strip() or None
    result = monitor.start(interface=interface)
    return jsonify(result), (200 if result["ok"] else 400)

@app.post("/api/stop")
def api_stop():
    return jsonify(monitor.stop())

@app.post("/api/demo")
def api_demo():
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    samples = [
        ("DEMO", "192.168.1.25", "192.168.1.1", "TCP", 443, "INFO", "Sample HTTPS-like traffic (simulated)"),
        ("DEMO", "192.168.1.25", "192.168.1.1", "TCP", 22, "MEDIUM", "Simulated unusual connection pattern"),
        ("DEMO", "192.168.1.77", "192.168.1.1", "TCP", 8080, "HIGH", "Simulated possible port scan pattern"),
    ]
    for source, src, dst, proto, port, severity, message in samples:
        add_event(source, src, dst, proto, port, severity, message, now)
    return jsonify({"ok": True, "message": "Added 3 simulated demo events. These are not real attacks."})

@app.post("/api/clear")
def api_clear():
    clear_events()
    return jsonify({"ok": True})
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        threaded=True
    )
