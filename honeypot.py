from flask import Flask, request, render_template, redirect, url_for, session
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "honeypot_secret_key_2026"

ALERT_LOG_FILE = "honeypot_alerts.json"


# ── CORE LOGGING ENGINE ──────────────────────────────────────────────────────
# Central function that structures every security event into a JSON record.
# Assigns auto-incremented IDs and severity levels before persisting to disk.

def log_alert(event_type, ip, details):
    alert = {
        "id": _next_id(),
        "timestamp": datetime.now().isoformat(),   # ISO 8601 format: 2026-04-21T18:17:00
        "event_type": event_type,
        "source_ip": ip,
        "details": details,
        "severity": _get_severity(event_type)
    }
    alerts = _load_alerts()
    alerts.append(alert)
    with open(ALERT_LOG_FILE, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\n ALERT [{alert['severity']}] | {event_type} | IP: {ip} | {details}")
    return alert


def _load_alerts():
    """Reads persisted alerts from disk. Returns empty list if no log exists yet."""
    if os.path.exists(ALERT_LOG_FILE):
        with open(ALERT_LOG_FILE, "r") as f:
            return json.load(f)
    return []

def _next_id():
    return len(_load_alerts()) + 1

# Severity matrix — drives dashboard color-coding and triage priority

def _get_severity(event_type):
    severity_map = {
        "PAGE_VISIT":         "LOW",
        "LOGIN_ATTEMPT":      "HIGH",
        "API_PROBE":          "HIGH",
        "REPEATED_ATTEMPT":   "CRITICAL",  # Escalated after 2+ attempts from same IP
        "HIDDEN_FILE_ACCESS": "CRITICAL"
    }
    return severity_map.get(event_type, "MEDIUM")

def _get_client_ip():
    """Extracts real attacker IP. X-Forwarded-For handles reverse proxy / load balancer scenarios."""
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def _mask_password(password):
    """Stores evidence without logging plaintext credentials — security best practice."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


# ── HONEYPOT TRAP 1: Fake Admin Login (/admin) ───────────────────────────────
# Deception principle: page looks real, behaves normally, but every interaction
# is silently logged. Attacker never knows they've been detected.
# Repeated login attempts (≥3) auto-escalate to CRITICAL severity.

@app.route("/admin", methods=["GET", "POST"])
def fake_admin():
    ip = _get_client_ip()
    if request.method == "GET":
        log_alert("PAGE_VISIT", ip, "Attacker discovered and visited hidden /admin honeypot page")
        return render_template("fake_login.html", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Behavioral analysis: track repeat offenders by IP
    previous_attempts = [
        a for a in _load_alerts()
        if a["source_ip"] == ip and a["event_type"] == "LOGIN_ATTEMPT"
    ]
    event_type = "REPEATED_ATTEMPT" if len(previous_attempts) >= 2 else "LOGIN_ATTEMPT"

    log_alert(
        event_type, ip,
        f"Login attempt — Username: '{username}' | Password: '{_mask_password(password)}' | Attempt #{len(previous_attempts)+1}"
    )
    # Always deny — attacker assumes wrong password, not that they're being tracked
    return render_template("fake_login.html", error="Invalid credentials. Access denied.")


# ── HONEYPOT TRAP 2: Fake API Endpoint (/api/v1/auth) ────────────────────────
# Targets automated scanners and tools like Burp Suite / sqlmap that probe
# common API paths. Returns a convincing 401 to sustain attacker engagement.

@app.route("/api/v1/auth", methods=["GET", "POST"])
def fake_api():
    ip = _get_client_ip()
    data = request.get_json(silent=True) or dict(request.form)
    log_alert("API_PROBE", ip, f"Attacker probed hidden API endpoint via {request.method} | Data: {str(data)[:100]}")
    return json.dumps({"status": "error", "code": 401, "message": "Authentication failed. Invalid token."}), \
           401, {"Content-Type": "application/json"}


# ── HONEYPOT TRAP 3: Fake Sensitive Files ────────────────────────────────────
# Mimics files that misconfigured servers accidentally expose.
# Returns fake-but-realistic credentials to keep attacker engaged (threat intel).
# Multiple routes mapped to one handler — clean Flask pattern for related traps.

@app.route("/.env")
@app.route("/config/db")
@app.route("/backup")
@app.route("/.git/config")
def fake_sensitive_file():
    ip = _get_client_ip()
    log_alert("HIDDEN_FILE_ACCESS", ip, f"Attacker attempted to access sensitive file: {request.path}")
    fake_content = """DB_HOST=10.0.0.5
    DB_USER=admin
    DB_PASS=Sup3rS3cr3t!
    DB_NAME=production_db
    SECRET_KEY=a1b2c3d4e5f6g7h8
    """
    return fake_content, 200, {"Content-Type": "text/plain"}


# ── ANALYST DASHBOARD (/dashboard) ───────────────────────────────────────────
# The defender's view — NOT a honeypot. Aggregates all alerts with live stats.
# Reverses list so newest events appear first;

@app.route("/dashboard")
def dashboard():
    alerts = _load_alerts()
    stats = {
        "total":      len(alerts),
        "critical":   len([a for a in alerts if a["severity"] == "CRITICAL"]),
        "high":       len([a for a in alerts if a["severity"] == "HIGH"]),
        "low":        len([a for a in alerts if a["severity"] == "LOW"]),
        "unique_ips": len(set(a["source_ip"] for a in alerts))  # attacker fingerprinting
    }
    return render_template("dashboard.html", alerts=list(reversed(alerts)), stats=stats)


# ── DEMO RESET (/clear) ──────────────────────────────────────────────────────
# Wipes the alert log for clean demo runs. Remove or auth-gate in production.

@app.route("/clear")
def clear_alerts():
    if os.path.exists(ALERT_LOG_FILE):
        os.remove(ALERT_LOG_FILE)
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  HONEYPOT SYSTEM — ACTIVE")
    print("="*55)
    print("\n  Trap URLs:")
    print("  🪤  http://localhost:8080/admin")
    print("  🪤  http://localhost:8080/api/v1/auth")
    print("  🪤  http://localhost:8080/.env")
    print("  🪤  http://localhost:8080/.git/config")
    print("  🪤  http://localhost:8080/backup")
    print("\n  Monitor: http://localhost:8080/dashboard")
    print("="*55 + "\n")
    app.run(debug=True, port=8080)