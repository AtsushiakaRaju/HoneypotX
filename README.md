# HoneypotX — Deception-Based Intrusion Detection System

A fully functional honeypot system built with Python and Flask that lures, fingerprints, and logs attackers in real time. Deploys multiple deception traps — a fake admin login portal, a fake REST API endpoint, and fake sensitive files — while aggregating all intrusion events into a live analyst dashboard.

> *"The best defense is letting the attacker think they're winning."*

---

## Overview

HoneypotX implements core **deception technology** principles used in enterprise threat intelligence and red-team/blue-team operations. Instead of blocking attackers at the perimeter, it lets them in — silently recording every move for forensic analysis.

Designed and built from scratch as a personal deep-dive into offensive security concepts, behavioral threat detection, and attacker psychology.

---

## Traps Deployed

| Trap | Route | Target |
|------|-------|--------|
| Fake Admin Portal | `/admin` | Manual intruders, credential stuffers |
| Fake REST API | `/api/v1/auth` | Automated scanners (Burp Suite, sqlmap) |
| Fake `.env` file | `/.env` | Environment variable harvesters |
| Fake Git config | `/.git/config` | Recon tools (GitTools, truffleHog) |
| Fake DB backup | `/backup` | Data exfiltration attempts |

All traps return convincing responses — the attacker never knows they've been fingerprinted.

---

## Features

### Deception Engine
- **Fake corporate login page** — styled as a real enterprise admin portal ("SecureNet Systems"), complete with branding, error messages, and an "authorized personnel only" notice. Looks indistinguishable from a real target.
- **Fake API endpoint** — returns a legitimate-looking `401 Unauthorized` JSON response, sustaining attacker engagement and logging POST data from automated tools.
- **Fake sensitive files** — serves plausible-looking credentials and config values to keep attackers occupied while every access is logged.

### Behavioral Analysis
- **Repeat offender escalation** — tracks login attempts per IP; automatically escalates severity from `HIGH → CRITICAL` after 2+ attempts from the same source, mirroring real-world threat scoring systems.
- **Real IP extraction** — handles `X-Forwarded-For` headers for accurate attacker fingerprinting behind reverse proxies and load balancers.
- **Password masking** — captures credential evidence without storing plaintext (`s****t`), following security logging best practices.

### Analyst Dashboard
- Live intrusion event table with severity badges (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`)
- Real-time stats: total alerts, critical count, high count, unique attacker IPs
- Auto-refreshes every 5 seconds — no manual reload needed during a live demo
- One-click log reset for clean demo runs

### Severity Matrix

| Event Type | Severity | Trigger |
|------------|----------|---------|
| `PAGE_VISIT` | LOW | Attacker discovers a trap URL |
| `LOGIN_ATTEMPT` | HIGH | Credential submission on fake portal |
| `API_PROBE` | HIGH | Automated scanner hits API endpoint |
| `HIDDEN_FILE_ACCESS` | CRITICAL | Attacker accesses `.env`, `.git`, or backup |
| `REPEATED_ATTEMPT` | CRITICAL | 3+ login attempts from same IP |

---

## Tech Stack

- **Python 3 + Flask** — lightweight web framework for rapid trap deployment
- **Jinja2** — templating engine for dashboard and fake login page
- **JSON flat-file persistence** — zero-dependency alert storage; production version would use a SIEM or time-series DB
- **Pure CSS** — dark terminal aesthetic dashboard with no external UI libraries

---

## How to Run

```bash
# Install dependency
pip install flask

# Launch honeypot
python honeypot.py
```

```
Trap URLs:
  🪤  http://localhost:8080/admin
  🪤  http://localhost:8080/api/v1/auth
  🪤  http://localhost:8080/.env
  🪤  http://localhost:8080/.git/config
  🪤  http://localhost:8080/backup

Monitor:  http://localhost:8080/dashboard
```

---

## Project Structure

```
HoneypotX/
├── honeypot.py              # Core Flask app — all trap routes and logging engine
├── honeypot_alerts.json     # Persisted alert log (auto-generated)
└── templates/
    ├── fake_login.html      # Convincing fake corporate login page
    └── dashboard.html       # Analyst alert dashboard
```

---

## Security Concepts Demonstrated

- **Deception technology** and honeypot architecture
- **Threat intelligence gathering** via attacker behavior logging
- **Behavioral analysis** — repeat offender detection, escalation logic
- **Attacker fingerprinting** — IP tracking, credential capture, tool identification
- **Secure logging practices** — PII/credential masking in event logs
- **Reverse proxy awareness** — `X-Forwarded-For` header handling
- **HTTP security concepts** — status codes, JSON APIs, auth flows

---

## Real-World Context

This project mirrors techniques used in production security environments:

- **Canary tokens** — fake files and credentials that alert when accessed
- **SIEM integration** — the alert JSON structure maps directly to formats like Elastic SIEM or Splunk
- **Threat intelligence platforms** — attacker IP tracking and behavioral scoring
- **Zero-interaction detection** — catches reconnaissance before any real system is touched

---

## Potential Extensions

- [ ] Email/Telegram alert notifications on CRITICAL events
- [ ] GeoIP lookup for attacker IP geolocation
- [ ] Rate limiting and auto-block via `iptables` integration
- [ ] Export alerts as CSV for SIEM ingestion
- [ ] Deploy on a public VPS to capture real-world internet scanners

---

## Author

**Harsha**

---

*Built for educational purposes. Deploy only on systems you own or have explicit permission to monitor.*
