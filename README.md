# SecurePanel

A Hardened Web Application for Cybersecurity Incident Management with STRIDE-Based Security Testing and Input Fuzzing.

## Results

| Metric | Value |
|--------|-------|
| Total Tests | 52 |
| Passed | 52 |
| Failed | 0 |
| Pass Rate | 100.0% |
| STRIDE Categories | 6 |
| Fuzz Payloads | 15 |
| Security Controls | 10 |

## Architecture

### Security Controls (Defence-in-Depth)

- bcrypt Password Hashing — salted adaptive hash, never plaintext
- Role-Based Access Control — admin/client separation via decorators
- CSRF Protection — Flask-WTF tokens on all POST forms
- Input Sanitisation — bleach strips all HTML/JS tags
- Parameterised SQL Queries — SQLite `?` placeholders throughout
- Security HTTP Headers — CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy
- Session Hardening — HttpOnly, SameSite=Lax, 30-min timeout, regeneration on login
- Rate Limiting — Flask-Limiter on API endpoints (5/min health, 200/min auth)
- Password Policy — min 8 chars, uppercase, lowercase, digit, special character
- Audit Logging — DB + file log with user ID, action, IP address, timestamp

### STRIDE Test Categories

- **S**poofing — credential validation, SQL injection resistance, bcrypt verification, session fixation
- **T**ampering — CSRF enforcement, role injection blocking, HTML sanitisation
- **R**epudiation — login/logout/registration event logging with IP addresses
- **I**nformation Disclosure — 8 security headers validated, error pages hide stack traces
- **D**enial of Service — rate limiting returns HTTP 429 on threshold breach
- **E**levation of Privilege — unauthenticated redirect, client-to-admin block, IDOR prevention

### Input Fuzzing (15 Payloads)

- XSS: script tags, img onerror, event handlers, SVG onload
- SQL Injection: UNION, OR 1=1, DROP TABLE, comment bypass
- Other: path traversal, null byte, 10K-char boundary, unicode directional, HTML entities, Jinja2 SSTI

## Tech Stack

- Kali Linux 2026.1
- Python 3.13
- Flask 3.1.0
- Flask-WTF 1.2.2 (CSRF)
- Flask-Bcrypt 1.0.1 (password hashing)
- Flask-Limiter 3.8.0 (rate limiting)
- bleach 6.2.0 (input sanitisation)
- SQLite3 (parameterised queries)

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/SecurePanel.git
cd SecurePanel
pip3 install -r requirements.txt --break-system-packages
python3 app.py
```

Default admin: `admin` / `Admin@Secure2026`

## Security Testing

```bash
# In a separate terminal (server must be running)
python3 security_tests.py
```

## Project Structure

```
secure-app/
├── app.py                  # Main Flask application (routes, security, RBAC)
├── security_tests.py       # STRIDE test suite + fuzzing (52 tests)
├── requirements.txt        # Python dependencies
├── run.sh                  # Kali Linux server launcher
├── run_tests.sh            # Kali Linux test runner
├── static/
│   └── style.css           # Dark cybersecurity theme
└── templates/
    ├── base.html            # Base layout with navigation
    ├── index.html           # Landing page with feature cards
    ├── login.html           # Login form with CSRF token
    ├── register.html        # Registration form with validation
    ├── dashboard.html       # Client incident dashboard
    ├── new_incident.html    # Incident submission form
    ├── view_incident.html   # Incident detail view
    ├── admin_dashboard.html # Admin panel (incidents/users/audit log)
    └── error.html           # Custom error pages (403, 404, 429, 500)
```

## Author

[YOUR NAME] — BSc Computing, University of Bolton (2026)

DEV6003 Secure Application Development — New York College Thessaloniki
