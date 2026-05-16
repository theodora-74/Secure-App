SecurePanel - Incident Management Portal

A hardened Flask web application for managing cybersecurity incidents, built with security at the design phase.
Developed for Secure Application Development at the University of Greater Manchester / New York College Thessaloniki.

Security Features
#FeatureImplementation1Password Hashingbcrypt with automatic salting2Role-Based Access ControlAdmin/client roles with decorator enforcement3CSRF ProtectionFlask-WTF CSRFProtect on all POST forms4Input Sanitisationbleach strips all HTML/JS from user input5SQL Injection PreventionParameterised queries throughout6Security HTTP HeadersCSP, X-Frame-Options, HSTS, Referrer-Policy, Permissions-Policy7Session SecurityHttpOnly, SameSite=Lax, 30-min timeout, regeneration on login8Rate LimitingFlask-Limiter on API endpoints9Password PolicyMin 8 chars, uppercase, lowercase, digit, special character10Audit LoggingAll auth events logged with IP, timestamp, and action detail
Tech Stack

Backend: Python 3.13, Flask 3.1.0
Database: SQLite3 with parameterised queries
Security: Flask-WTF, Flask-Bcrypt, Flask-Limiter, bleach
Platform: Kali Linux 2026.1
Testing: Custom STRIDE test suite + input fuzzing (52 tests, 100% pass rate)

Setup
bash# Install dependencies
pip3 install -r requirements.txt --break-system-packages

# Start the server
python3 app.py
Server runs on http://127.0.0.1:5000
Default admin credentials: admin / Admin@Secure2026
Security Testing
bash# In a separate terminal (server must be running)
python3 security_tests.py
Tests follow the STRIDE threat model:
CategoryTestsResultSpoofing4ALL PASSTampering3ALL PASSRepudiation4ALL PASSInformation Disclosure9ALL PASSElevation of Privilege6ALL PASSPassword Policy7ALL PASSFuzzing (15 payloads)16ALL PASSDenial of Service3ALL PASSTotal52100%
Project Structure
secure-app/
├── app.py                  # Main Flask application
├── security_tests.py       # STRIDE security test suite
├── requirements.txt        # Python dependencies
├── run.sh                  # Kali Linux server launcher
├── run_tests.sh            # Kali Linux test runner
├── static/
│   └── style.css           # Dark cybersecurity theme
└── templates/
    ├── base.html            # Base layout with navigation
    ├── index.html           # Landing page
    ├── login.html           # Login form
    ├── register.html        # Registration form
    ├── dashboard.html       # Client incident dashboard
    ├── new_incident.html    # Incident submission form
    ├── view_incident.html   # Incident detail view
    ├── admin_dashboard.html # Admin panel (incidents/users/audit)
    └── error.html           # Custom error pages
License
Copyright (c) 2026. All rights reserved. See LICENSE for details.
