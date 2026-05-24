"""
Secure Incident Management Portal
DEV6003 - Secure Application Development
------------------------------------------
A hardened Flask web backend for managing cybersecurity incidents.

Security Features Implemented:
1. bcrypt password hashing (never store plaintext)
2. Role-Based Access Control (RBAC) - admin / client
3. CSRF protection via Flask-WTF on all forms
4. Input sanitisation using bleach (strip all HTML/JS)
5. Parameterised SQL queries (prevent SQL injection)
6. Security HTTP headers (CSP, X-Frame-Options, HSTS, etc.)
7. Secure session configuration (HttpOnly, SameSite, timeout)
8. Rate limiting on authentication endpoints
9. Password complexity enforcement
10. XSS prevention via Jinja2 autoescaping + CSP
"""

import os
import re
import sqlite3
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort, g
)
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach


# ---------------------------------------------------------------------------
# Application Factory & Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Secret key for session signing - generated securely
app.config["SECRET_KEY"] = secrets.token_hex(32)

# Session hardening
app.config["SESSION_COOKIE_HTTPONLY"] = True      # JS cannot read cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"     # CSRF mitigation
app.config["SESSION_COOKIE_SECURE"] = False        # Set True in production (HTTPS)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)  # Auto-expire

# Database path
DATABASE = os.path.join(os.path.dirname(__file__), "secure_portal.db")

# ---------------------------------------------------------------------------
# Extensions
# ---------------------------------------------------------------------------

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://"
)

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------

logging.basicConfig(
    filename="security_audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("security")


# ---------------------------------------------------------------------------
# Database Helpers (parameterised queries only)
# ---------------------------------------------------------------------------

def get_db():
    """Open a database connection for the current request context."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialise the database schema and seed admin account."""
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys=ON")

    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            email       TEXT    NOT NULL UNIQUE,
            password    TEXT    NOT NULL,
            role        TEXT    NOT NULL DEFAULT 'client',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            is_active   INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            title       TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            category    TEXT    NOT NULL,
            description TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'open',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            action      TEXT    NOT NULL,
            detail      TEXT,
            ip_address  TEXT,
            timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """)

    # Seed default admin if not exists
    existing = db.execute(
        "SELECT id FROM users WHERE username = ?", ("admin",)
    ).fetchone()

    if not existing:
        hashed = bcrypt.generate_password_hash("Admin@Secure2026").decode("utf-8")
        db.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            ("admin", "admin@securepanel.local", hashed, "admin")
        )
        db.commit()
        print("[+] Default admin account created (admin / Admin@Secure2026)")

    db.close()


# ---------------------------------------------------------------------------
# Input Sanitisation
# ---------------------------------------------------------------------------

def sanitise(text):
    """Strip all HTML tags and attributes from user input."""
    if text is None:
        return ""
    return bleach.clean(str(text), tags=[], attributes={}, strip=True).strip()


def validate_password(password):
    """Enforce password complexity policy."""
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Password must contain at least one special character.")
    return errors


# ---------------------------------------------------------------------------
# Security Audit Logger
# ---------------------------------------------------------------------------

def log_event(action, detail="", user_id=None):
    """Write a security event to both the database and log file."""
    ip = request.remote_addr if request else "N/A"
    uid = user_id or session.get("user_id")
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?, ?, ?, ?)",
            (uid, action, detail, ip)
        )
        db.commit()
    except Exception:
        pass
    logger.info(f"user={uid} action={action} detail={detail} ip={ip}")


# ---------------------------------------------------------------------------
# Decorators for RBAC
# ---------------------------------------------------------------------------

def login_required(f):
    """Ensure the user is authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Ensure the user has admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            log_event("UNAUTHORISED_ACCESS_ATTEMPT", f"Route: {request.path}")
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------

@app.after_request
def apply_security_headers(response):
    """Attach hardened HTTP headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


# ---------------------------------------------------------------------------
# Context Processor
# ---------------------------------------------------------------------------

@app.context_processor
def inject_user():
    """Make current user info available in all templates."""
    if "user_id" in session:
        return {
            "current_user": session.get("username"),
            "current_role": session.get("role")
        }
    return {"current_user": None, "current_role": None}


# ---------------------------------------------------------------------------
# Routes - Public
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("200 per minute")
def register():
    if request.method == "POST":
        username = sanitise(request.form.get("username", ""))
        email = sanitise(request.form.get("email", ""))
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # Validation
        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            errors.append("Username may only contain letters, digits, and underscores.")
        if not email or not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            errors.append("Please provide a valid email address.")
        if password != confirm:
            errors.append("Passwords do not match.")

        pw_errors = validate_password(password)
        errors.extend(pw_errors)

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html")

        # Check uniqueness (parameterised)
        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()

        if existing:
            flash("Username or email already exists.", "danger")
            log_event("REGISTER_DUPLICATE", f"username={username}")
            return render_template("register.html")

        # Hash and store
        hashed = bcrypt.generate_password_hash(password).decode("utf-8")
        db.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (username, email, hashed, "client")
        )
        db.commit()
        log_event("USER_REGISTERED", f"username={username}")
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("200 per minute")
def login():
    if request.method == "POST":
        username = sanitise(request.form.get("username", ""))
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,)
        ).fetchone()

        if user and bcrypt.check_password_hash(user["password"], password):
            # Regenerate session to prevent fixation
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_event("LOGIN_SUCCESS", f"username={username}", user_id=user["id"])
            flash(f"Welcome back, {user['username']}.", "success")
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        else:
            log_event("LOGIN_FAILED", f"username={username}")
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    log_event("LOGOUT")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Routes - Client Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    incidents = db.execute(
        "SELECT * FROM incidents WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template("dashboard.html", incidents=incidents)


@app.route("/incident/new", methods=["GET", "POST"])
@login_required
def new_incident():
    if request.method == "POST":
        title = sanitise(request.form.get("title", ""))
        severity = sanitise(request.form.get("severity", ""))
        category = sanitise(request.form.get("category", ""))
        description = sanitise(request.form.get("description", ""))

        errors = []
        if not title or len(title) < 5:
            errors.append("Title must be at least 5 characters.")
        if severity not in ("low", "medium", "high", "critical"):
            errors.append("Invalid severity level.")
        if category not in ("malware", "phishing", "data_breach", "unauthorized_access", "dos", "other"):
            errors.append("Invalid category.")
        if not description or len(description) < 20:
            errors.append("Description must be at least 20 characters.")
        if len(description) > 5000:
            errors.append("Description must not exceed 5000 characters.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("new_incident.html")

        db = get_db()
        db.execute(
            "INSERT INTO incidents (user_id, title, severity, category, description) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], title, severity, category, description)
        )
        db.commit()
        log_event("INCIDENT_CREATED", f"title={title}")
        flash("Incident submitted successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("new_incident.html")


@app.route("/incident/<int:incident_id>")
@login_required
def view_incident(incident_id):
    db = get_db()
    if session.get("role") == "admin":
        incident = db.execute(
            "SELECT i.*, u.username FROM incidents i JOIN users u ON i.user_id = u.id WHERE i.id = ?",
            (incident_id,)
        ).fetchone()
    else:
        incident = db.execute(
            "SELECT * FROM incidents WHERE id = ? AND user_id = ?",
            (incident_id, session["user_id"])
        ).fetchone()

    if not incident:
        abort(404)
    return render_template("view_incident.html", incident=incident)


# ---------------------------------------------------------------------------
# Routes - Admin Dashboard (RBAC protected)
# ---------------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    incidents = db.execute(
        "SELECT i.*, u.username FROM incidents i JOIN users u ON i.user_id = u.id ORDER BY i.created_at DESC"
    ).fetchall()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    logs = db.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    stats = {
        "total_incidents": db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
        "open_incidents": db.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'").fetchone()[0],
        "critical_incidents": db.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'critical'").fetchone()[0],
        "total_users": db.execute("SELECT COUNT(*) FROM users WHERE role = 'client'").fetchone()[0],
    }
    return render_template("admin_dashboard.html", incidents=incidents, users=users, logs=logs, stats=stats)


@app.route("/admin/incident/<int:incident_id>/update", methods=["POST"])
@admin_required
def update_incident_status(incident_id):
    new_status = sanitise(request.form.get("status", ""))
    if new_status not in ("open", "investigating", "resolved", "closed"):
        flash("Invalid status.", "danger")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    db.execute(
        "UPDATE incidents SET status = ?, updated_at = datetime('now') WHERE id = ?",
        (new_status, incident_id)
    )
    db.commit()
    log_event("INCIDENT_STATUS_UPDATED", f"incident={incident_id} status={new_status}")
    flash("Incident status updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:user_id>/toggle", methods=["POST"])
@admin_required
def toggle_user(user_id):
    if user_id == session.get("user_id"):
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    user = db.execute("SELECT is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        new_state = 0 if user["is_active"] else 1
        db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_state, user_id))
        db.commit()
        action = "USER_ACTIVATED" if new_state else "USER_DEACTIVATED"
        log_event(action, f"target_user={user_id}")
        flash("User status updated.", "success")
    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------------------------
# Rate-Limited API Endpoint (for DoS testing demonstration)
# ---------------------------------------------------------------------------

@app.route("/api/health")
@limiter.limit("5 per minute")
def health_check():
    """Health check endpoint with strict rate limiting.
    Demonstrates rate limiting protection against denial of service.
    """
    return {"status": "ok", "service": "SecurePanel"}, 200


# ---------------------------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access Denied. You do not have permission to view this resource."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="The requested resource was not found."), 404

@app.errorhandler(429)
def rate_limited(e):
    return render_template("error.html", code=429, message="Too many requests. Please try again later."), 429

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="An internal server error occurred."), 500


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    # Debug=False in production; using True here for development only
    # debug=False for security (prevents stack trace exposure and code reloading)
    # Change to debug=True temporarily during development if needed
    app.run(debug=False, host="0.0.0.0", port=5000)
