"""
app.py - Application Factory & Blueprint Registration
------------------------------------------------------
Student explanation:
In accordance with professional software design (the Flask Application Factory pattern),
app.py contains NO business logic. Its sole purpose is to:
1. Create and configure the Flask application instance using settings from config.py.
2. Initialize database extensions and migrations via database.py.
3. Configure enterprise security controls:
   - 15-minute session inactivity timeout.
   - Synchronizer Token Pattern (CSRF protection) on all form submissions.
   - Global context processor injecting SYSTEM_NAME, current_user, and csrf_token.
4. Register all modular controllers (Blueprints) for authentication, email security,
   incident triage, simulations, training, and analytics dashboards.
"""

import os
import time
import secrets
from flask import Flask, request, session, redirect, url_for, flash, abort
from config import config_dict
from database import init_db
from models import User

# Import all route blueprints
from routes.auth import auth_bp
from routes.emails import emails_bp
from routes.reports import reports_bp
from routes.incidents import incidents_bp
from routes.simulation import simulation_bp
from routes.training import training_bp
from routes.alerts import alerts_bp
from routes.dashboard import dashboard_bp


def create_app(config_name=None):
    """
    Application factory: builds and configures a new Flask application instance.
    """
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "default")

    app = Flask(__name__)

    # Load configuration settings
    config_class = config_dict.get(config_name, config_dict["default"])
    app.config.from_object(config_class)

    # Initialize database and migrations
    init_db(app)

    # ─── SECURITY: CSRF TOKEN HELPER ───────────────────────────
    def generate_csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(20)
        return session["_csrf_token"]

    # ─── GLOBAL TEMPLATE CONTEXT PROCESSOR ──────────────────────
    @app.context_processor
    def inject_global_vars():
        current_user = None
        if "user_id" in session:
            current_user = User.query.get(session["user_id"])
        return {
            "system_name": app.config.get("SYSTEM_NAME", "PhishShield"),
            "current_user": current_user,
            "csrf_token": generate_csrf_token
        }

    # ─── SECURITY: 15-MINUTE INACTIVITY TIMEOUT & CSRF GUARD ──
    @app.before_request
    def security_checks():
        # Ensure CSRF token is present in session
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(20)

        # 1. 15-minute inactivity session timeout
        if "user_id" in session:
            now = time.time()
            last_active = session.get("last_active")
            # 15 minutes = 900 seconds
            if last_active and (now - last_active > 900):
                session.clear()
                flash("Your session expired due to 15 minutes of inactivity. Please sign in again.", "warning")
                return redirect(url_for("auth.login"))
            session["last_active"] = now

        # 2. CSRF Protection on POST/PUT/DELETE requests
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            # Exclude tracking endpoint or public health checks if any
            if not request.endpoint or "track_click" in request.endpoint:
                return

            sent_token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
            session_token = session.get("_csrf_token")

            if not sent_token or not session_token or not secrets.compare_digest(sent_token, session_token):
                app.logger.warning(f"CSRF validation failed for {request.endpoint} from IP {request.remote_addr}")
                abort(400, description="CSRF token validation failed. Please refresh the page and try again.")

    # Register blueprints (modular routing controllers)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(emails_bp, url_prefix="/emails")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(incidents_bp, url_prefix="/incidents")
    app.register_blueprint(simulation_bp, url_prefix="/simulation")
    app.register_blueprint(training_bp, url_prefix="/training")
    app.register_blueprint(alerts_bp, url_prefix="/alerts")

    return app


# Create the application instance for WSGI servers / direct run
app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = app.config.get("DEBUG", True)
    app.run(host="0.0.0.0", port=port, debug=debug_mode)