"""
app.py - Application Factory & Blueprint Registration
------------------------------------------------------
Student explanation:
In accordance with professional software design (the Flask Application Factory pattern),
app.py contains NO business logic. Its sole purpose is to:
1. Create and configure the Flask application instance using settings from config.py.
2. Initialize database extensions via database.py.
3. Inject global template variables (such as SYSTEM_NAME) so they are available
   across all Jinja HTML templates.
4. Register all modular controllers (Blueprints) for authentication, email security,
   incident triage, simulations, training, and analytics dashboards.
"""

import os
from flask import Flask
from config import config_dict
from database import init_db

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

    # Initialize database
    init_db(app)

    # Global template context processor
    # Injects SYSTEM_NAME into every template as {{ system_name }}
    @app.context_processor
    def inject_global_vars():
        return {
            "system_name": app.config.get("SYSTEM_NAME", "PhishShield")
        }

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