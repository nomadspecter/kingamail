"""
routes/__init__.py - Web Routes Package
----------------------------------------
Student explanation:
This package organizes the web application into modular controllers called Blueprints.
Dividing routes by domain (auth, emails, incidents, simulations, training, etc.)
prevents massive monolithic files and makes large applications maintainable.
"""

from routes.auth import auth_bp
from routes.emails import emails_bp
from routes.reports import reports_bp
from routes.incidents import incidents_bp
from routes.simulation import simulation_bp
from routes.training import training_bp
from routes.alerts import alerts_bp
from routes.dashboard import dashboard_bp

__all__ = [
    "auth_bp",
    "emails_bp",
    "reports_bp",
    "incidents_bp",
    "simulation_bp",
    "training_bp",
    "alerts_bp",
    "dashboard_bp"
]
