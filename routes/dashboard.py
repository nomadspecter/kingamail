"""
routes/dashboard.py - Security Dashboards & Analytics Controller
----------------------------------------------------------------
Student explanation:
Renders role-specific dashboards:
  - IT Admin: enterprise threat overview, quarantine counts, compromised accounts.
  - Department Manager: team simulation failure rates, training completion rates.
  - Employee: personal security score and pending awareness tasks.
Also provides CSV reporting and data exports (Phase 6).
"""

from flask import Blueprint, render_template, request, jsonify, current_app
from database import db
from models import User, Role, Department, Email, Incident, Report, Campaign, TrainingModule

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    """
    Main portal landing view.
    In Phase 1, displays system status, foundation health check,
    database metrics, and navigation overview.
    """
    # Fetch foundation statistics
    db_status = "Connected"
    stats = {
        "departments": 0,
        "roles": 0,
        "users": 0,
        "emails": 0,
        "modules": 0
    }

    try:
        stats["departments"] = Department.query.count()
        stats["roles"] = Role.query.count()
        stats["users"] = User.query.count()
        stats["emails"] = Email.query.count()
        stats["modules"] = TrainingModule.query.count()
    except Exception as e:
        db_status = f"Database Error: {str(e)}"

    return render_template(
        "index.html",
        db_status=db_status,
        stats=stats
    )


@dashboard_bp.route("/admin")
def admin_dashboard():
    """Admin security operations overview (Phase 6)."""
    return render_template("dashboard_admin.html")


@dashboard_bp.route("/manager")
def manager_dashboard():
    """Department risk and awareness dashboard (Phase 6)."""
    return render_template("dashboard_manager.html")


@dashboard_bp.route("/health")
def health():
    """Health check endpoint returning system status in JSON."""
    return jsonify({
        "status": "healthy",
        "system_name": current_app.config.get("SYSTEM_NAME", "PhishShield"),
        "phase": 1,
        "version": "1.0.0"
    })
