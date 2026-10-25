"""
routes/incidents.py - Security Incident Response Management
------------------------------------------------------------
Student explanation:
Provides the Security Operations Center (SOC) management interface for confirmed
security incidents. Tracks chronological containment actions, affected accounts,
associated alerts, and final resolution.
"""

from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from database import db
from models import Incident, User, Alert
from routes.auth import login_required, role_required

incidents_bp = Blueprint("incidents", __name__)


@incidents_bp.route("/")
@login_required
@role_required("IT Admin")
def list_incidents():
    """Admin view: lists all open and resolved security incidents."""
    status_filter = request.args.get("status", "all")
    query = Incident.query

    if status_filter == "open":
        query = query.filter_by(status="open")
    elif status_filter in ("in_progress", "resolved", "closed"):
        query = query.filter_by(status=status_filter)

    incidents = query.order_by(Incident.created_at.desc()).all()

    counts = {
        "open": Incident.query.filter_by(status="open").count(),
        "in_progress": Incident.query.filter_by(status="in_progress").count(),
        "resolved": Incident.query.filter(Incident.status.in_(["resolved", "closed"])).count(),
        "total": Incident.query.count()
    }

    return render_template(
        "incidents_list.html",
        incidents=incidents,
        status_filter=status_filter,
        counts=counts
    )


@incidents_bp.route("/view/<int:incident_id>")
@login_required
@role_required("IT Admin")
def view_incident(incident_id):
    """
    Displays the complete security investigation docket:
    - Incident metadata, severity, and status.
    - Affected victim identity and account status.
    - Chronological actions audit log.
    - Linked security broadcast alerts.
    """
    incident = Incident.query.get_or_404(incident_id)
    return render_template("incident_detail.html", incident=incident)


@incidents_bp.route("/close/<int:incident_id>", methods=["POST"])
@login_required
@role_required("IT Admin")
def close_incident(incident_id):
    """
    Marks an incident as resolved/closed and records the resolution in the audit log.
    """
    incident = Incident.query.get_or_404(incident_id)
    admin_id = session.get("user_id")
    admin_user = User.query.get(admin_id)

    resolution_notes = request.form.get("resolution_notes", "").strip() or "Threat mitigated and confirmed resolved by SOC analyst."

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Append resolution step to the actions log
    actions_log = list(incident.actions_log or [])
    actions_log.append({
        "timestamp": now_str,
        "action": "Incident Resolved & Closed",
        "details": resolution_notes,
        "performed_by": admin_user.full_name
    })

    incident.actions_log = actions_log
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(incident, "actions_log")
    incident.status = "resolved"
    incident.resolved_at = datetime.utcnow()

    db.session.commit()
    flash(f"Incident {incident.incident_number} has been marked as RESOLVED.", "success")
    return redirect(url_for("incidents.view_incident", incident_id=incident.id))
