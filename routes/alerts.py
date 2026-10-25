"""
routes/alerts.py - Security Advisory & Threat Broadcast Controller
------------------------------------------------------------------
Student explanation:
Enables the security operations center to broadcast threat warnings to all
employees across the enterprise. Tracks which users have viewed and acknowledged
the warning in the alert_recipient table.
"""

from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from database import db
from models import Alert, AlertRecipient, User
from routes.auth import login_required, role_required

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/")
@login_required
def list_alerts():
    """
    Displays company security advisories sent to the current user.
    """
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    is_admin = user.role and user.role.name == "IT Admin"

    # Fetch alert receipts for current user
    user_receipts = AlertRecipient.query.filter_by(
        user_id=user_id
    ).join(Alert).order_by(Alert.created_at.desc()).all()

    unread_count = sum(1 for r in user_receipts if not r.is_read)

    return render_template(
        "alerts_list.html",
        receipts=user_receipts,
        unread_count=unread_count,
        is_admin=is_admin
    )


@alerts_bp.route("/acknowledge/<int:alert_id>", methods=["POST"])
@login_required
def acknowledge_alert(alert_id):
    """
    Employee acknowledgment: marks the advisory as read in the alert_recipient table.
    """
    user_id = session.get("user_id")
    receipt = AlertRecipient.query.filter_by(alert_id=alert_id, user_id=user_id).first()

    if receipt:
        receipt.is_read = True
        receipt.read_at = datetime.utcnow()
        db.session.commit()
        flash("Security alert marked as acknowledged.", "success")
    else:
        flash("Alert receipt not found.", "warning")

    return redirect(url_for("alerts.list_alerts"))


@alerts_bp.route("/broadcast", methods=["POST"])
@login_required
@role_required("IT Admin")
def broadcast_alert():
    """
    Manual Security Alert Broadcast by SOC Administrator.
    Dispatches a new advisory to all registered users.
    """
    admin_id = session.get("user_id")
    title = request.form.get("title", "").strip()
    message = request.form.get("message", "").strip()
    severity = request.form.get("severity", "warning").strip()

    if not title or not message:
        flash("Alert title and message are required.", "danger")
        return redirect(url_for("alerts.list_alerts"))

    new_alert = Alert(
        title=title,
        message=message,
        severity=severity,
        created_by_user_id=admin_id
    )
    db.session.add(new_alert)
    db.session.flush()

    # Deliver to all users
    all_users = User.query.all()
    for u in all_users:
        db.session.add(AlertRecipient(alert_id=new_alert.id, user_id=u.id, is_read=False))

    db.session.commit()
    flash(f"Security advisory broadcast successfully dispatched to {len(all_users)} employee accounts.", "success")
    return redirect(url_for("alerts.list_alerts"))
