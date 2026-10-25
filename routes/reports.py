"""
routes/reports.py - Phishing Incident Reporting & Triage Controller
-------------------------------------------------------------------
Student explanation:
Enables employees to report suspicious emails to the Security Operations Center (SOC).
IT Administrators triage these submissions, classifying them as Phishing, Safe, or Spam.
"""

from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from database import db
from models import Report, Email, User
from routes.auth import login_required, role_required

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/submit/<int:email_id>", methods=["POST"])
@login_required
def submit_report(email_id):
    """
    Submits an email to the SOC for threat triage.
    Creates a new Report entry and marks email.is_reported = True.
    """
    user_id = session.get("user_id")
    email_obj = Email.query.get_or_404(email_id)

    # Validate that employee owns the email or is an IT Admin
    user = User.query.get(user_id)
    if not (user.role and user.role.name == "IT Admin") and email_obj.recipient_id != user_id:
        return abort(403)

    # Check if already reported
    existing_report = Report.query.filter_by(email_id=email_id).first()
    if existing_report:
        flash("This email has already been submitted to the Security Operations Center.", "info")
        return redirect(request.referrer or url_for("emails.inbox"))

    report_reason = request.form.get("reason", "Reported by employee as suspicious phishing email.")
    new_report = Report(
        email_id=email_obj.id,
        reported_by_user_id=user_id,
        report_reason=report_reason,
        admin_verdict="pending"
    )
    email_obj.is_reported = True

    db.session.add(new_report)
    db.session.commit()

    flash(f"Thank you! Email '{email_obj.subject}' has been reported to the Security Team for investigation.", "success")
    return redirect(request.referrer or url_for("emails.inbox"))


@reports_bp.route("/")
@login_required
@role_required("IT Admin")
def list_reports():
    """Admin view: list submitted phishing reports for triage (Phase 4)."""
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template("reports_list.html", reports=reports)
