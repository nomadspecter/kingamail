"""
routes/reports.py - Phishing Incident Reporting & SOC Triage Controller
-----------------------------------------------------------------------
Student explanation:
Enables employees to report suspicious emails to the Security Operations Center (SOC).
IT Administrators triage these submissions:
  - If classified as 'phishing': automatically opens a formal security Incident (INC-YYYY-XXXX),
    blacklists the malicious sender, flags the victim account as 'compromised' with forced
    password reset, records chronological audit logs, and broadcasts an alert to all employees.
  - If classified as 'safe' or 'spam': updates the report verdict without escalating an incident.
"""

from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from database import db
from models import Report, Email, User, Incident, BlockedSender, Alert, AlertRecipient
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

    report_reason = request.form.get("reason", "Reported by employee as suspicious phishing email.").strip()
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
    """Admin view: lists submitted phishing reports for SOC triage."""
    filter_status = request.args.get("status", "all")
    query = Report.query

    if filter_status == "pending":
        query = query.filter_by(admin_verdict="pending")
    elif filter_status in ("phishing", "safe", "spam"):
        query = query.filter_by(admin_verdict=filter_status)

    reports = query.order_by(Report.created_at.desc()).all()

    # Triage summary counts
    pending_count = Report.query.filter_by(admin_verdict="pending").count()
    phishing_count = Report.query.filter_by(admin_verdict="phishing").count()
    safe_count = Report.query.filter_by(admin_verdict="safe").count()
    spam_count = Report.query.filter_by(admin_verdict="spam").count()

    return render_template(
        "reports_list.html",
        reports=reports,
        filter_status=filter_status,
        counts={
            "pending": pending_count,
            "phishing": phishing_count,
            "safe": safe_count,
            "spam": spam_count,
            "total": len(reports)
        }
    )


@reports_bp.route("/triage/<int:report_id>", methods=["POST"])
@login_required
@role_required("IT Admin")
def triage_report(report_id):
    """
    SOC Analyst Triage Decision:
    - 'phishing': Opens incident INC-YYYY-XXXX, blacklists sender, flags victim account
      as compromised (requiring password reset), creates enterprise alert, and logs all actions.
    - 'safe' / 'spam': Updates report without incident creation.
    """
    admin_id = session.get("user_id")
    admin_user = User.query.get(admin_id)
    report = Report.query.get_or_404(report_id)

    verdict = request.form.get("verdict", "").strip().lower()
    triage_notes = request.form.get("notes", "").strip()

    if verdict not in ("phishing", "safe", "spam"):
        flash("Invalid triage verdict selected.", "danger")
        return redirect(url_for("reports.list_reports"))

    report.admin_verdict = verdict
    report.reviewed_by_user_id = admin_id
    report.reviewed_at = datetime.utcnow()

    if verdict == "phishing":
        # 1. Determine sequential incident number: INC-YYYY-XXXX
        current_year = datetime.utcnow().year
        incident_count = Incident.query.count() + 1
        incident_num = f"INC-{current_year}-{incident_count:04d}"

        # 2. Identify affected victim user
        victim_user_id = report.reported_by_user_id
        if report.email and report.email.recipient_id:
            victim_user_id = report.email.recipient_id
        victim_user = User.query.get(victim_user_id)

        # 3. Containment: Flag victim as compromised and enforce password reset
        if victim_user:
            victim_user.status = "compromised"
            victim_user.force_password_reset = True

        # 4. Blacklist sender address / domain in blocked_sender table
        sender_val = report.email.sender if report.email else "unknown-sender"
        existing_block = BlockedSender.query.filter_by(sender_value=sender_val).first()
        if not existing_block:
            new_block = BlockedSender(
                sender_value=sender_val,
                blocked_by_user_id=admin_id,
                reason=f"Confirmed malicious sender from {incident_num} (Report #{report.id})"
            )
            db.session.add(new_block)

        # 5. Broadcast Enterprise Security Advisory Alert to all active staff
        alert_title = f"SECURITY ALERT: Active Phishing Threat Blocked ({incident_num})"
        alert_body = (
            f"The IT Security SOC has intercepted and confirmed an active phishing attack from '{sender_val}' "
            f"with subject '{report.email.subject if report.email else 'Unknown'}'.\n"
            f"The sender has been blacklisted and containment procedures are active. "
            f"Do not click unexpected links or respond to requests for credentials."
        )
        new_alert = Alert(
            title=alert_title,
            message=alert_body,
            severity="danger",
            created_by_user_id=admin_id
        )
        db.session.add(new_alert)
        db.session.flush()

        # Distribute alert recipient records to all corporate users
        all_users = User.query.all()
        for u in all_users:
            recip = AlertRecipient(
                alert_id=new_alert.id,
                user_id=u.id,
                is_read=False
            )
            db.session.add(recip)

        # 6. Build complete chronological actions audit log
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        actions_log = [
            {
                "timestamp": now_str,
                "action": "Security Incident Opened",
                "details": f"SOC confirmed phishing threat from Report #{report.id}. Notes: {triage_notes or 'None'}",
                "performed_by": admin_user.full_name
            },
            {
                "timestamp": now_str,
                "action": "Sender Blacklisted",
                "details": f"Added sender '{sender_val}' to corporate BlockedSender blacklist",
                "performed_by": admin_user.full_name
            },
            {
                "timestamp": now_str,
                "action": "Victim Account Contained",
                "details": f"Flagged {victim_user.email if victim_user else 'user'} as COMPROMISED; forced password reset enabled",
                "performed_by": admin_user.full_name
            },
            {
                "timestamp": now_str,
                "action": "Enterprise Advisory Broadcast",
                "details": f"Dispatched critical security alert #{new_alert.id} to {len(all_users)} employee accounts",
                "performed_by": admin_user.full_name
            }
        ]

        # 7. Create the formal Incident record
        incident_title = f"Phishing Attack: {report.email.subject if report.email else 'Malicious Email'}"
        new_incident = Incident(
            incident_number=incident_num,
            title=incident_title,
            description=f"Confirmed phishing campaign targeting {victim_user.email if victim_user else 'enterprise'}.\nNotes: {triage_notes}",
            severity="high",
            status="open",
            report_id=report.id,
            affected_user_id=victim_user.id if victim_user else None,
            created_by_user_id=admin_id,
            actions_log=actions_log
        )
        db.session.add(new_incident)
        db.session.flush()

        new_alert.incident_id = new_incident.id

        db.session.commit()
        flash(f"Phishing confirmed! Opened {incident_num}, blacklisted '{sender_val}', contained victim account, and broadcast alert.", "warning")
        return redirect(url_for("incidents.view_incident", incident_id=new_incident.id))

    else:
        # Safe or Spam verdict
        db.session.commit()
        flash(f"Report #{report.id} resolved as '{verdict.upper()}'. No incident opened.", "info")
        return redirect(url_for("reports.list_reports"))
