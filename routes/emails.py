"""
routes/emails.py - Mailbox, Threat Inspection & Quarantine Controller
----------------------------------------------------------------------
Student explanation:
This module manages email security operations for employees and IT staff:
1. Mailbox View: Shows incoming emails inspected by the rule-based detection engine.
   Emails with risk score <= 70 appear in the user's inbox; score > 70 are quarantined.
2. Threat Inspection: Displays a detailed security breakdown for any email, including
   sender reputation, typosquatting checks, urgency indicators, and link audits.
3. Quarantine Management: Allows users and SOC analysts to review isolated high-risk messages,
   with release or deletion capabilities.
4. On-Demand Threat Scanner: Enables analysts and employees to paste raw email text or headers
   to test against the 12 offline heuristic rules and the database blocked sender list.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from database import db
from models import Email, User, BlockedSender
from routes.auth import login_required, role_required
from detection.scoring import analyze_email

emails_bp = Blueprint("emails", __name__)


@emails_bp.route("/")
@emails_bp.route("/inbox")
@login_required
def inbox():
    """
    Renders the authenticated user's corporate inbox.
    Only shows emails with status='inbox' belonging to the current user.
    """
    user_id = session.get("user_id")
    search_query = request.args.get("q", "").strip()

    # Parameterized query to prevent SQL injection
    query = Email.query.filter_by(recipient_id=user_id, status="inbox")

    if search_query:
        search_pattern = f"%{search_query}%"
        query = query.filter(
            (Email.subject.ilike(search_pattern)) | (Email.sender.ilike(search_pattern))
        )

    emails = query.order_by(Email.received_at.desc()).all()

    # Calculate inbox statistics
    total_count = len(emails)
    unread_count = sum(1 for e in emails if not e.is_read)
    suspicious_count = sum(1 for e in emails if e.verdict == "Suspicious")
    safe_count = sum(1 for e in emails if e.verdict == "Safe")

    return render_template(
        "inbox.html",
        emails=emails,
        search_query=search_query,
        stats={
            "total": total_count,
            "unread": unread_count,
            "suspicious": suspicious_count,
            "safe": safe_count
        }
    )


@emails_bp.route("/quarantine")
@login_required
def quarantine():
    """
    Renders the email quarantine module.
    - IT Admins can view all quarantined emails across the organization.
    - Regular employees can view only their personal quarantined emails.
    """
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    is_admin = user.role and user.role.name == "IT Admin"

    if is_admin:
        # SOC Admin views all quarantined emails
        quarantined_emails = Email.query.filter_by(status="quarantined").order_by(Email.received_at.desc()).all()
    else:
        # Regular user views their own quarantined emails
        quarantined_emails = Email.query.filter_by(
            recipient_id=user_id, status="quarantined"
        ).order_by(Email.received_at.desc()).all()

    return render_template(
        "quarantine.html",
        emails=quarantined_emails,
        is_admin=is_admin
    )


@emails_bp.route("/view/<int:email_id>")
@login_required
def view_email(email_id):
    """
    Displays the complete security analysis and body of a single email.
    Enforces authorization: regular users can only view their own emails;
    IT Admins can inspect any email in the system.
    """
    email_obj = Email.query.get_or_404(email_id)
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    # Ownership and access control
    is_admin = user.role and user.role.name == "IT Admin"
    if not is_admin and email_obj.recipient_id != user_id:
        flash("You do not have permission to view this email.", "danger")
        return abort(403)

    # Mark as read
    if not email_obj.is_read:
        email_obj.is_read = True
        db.session.commit()

    return render_template(
        "email_detail.html",
        email=email_obj,
        is_admin=is_admin
    )


@emails_bp.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    """
    On-Demand Email Threat Inspection Engine.
    Allows testing of raw email text or specific sender/subject/body fields.
    Detection runs 100% locally and self-contained against the 12 heuristic rules
    and the database blocked_sender list.
    """
    analysis_result = None
    input_data = {
        "from_address": "",
        "reply_to": "",
        "subject": "",
        "body": ""
    }

    if request.method == "POST":
        raw_email = request.form.get("raw_email", "").strip()
        from_address = request.form.get("from_address", "").strip()
        reply_to = request.form.get("reply_to", "").strip()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()

        input_data = {
            "from_address": from_address,
            "reply_to": reply_to,
            "subject": subject,
            "body": body
        }

        # Build raw text if fields provided individually
        if not raw_email:
            headers = [f"From: {from_address}"]
            if reply_to:
                headers.append(f"Reply-To: {reply_to}")
            if subject:
                headers.append(f"Subject: {subject}")
            raw_email = "\n".join(headers) + "\n\n" + body

        # Query custom blocked patterns from database
        custom_blocked = [b.sender_value.strip().lower() for b in BlockedSender.query.all() if b.sender_value]

        # Execute fully offline heuristic analysis
        analysis_result = analyze_email(raw_email, custom_blocked=custom_blocked)

    return render_template(
        "analyze.html",
        analysis=analysis_result,
        input_data=input_data
    )


@emails_bp.route("/quarantine/release/<int:email_id>", methods=["POST"])
@login_required
def release_email(email_id):
    """
    Releases an email from quarantine back to the user's inbox.
    Allowed for IT Admins or the email's owner.
    """
    email_obj = Email.query.get_or_404(email_id)
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    is_admin = user.role and user.role.name == "IT Admin"
    if not is_admin and email_obj.recipient_id != user_id:
        return abort(403)

    email_obj.status = "inbox"
    db.session.commit()
    flash(f"Email '{email_obj.subject}' has been released to your inbox.", "success")
    return redirect(url_for("emails.quarantine"))


@emails_bp.route("/delete/<int:email_id>", methods=["POST"])
@login_required
def delete_email(email_id):
    """
    Permanently removes an email from the system.
    Allowed for IT Admins or the email's owner.
    """
    email_obj = Email.query.get_or_404(email_id)
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    is_admin = user.role and user.role.name == "IT Admin"
    if not is_admin and email_obj.recipient_id != user_id:
        return abort(403)

    return_to = "emails.inbox" if email_obj.status == "inbox" else "emails.quarantine"
    db.session.delete(email_obj)
    db.session.commit()
    flash("Email deleted successfully.", "info")
    return redirect(url_for(return_to))
