"""
routes/simulation.py - Phishing Simulation & Awareness Campaign Controller
--------------------------------------------------------------------------
Student explanation:
Orchestrates enterprise phishing awareness simulations:
1. IT Admins schedule simulated phishing campaigns targeting employees.
2. For each participant, a unique cryptographic tracking token is minted, and a simulated
   email containing the tracking link is placed into the employee's database mailbox.
3. When the employee clicks the link (/simulation/track/<token>):
   - The click is recorded in sim_result (is_clicked=True, clicked_at timestamp).
   - An educational landing page is rendered informing them of the simulation.
   - PRIVACY RULE: Never collect or store any typed credentials or input on the landing page.
4. When an employee reports the simulated email, sim_result.is_reported is updated.
"""

import secrets
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from database import db
from models import Campaign, SimResult, User, Email
from routes.auth import login_required, role_required

simulation_bp = Blueprint("simulation", __name__)


@simulation_bp.route("/")
@simulation_bp.route("/campaigns")
@login_required
@role_required("IT Admin")
def campaigns():
    """
    Admin view: Lists all phishing awareness simulation campaigns with click & report rates.
    """
    all_campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    all_users = User.query.filter_by(status="active").all()

    # Pre-calculate metrics for each campaign
    campaign_stats = []
    for c in all_campaigns:
        total = len(c.results)
        clicked = sum(1 for r in c.results if r.is_clicked)
        reported = sum(1 for r in c.results if r.is_reported)
        click_rate = round((clicked / total * 100), 1) if total > 0 else 0
        report_rate = round((reported / total * 100), 1) if total > 0 else 0

        campaign_stats.append({
            "campaign": c,
            "total": total,
            "clicked": clicked,
            "reported": reported,
            "click_rate": click_rate,
            "report_rate": report_rate
        })

    return render_template(
        "campaigns_list.html",
        campaign_stats=campaign_stats,
        users=all_users
    )


@simulation_bp.route("/create", methods=["POST"])
@login_required
@role_required("IT Admin")
def create_campaign():
    """
    Creates and launches a new phishing awareness simulation.
    Delivers customized simulated phishing emails with tracking links to targeted staff inboxes.
    """
    admin_id = session.get("user_id")
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    subject = request.form.get("subject", "").strip()
    body_template = request.form.get("body", "").strip()
    target_scope = request.form.get("target_scope", "all").strip()

    if not name or not subject or not body_template:
        flash("Campaign name, subject, and email body template are required.", "danger")
        return redirect(url_for("simulation.campaigns"))

    # Determine target participants
    if target_scope == "all":
        target_users = User.query.filter_by(status="active").all()
    else:
        user_ids = request.form.getlist("user_ids")
        target_users = User.query.filter(User.id.in_(user_ids)).all()

    if not target_users:
        flash("No active participants selected for this simulation.", "warning")
        return redirect(url_for("simulation.campaigns"))

    # 1. Create the Campaign record
    campaign = Campaign(
        name=name,
        description=description,
        template_subject=subject,
        template_body=body_template,
        status="active",
        created_by_user_id=admin_id,
        start_date=datetime.utcnow()
    )
    db.session.add(campaign)
    db.session.flush()

    # 2. Generate tracking tokens and deliver simulated emails
    for target in target_users:
        token = secrets.token_urlsafe(32)
        sim_result = SimResult(
            campaign_id=campaign.id,
            user_id=target.id,
            tracking_token=token,
            sent_at=datetime.utcnow(),
            is_clicked=False,
            is_reported=False
        )
        db.session.add(sim_result)

        # Build simulated email body containing unique tracking link
        track_url = url_for("simulation.track_click", token=token, _external=True)
        email_body = (
            f"{body_template}\n\n"
            f"--------------------------------------------------\n"
            f"Action Link: {track_url}\n"
            f"--------------------------------------------------"
        )

        sim_email = Email(
            recipient_id=target.id,
            sender="security-portal@corporate-notifications.org",
            reply_to="security-portal@corporate-notifications.org",
            subject=f"[Simulated] {subject}",
            body=email_body,
            risk_score=55,
            verdict="Suspicious",
            confidence="Medium",
            status="inbox",
            is_read=False,
            is_reported=False
        )
        db.session.add(sim_email)

    db.session.commit()
    flash(f"Simulation campaign '{campaign.name}' launched! Dispatched {len(target_users)} test emails with unique tracking tokens.", "success")
    return redirect(url_for("simulation.campaigns"))


@simulation_bp.route("/track/<token>")
def track_click(token):
    """
    Tracking endpoint for simulated phishing links.
    PRIVACY GUARANTEE:
      1. Records click event in sim_result (is_clicked=True, clicked_at=now).
      2. Renders educational landing page explaining the red flags.
      3. NEVER prompts for, collects, or stores any typed input or credentials.
    """
    sim_result = SimResult.query.filter_by(tracking_token=token).first()
    if not sim_result:
        return render_template("simulation_landing.html", not_found=True)

    # Record the click event
    if not sim_result.is_clicked:
        sim_result.is_clicked = True
        sim_result.clicked_at = datetime.utcnow()
        db.session.commit()

    return render_template(
        "simulation_landing.html",
        token=token,
        campaign=sim_result.campaign,
        participant=sim_result.user,
        clicked_at=sim_result.clicked_at
    )
