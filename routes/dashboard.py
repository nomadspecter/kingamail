"""
routes/dashboard.py - Security Dashboards, Analytics & Compliance Reports
-------------------------------------------------------------------------
Student explanation:
Renders role-specific dashboards:
  - IT Admin (/dashboard/admin): Enterprise threat metrics, SOC incidents, quarantined emails,
    and high-risk employees (compromised accounts, simulation clickers, failed quizzes).
  - Department Manager (/dashboard/manager): Team simulation failure rates, reporting rates,
    and training completion percentages.
  - Compliance Reports (/dashboard/reports): Cross-department audit metrics and CSV data export.
"""

import io
import csv
from datetime import datetime
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, abort, session, Response, current_app, jsonify
)
from database import db
from models import (
    User, Role, Department, Email, Incident, Report,
    Campaign, SimResult, TrainingModule, QuizResult, BlockedSender
)
from routes.auth import login_required, role_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    """
    Main portal landing view.
    If authenticated, routes to the appropriate role-based dashboard.
    If unauthenticated, displays the portal welcome and sign-in prompt.
    """
    if "user_id" in session:
        role = session.get("user_role")
        if role == "IT Admin":
            return redirect(url_for("dashboard.admin_dashboard"))
        elif role == "Manager":
            return redirect(url_for("dashboard.manager_dashboard"))
        else:
            return redirect(url_for("emails.inbox"))

    # Public landing page with foundation summary
    stats = {
        "departments": Department.query.count(),
        "roles": Role.query.count(),
        "users": User.query.count(),
        "emails": Email.query.count(),
        "modules": TrainingModule.query.count()
    }
    return render_template("index.html", db_status="Connected", stats=stats)


@dashboard_bp.route("/admin")
@dashboard_bp.route("/dashboard/admin")
@login_required
@role_required("IT Admin")
def admin_dashboard():
    """
    IT Administrator Security Operations Center (SOC) Dashboard.
    Visualizes enterprise threat levels, quarantine volumes, active incidents,
    and employees presenting elevated risk factors.
    """
    # 1. Threat & Email Ingestion Statistics
    total_emails = Email.query.count()
    safe_emails = Email.query.filter_by(verdict="Safe").count()
    suspicious_emails = Email.query.filter_by(verdict="Suspicious").count()
    quarantined_emails = Email.query.filter_by(status="quarantined").count()

    # 2. Incident Response Metrics
    open_incidents = Incident.query.filter_by(status="open").count()
    investigating_incidents = Incident.query.filter_by(status="in_progress").count()
    resolved_incidents = Incident.query.filter(Incident.status.in_(["resolved", "closed"])).count()
    total_incidents = Incident.query.count()

    # 3. Report Triage Metrics
    pending_reports = Report.query.filter_by(admin_verdict="pending").count()
    confirmed_reports = Report.query.filter_by(admin_verdict="phishing").count()

    # 4. Blocklist Stats
    blocked_senders_count = BlockedSender.query.count()
    recent_blocked = BlockedSender.query.order_by(BlockedSender.created_at.desc()).limit(5).all()

    # 5. High-Risk Users Identification:
    # A user is high risk if they are:
    #   - Compromised (status == 'compromised')
    #   - Clicked a simulated phishing link (is_clicked == True)
    #   - Failed awareness assessments (quiz score < 70)
    all_users = User.query.all()
    high_risk_users = []

    for u in all_users:
        reasons = []
        sim_clicks = sum(1 for r in u.simulation_results if r.is_clicked)
        sim_reports = sum(1 for r in u.simulation_results if r.is_reported)
        failed_quizzes = sum(1 for q in u.quiz_results if not q.passed)

        if u.status == "compromised":
            reasons.append("Account Flagged Compromised")
        if sim_clicks > 0:
            reasons.append(f"Clicked {sim_clicks} Simulation Link(s)")
        if failed_quizzes > 0:
            reasons.append(f"Failed {failed_quizzes} Assessment(s)")

        if reasons:
            high_risk_users.append({
                "user": u,
                "reasons": reasons,
                "sim_clicks": sim_clicks,
                "sim_reports": sim_reports,
                "failed_quizzes": failed_quizzes,
                "risk_level": "Critical" if u.status == "compromised" else "High" if sim_clicks > 0 else "Medium"
            })

    # Sort high-risk users by severity
    high_risk_users.sort(key=lambda x: (x["user"].status == "compromised", x["sim_clicks"]), reverse=True)

    metrics = {
        "emails": {
            "total": total_emails,
            "safe": safe_emails,
            "suspicious": suspicious_emails,
            "quarantined": quarantined_emails
        },
        "incidents": {
            "total": total_incidents,
            "open": open_incidents,
            "in_progress": investigating_incidents,
            "resolved": resolved_incidents
        },
        "reports": {
            "pending": pending_reports,
            "confirmed": confirmed_reports
        },
        "blocked_senders": blocked_senders_count,
        "recent_blocked": recent_blocked,
        "high_risk_users": high_risk_users
    }

    return render_template("dashboard_admin.html", metrics=metrics)


@dashboard_bp.route("/manager")
@dashboard_bp.route("/dashboard/manager")
@login_required
@role_required("Manager", "IT Admin")
def manager_dashboard():
    """
    Department Risk & Awareness Dashboard.
    Enables department heads to measure team vulnerability, simulation failure rates,
    and quiz compliance.
    """
    user_id = session.get("user_id")
    current_user_obj = User.query.get(user_id)
    is_admin = current_user_obj.role and current_user_obj.role.name == "IT Admin"

    # Select target department
    dept_id = request.args.get("dept_id", type=int)
    all_departments = Department.query.order_by(Department.name).all()

    if not dept_id:
        if current_user_obj.department_id:
            dept_id = current_user_obj.department_id
        elif all_departments:
            dept_id = all_departments[0].id

    department = Department.query.get(dept_id) if dept_id else None

    # Fetch department employees
    team_members = []
    total_team_members = 0
    sim_click_count = 0
    sim_report_count = 0
    quizzes_completed_count = 0
    total_quiz_score_sum = 0
    total_quizzes_evaluated = 0

    if department:
        team_users = User.query.filter_by(department_id=department.id).all()
        total_team_members = len(team_users)

        for u in team_users:
            u_clicks = sum(1 for r in u.simulation_results if r.is_clicked)
            u_reports = sum(1 for r in u.simulation_results if r.is_reported)
            u_quizzes = len(u.quiz_results)
            avg_quiz = round(sum(q.score for q in u.quiz_results) / u_quizzes, 1) if u_quizzes > 0 else 0

            sim_click_count += u_clicks
            sim_report_count += u_reports
            quizzes_completed_count += u_quizzes
            total_quiz_score_sum += sum(q.score for q in u.quiz_results)
            total_quizzes_evaluated += u_quizzes

            team_members.append({
                "user": u,
                "sim_clicks": u_clicks,
                "sim_reports": u_reports,
                "quizzes_taken": u_quizzes,
                "avg_score": avg_quiz,
                "status": u.status
            })

    # Department statistics
    total_sim_targets = sum(len(u.simulation_results) for u in (team_users if department else []))
    fail_rate = round((sim_click_count / total_sim_targets * 100), 1) if total_sim_targets > 0 else 0
    report_rate = round((sim_report_count / total_sim_targets * 100), 1) if total_sim_targets > 0 else 0
    avg_team_quiz_score = round(total_quiz_score_sum / total_quizzes_evaluated, 1) if total_quizzes_evaluated > 0 else 0

    stats = {
        "department": department,
        "departments": all_departments,
        "total_members": total_team_members,
        "fail_rate": fail_rate,
        "report_rate": report_rate,
        "avg_quiz_score": avg_team_quiz_score,
        "team_members": team_members,
        "is_admin": is_admin
    }

    return render_template("dashboard_manager.html", stats=stats)


@dashboard_bp.route("/reports")
@dashboard_bp.route("/dashboard/reports")
@login_required
@role_required("IT Admin", "Manager")
def reports_overview():
    """
    Cross-Department Compliance & Awareness Reports Overview.
    Provides organizational benchmarking and direct link to CSV export.
    """
    departments = Department.query.order_by(Department.name).all()
    dept_summaries = []

    for dept in departments:
        dept_users = User.query.filter_by(department_id=dept.id).all()
        user_count = len(dept_users)

        total_sims = sum(len(u.simulation_results) for u in dept_users)
        clicked_sims = sum(sum(1 for r in u.simulation_results if r.is_clicked) for u in dept_users)
        reported_sims = sum(sum(1 for r in u.simulation_results if r.is_reported) for u in dept_users)

        click_rate = round((clicked_sims / total_sims * 100), 1) if total_sims > 0 else 0
        report_rate = round((reported_sims / total_sims * 100), 1) if total_sims > 0 else 0

        quizzes = [q for u in dept_users for q in u.quiz_results]
        avg_score = round(sum(q.score for q in quizzes) / len(quizzes), 1) if quizzes else 0
        completion_rate = round((len(quizzes) / (user_count * 3) * 100), 1) if user_count > 0 else 0

        dept_summaries.append({
            "department": dept,
            "user_count": user_count,
            "click_rate": click_rate,
            "report_rate": report_rate,
            "avg_score": avg_score,
            "completion_rate": min(completion_rate, 100.0)
        })

    return render_template("reports.html", dept_summaries=dept_summaries)


@dashboard_bp.route("/reports/export-csv")
@dashboard_bp.route("/dashboard/reports/export-csv")
@login_required
@role_required("IT Admin", "Manager")
def export_csv():
    """
    Generates and streams an enterprise workforce awareness & compliance CSV report.
    Columns include employee identification, simulation interactions, and quiz records.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV Header
    writer.writerow([
        "Employee ID",
        "Full Name",
        "Email Address",
        "Department",
        "Role",
        "Account Status",
        "Simulations Targeted",
        "Simulations Clicked",
        "Simulations Reported",
        "Quizzes Taken",
        "Average Quiz Score (%)",
        "Security Posture Rating"
    ])

    users = User.query.order_by(User.id).all()
    for u in users:
        dept_name = u.department.name if u.department else "Unassigned"
        role_name = u.role.name if u.role else "Employee"

        sim_targeted = len(u.simulation_results)
        sim_clicked = sum(1 for r in u.simulation_results if r.is_clicked)
        sim_reported = sum(1 for r in u.simulation_results if r.is_reported)

        quizzes_taken = len(u.quiz_results)
        avg_score = round(sum(q.score for q in u.quiz_results) / quizzes_taken, 1) if quizzes_taken > 0 else 0.0

        # Determine posture rating
        if u.status == "compromised":
            posture = "COMPROMISED - Immediate Remediation"
        elif sim_clicked > 0 and avg_score < 70:
            posture = "High Risk - Mandatory Retraining"
        elif sim_clicked > 0:
            posture = "Moderate Risk - Clicked Simulation"
        elif sim_reported > 0 and avg_score >= 80:
            posture = "Security Champion - High Vigilance"
        else:
            posture = "Standard Compliance"

        writer.writerow([
            u.id,
            u.full_name,
            u.email,
            dept_name,
            role_name,
            u.status.upper(),
            sim_targeted,
            sim_clicked,
            sim_reported,
            quizzes_taken,
            avg_score,
            posture
        ])

    output.seek(0)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"kingamail_awareness_report_{timestamp}.csv"

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@dashboard_bp.route("/health")
def health():
    """Health check endpoint returning system status in JSON."""
    return jsonify({
        "status": "healthy",
        "system_name": current_app.config.get("SYSTEM_NAME", "KingaMail Corporate Shield"),
        "version": "1.0.0"
    })
