"""
routes/reports.py - Phishing Incident Reporting Controller
----------------------------------------------------------
Student explanation:
Enables employees to report suspicious emails to the security operations center (SOC).
Allows IT Administrators to triage reported messages as Phishing, Safe, or Spam (Phase 4).
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash

reports_bp = Blueprint("reports", __name__)

@reports_bp.route("/")
def list_reports():
    """Admin view: list submitted phishing reports for triage."""
    return render_template("reports_list.html")
