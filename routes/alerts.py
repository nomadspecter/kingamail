"""
routes/alerts.py - Security Broadcast & Notification Controller
--------------------------------------------------------------
Student explanation:
Enables IT security to broadcast emergency threat warnings to all employees
(e.g., active spoofing campaign against corporate payroll). Tracks whether
employees have read and acknowledged the advisory (Phase 4).
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash

alerts_bp = Blueprint("alerts", __name__)

@alerts_bp.route("/")
def list_alerts():
    """Lists security alerts relevant to the current user."""
    return render_template("alerts_list.html")
