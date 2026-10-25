"""
routes/incidents.py - Security Incident Response Controller
------------------------------------------------------------
Student explanation:
Orchestrates enterprise incident response when a phishing threat is confirmed.
Allows IT Admins to open incidents, block malicious senders, flag compromised accounts,
trigger password resets, broadcast company alerts, and audit every mitigation step (Phase 4).
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash

incidents_bp = Blueprint("incidents", __name__)

@incidents_bp.route("/")
def list_incidents():
    """Admin view: list active and resolved security incidents."""
    return render_template("incidents_list.html")
