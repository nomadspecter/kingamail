"""
routes/emails.py - Mailbox & Email Security Controller
------------------------------------------------------
Student explanation:
Provides routes for employees to view their inbox, inspect quarantined messages,
analyze email risk scores and breakdown indicators, or paste raw text to run
on-demand heuristic threat scans (Phase 3).
"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for

emails_bp = Blueprint("emails", __name__)

@emails_bp.route("/")
@emails_bp.route("/inbox")
def inbox():
    """Renders the employee corporate inbox."""
    return render_template("inbox.html")

@emails_bp.route("/quarantine")
def quarantine():
    """Renders the quarantine view for high-risk / scam emails."""
    return render_template("quarantine.html")

@emails_bp.route("/analyze", methods=["GET", "POST"])
def analyze():
    """On-demand raw email scanner for manual inspection."""
    return render_template("analyze.html")
