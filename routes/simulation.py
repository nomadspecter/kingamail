"""
routes/simulation.py - Phishing Simulation & Awareness Controller
-----------------------------------------------------------------
Student explanation:
Manages simulated phishing campaigns created by administrators.
Generates unique tracking tokens for simulation links, renders educational landing
pages when links are clicked (without collecting credentials), and measures reporting
rates to evaluate corporate susceptibility (Phase 5).
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash

simulation_bp = Blueprint("simulation", __name__)

@simulation_bp.route("/")
def campaigns():
    """Admin view: list phishing awareness campaigns."""
    return render_template("campaigns_list.html")

@simulation_bp.route("/track/<token>")
def track_click(token):
    """Tracking route for simulation link clicks."""
    return render_template("simulation_landing.html", token=token)
