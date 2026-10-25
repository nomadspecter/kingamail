"""
routes/training.py - Employee Security Training & Quizzes
---------------------------------------------------------
Student explanation:
Provides interactive training courses and quizzes for employees.
Scores each completed quiz and saves results in quiz_result to track workforce
compliance and vulnerability reductions over time (Phase 5).
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash

training_bp = Blueprint("training", __name__)

@training_bp.route("/")
def modules():
    """Lists available cybersecurity training modules."""
    return render_template("training_modules.html")
