"""
routes/auth.py - Authentication & Session Controller
----------------------------------------------------
Student explanation:
Handles user login, 2FA OTP verification, session lifecycle,
and logout. It also logs every authentication attempt into the login_log
audit table and enforces account lockouts or password reset flags.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Login endpoint:
    GET: renders the corporate authentication portal.
    POST: verifies credentials and initiates 2FA flow (Phase 2).
    """
    if request.method == "POST":
        flash("Phase 1 is active. Full authentication logic activates in Phase 2.", "info")
        return redirect(url_for("auth.login"))
    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    """Clears user session and redirects to login portal."""
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))
