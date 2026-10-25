"""
routes/auth.py - Authentication & Role-Based Access Control
-----------------------------------------------------------
Student explanation:
This module manages the entire authentication lifecycle:
1. Primary login via email and password (hashed with PBKDF2/SHA256).
2. Two-Factor Authentication (2FA): generates a random 6-digit one-time code (OTP),
   hashes it, and stores it in the user record with a 5-minute expiry.
   In DEMO_MODE, it prints to the console and displays on screen.
3. Session Security: enforces a 15-minute inactivity timeout and secure cookies.
4. Role-Based Access Control (RBAC): provides @login_required and @role_required
   decorators that protect routes based on permissions (Employee, IT Admin, Manager).
5. Audit Logging: every login attempt (success, failure, account lockout) is saved
   to the login_log table.
"""

import os
import time
import random
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, flash, current_app, abort
)
from database import db
from models import User, Role, LoginLog

auth_bp = Blueprint("auth", __name__)


# ─── RBAC & AUTHENTICATION DECORATORS ──────────────────────────

def login_required(f):
    """
    Decorator ensuring the request comes from an authenticated user.
    Redirects to the login page if unauthenticated, locked, or session expired.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            flash("Authentication required. Please sign in.", "warning")
            return redirect(url_for("auth.login", next=request.url))

        # Parameterized ORM lookup
        user = User.query.get(user_id)
        if not user or user.is_locked():
            session.clear()
            flash("Your account has been locked. Please contact IT Security.", "danger")
            return redirect(url_for("auth.login"))

        # Force compromised victim accounts to complete password reset
        if user.force_password_reset and request.endpoint not in (
            "auth.reset_password", "auth.logout", "static"
        ):
            flash("Your account status is compromised. You must reset your password before proceeding.", "warning")
            return redirect(url_for("auth.reset_password"))

        return f(*args, **kwargs)
    return decorated_function


def role_required(*allowed_roles):
    """
    Decorator enforcing Role-Based Access Control (RBAC).
    Permits access only if the authenticated user's role matches one of allowed_roles.
    """
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = User.query.get(session.get("user_id"))
            if not user or not user.role or user.role.name not in allowed_roles:
                flash(f"Access denied: This section requires role ({', '.join(allowed_roles)}).", "danger")
                return render_template("errors/403.html", allowed_roles=allowed_roles), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def log_login_attempt(email, status, user_id=None, failure_reason=None):
    """
    Helper to record every authentication event in the login_log table.
    """
    try:
        log_entry = LoginLog(
            user_id=user_id,
            email_attempted=email,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string[:255] if request.user_agent else None,
            status=status,
            failure_reason=failure_reason
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error logging login attempt: {e}")


# ─── AUTHENTICATION ROUTES ────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Step 1: Primary Authentication (Email + Password)
    Verifies credentials, checks lock status, generates 6-digit OTP,
    hashes and saves OTP with 5-minute expiry, then redirects to OTP verification.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter both email and password.", "danger")
            return render_template("login.html")

        # Parameterized query to prevent SQL injection
        user = User.query.filter_by(email=email).first()

        if not user:
            log_login_attempt(email, status="failed", failure_reason="User not found")
            flash("Invalid email or password.", "danger")
            return render_template("login.html")

        if user.is_locked():
            log_login_attempt(email, status="locked_blocked", user_id=user.id, failure_reason="Account is locked")
            flash("This account is locked due to security policy. Please contact an IT Administrator.", "danger")
            return render_template("login.html")

        if not user.check_password(password):
            user.failed_login_count += 1
            if user.failed_login_count >= 5:
                user.status = "locked"
                failure_reason = "Exceeded 5 failed attempts - account locked"
            else:
                failure_reason = f"Invalid password (attempt {user.failed_login_count}/5)"

            db.session.commit()
            log_login_attempt(email, status="failed", user_id=user.id, failure_reason=failure_reason)

            if user.is_locked():
                flash("Account locked due to 5 consecutive failed login attempts. Contact IT Security.", "danger")
            else:
                flash("Invalid email or password.", "danger")
            return render_template("login.html")

        # Reset failed login count on successful password verification
        user.failed_login_count = 0

        # Step 2 Preparation: Generate random 6-digit OTP
        raw_otp = f"{random.randint(100000, 999999)}"

        # Store OTP securely hashed with a 5-minute expiry
        user.set_otp(raw_otp)
        db.session.commit()

        # Place pending authentication in session
        session["pending_user_id"] = user.id
        session["pending_email"] = user.email

        # DEMO_MODE handling: display on screen and print to console
        demo_mode = current_app.config.get("DEMO_MODE", True)
        if demo_mode:
            session["demo_otp"] = raw_otp
            print(f"\n=======================================================")
            print(f"[DEMO_MODE 2FA OTP] Verification Code for {user.email}: {raw_otp}")
            print(f"=======================================================\n")

        return redirect(url_for("auth.verify_otp"))

    return render_template("login.html")


@auth_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    """
    Step 2: Two-Factor Authentication (OTP Verification)
    Compares entered code against the stored hash and validates the 5-minute expiry.
    """
    pending_user_id = session.get("pending_user_id")
    pending_email = session.get("pending_email", "user")

    if not pending_user_id:
        flash("Please log in with your credentials first.", "info")
        return redirect(url_for("auth.login"))

    user = User.query.get(pending_user_id)
    if not user:
        session.clear()
        return redirect(url_for("auth.login"))

    demo_otp = session.get("demo_otp")

    if request.method == "POST":
        entered_code = request.form.get("otp_code", "").strip()

        if not entered_code or len(entered_code) != 6:
            flash("Please enter a valid 6-digit verification code.", "danger")
            return render_template("verify_otp.html", email=pending_email, demo_otp=demo_otp)

        # Verify against stored hash and check 5-minute expiry
        if not user.check_otp(entered_code):
            log_login_attempt(user.email, status="failed", user_id=user.id, failure_reason="Invalid or expired OTP")
            flash("Invalid or expired verification code. Please request a new code.", "danger")
            return render_template("verify_otp.html", email=pending_email, demo_otp=demo_otp)

        # OTP is valid: finalize authentication
        user.clear_otp()
        db.session.commit()

        # Clear pending session and establish active user session
        session.clear()
        session["user_id"] = user.id
        session["user_email"] = user.email
        session["user_name"] = user.full_name
        session["user_role"] = user.role.name if user.role else "Employee"
        session["last_active"] = time.time()

        # Audit successful login
        log_login_attempt(user.email, status="success", user_id=user.id)

        # Check for compromised status / forced password reset
        if user.is_compromised() or user.force_password_reset:
            flash("Security Notice: Your account was flagged as compromised. You must reset your password.", "warning")
            return redirect(url_for("auth.reset_password"))

        flash(f"Welcome back, {user.full_name}!", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("verify_otp.html", email=pending_email, demo_otp=demo_otp)


@auth_bp.route("/resend-otp")
def resend_otp():
    """Generates a new 6-digit OTP and extends the 5-minute window."""
    pending_user_id = session.get("pending_user_id")
    if not pending_user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(pending_user_id)
    if not user:
        return redirect(url_for("auth.login"))

    raw_otp = f"{random.randint(100000, 999999)}"
    user.set_otp(raw_otp)
    db.session.commit()

    if current_app.config.get("DEMO_MODE", True):
        session["demo_otp"] = raw_otp
        print(f"\n[DEMO_MODE 2FA OTP RESENT] New Code for {user.email}: {raw_otp}\n")

    flash("A new verification code has been dispatched (valid for 5 minutes).", "info")
    return redirect(url_for("auth.verify_otp"))


@auth_bp.route("/reset-password", methods=["GET", "POST"])
@login_required
def reset_password():
    """
    Enables users to change their password.
    Mandatory when account is compromised or force_password_reset is True.
    """
    user = User.query.get(session["user_id"])

    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if len(new_password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("reset_password.html")

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html")

        user.set_password(new_password)
        user.force_password_reset = False
        if user.is_compromised():
            user.status = "active"

        db.session.commit()
        flash("Password updated successfully. Your account is now fully active.", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("reset_password.html", user=user)


@auth_bp.route("/logout")
def logout():
    """Terminates session and clears all user tokens."""
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))
