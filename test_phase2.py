"""
test_phase2.py - Automated Test Suite for Phase 2 (Authentication & RBAC)
-------------------------------------------------------------------------
Validates against the live database:
1. User credential validation and password hashing (PBKDF2/SHA256).
2. Account lockout on 5 consecutive failed login attempts.
3. 2FA OTP generation, hashing, 5-minute expiry, and verification.
4. Session management, inactivity timeout (15 minutes).
5. Audit logging in login_log table for all attempts.
6. Role-Based Access Control (RBAC) via @login_required and @role_required.
"""

import sys
import time
from datetime import datetime, timedelta
from app import create_app
from database import db
from models import User, Role, Department, LoginLog


def run_tests():
    app = create_app()
    with app.app_context():
        print(">>> [Phase 2 Test] Initializing test client & database connection...")

        # 1. Verify roles and test users exist
        admin_user = User.query.filter_by(email="admin@corporate.local").first()
        emp_user = User.query.filter_by(email="employee@corporate.local").first()
        manager_user = User.query.filter_by(email="manager@corporate.local").first()

        assert admin_user is not None, "admin@corporate.local must exist"
        assert emp_user is not None, "employee@corporate.local must exist"
        assert manager_user is not None, "manager@corporate.local must exist"
        print("  ✓ Verified demo users exist in Supabase database")

        # 2. Test Password Hashing and Verification
        assert emp_user.check_password("Employee123!"), "Password verification failed for employee"
        assert not emp_user.check_password("WrongPassword!"), "False positive in password check"
        print("  ✓ Password hashing and verification working correctly")

        # 3. Test OTP Generation, Hashing, and 5-minute Expiration
        raw_otp = "847291"
        emp_user.set_otp(raw_otp)
        db.session.commit()

        # OTP is stored hashed, not plaintext
        assert emp_user.otp_code != raw_otp, "OTP must NOT be stored in plaintext"
        assert len(emp_user.otp_code) > 20, "OTP hash appears malformed"
        assert emp_user.check_otp(raw_otp) is True, "Valid OTP verification failed"
        assert emp_user.check_otp("000000") is False, "Invalid OTP was accepted"

        # Check expiry calculation is within 5 minutes
        now = datetime.utcnow()
        time_diff = (emp_user.otp_expiry - now).total_seconds()
        assert 250 <= time_diff <= 305, f"OTP expiry should be ~300s, got {time_diff}s"

        # Test simulated expired OTP
        emp_user.otp_expiry = datetime.utcnow() - timedelta(seconds=10)
        assert emp_user.check_otp(raw_otp) is False, "Expired OTP was erroneously accepted"

        # Clear OTP
        emp_user.clear_otp()
        db.session.commit()
        assert emp_user.otp_code is None, "clear_otp did not wipe otp_code"
        assert emp_user.otp_expiry is None, "clear_otp did not wipe otp_expiry"
        print("  ✓ 2FA OTP hashed storage and 5-minute expiry validated")

        # Register test route for RBAC testing before first request
        from routes.auth import role_required
        @app.route("/test-admin-only")
        @role_required("IT Admin")
        def test_admin_only():
            return "SOC Admin Secret Data", 200

        # 4. Test Lockout Logic
        test_email = "lockout_test@corporate.local"
        test_user = User.query.filter_by(email=test_email).first()
        if not test_user:
            emp_role = Role.query.filter_by(name="Employee").first()
            test_user = User(
                email=test_email,
                full_name="Lockout Test User",
                role_id=emp_role.id,
                status="active",
                failed_login_count=0
            )
            test_user.set_password("SecurePass123!")
            db.session.add(test_user)
            db.session.commit()

        test_user.status = "active"
        test_user.failed_login_count = 0
        db.session.commit()

        client = app.test_client()

        # Perform 5 consecutive bad logins
        for i in range(1, 6):
            # Fetch CSRF token
            resp = client.get("/auth/login")
            with client.session_transaction() as sess:
                token = sess.get("_csrf_token")
            
            resp = client.post("/auth/login", data={
                "email": test_email,
                "password": f"WrongAttempt{i}",
                "csrf_token": token
            }, follow_redirects=True)

        db.session.refresh(test_user)
        assert test_user.failed_login_count >= 5, f"Expected failed_login_count >= 5, got {test_user.failed_login_count}"
        assert test_user.status == "locked", f"Expected user status 'locked', got {test_user.status}"
        assert test_user.is_locked() is True, "is_locked() returned False"
        print("  ✓ Account lockout after 5 consecutive bad passwords validated")

        # Clean up test user
        test_user.status = "active"
        test_user.failed_login_count = 0
        db.session.commit()

        # 5. Test Full Two-Step Authentication Flow with TestClient
        client = app.test_client()
        # Step 1: GET login page to populate CSRF token
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        with client.session_transaction() as sess:
            csrf_token = sess.get("_csrf_token")

        # POST valid credentials
        resp = client.post("/auth/login", data={
            "email": "employee@corporate.local",
            "password": "Employee123!",
            "csrf_token": csrf_token
        }, follow_redirects=False)

        assert resp.status_code == 302, f"Expected 302 redirect to OTP, got {resp.status_code}"
        assert "/auth/verify-otp" in resp.headers["Location"], "Did not redirect to /auth/verify-otp"

        with client.session_transaction() as sess:
            demo_otp = sess.get("demo_otp")
            assert demo_otp is not None, "DEMO_MODE OTP was not set in session"
            assert len(demo_otp) == 6, f"Invalid demo OTP length: {demo_otp}"
            pending_user_id = sess.get("pending_user_id")
            assert pending_user_id == emp_user.id, "pending_user_id mismatch"

        # Step 2: POST valid OTP
        resp = client.post("/auth/verify-otp", data={
            "otp_code": demo_otp,
            "csrf_token": csrf_token
        }, follow_redirects=False)

        assert resp.status_code == 302, f"Expected 302 redirect after OTP verify, got {resp.status_code}"
        with client.session_transaction() as sess:
            assert sess.get("user_id") == emp_user.id, "User session not established after OTP verify"
            assert sess.get("user_role") == "Employee", "User role not stored in session"
        print("  ✓ Full 2-step authentication flow (Password + OTP) succeeded")

        # 6. Verify LoginLog Audit Entries
        logs = LoginLog.query.filter_by(email_attempted="employee@corporate.local").order_by(LoginLog.id.desc()).limit(5).all()
        assert len(logs) > 0, "No login logs recorded"
        assert any(l.status == "success" for l in logs), "Success status not logged in login_log"
        print("  ✓ Audit logging in login_log verified")

        # 7. Test Role-Based Access Control (RBAC)
        # Request as Employee -> Expect 403
        resp = client.get("/test-admin-only")
        assert resp.status_code == 403, f"Expected 403 Forbidden for Employee, got {resp.status_code}"

        # Switch session to IT Admin
        with client.session_transaction() as sess:
            sess["user_id"] = admin_user.id
            sess["user_role"] = "IT Admin"

        resp = client.get("/test-admin-only")
        assert resp.status_code == 200, f"Expected 200 OK for IT Admin, got {resp.status_code}"
        print("  ✓ Role-Based Access Control (@role_required) verified (403 for unauthorized, 200 for permitted)")

        # 8. Test 15-Minute Session Inactivity Timeout
        with client.session_transaction() as sess:
            # Set last_active to 16 minutes ago (960 seconds)
            sess["last_active"] = time.time() - 960

        resp = client.get("/test-admin-only", follow_redirects=False)
        assert resp.status_code == 302, "Expected redirect to login when session has expired"
        assert "/auth/login" in resp.headers["Location"], "Did not redirect to /auth/login on inactivity timeout"
        print("  ✓ 15-minute inactivity session timeout verified")

        print("\n=======================================================")
        print(" ALL PHASE 2 TESTS PASSED SUCCESSFULLY (AGAINST DB)")
        print("=======================================================\n")


if __name__ == "__main__":
    run_tests()
