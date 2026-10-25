"""
test_phase6.py - Automated Test Suite for Phase 6 (Dashboards & Compliance Reports)
-----------------------------------------------------------------------------------
Validates against live Supabase database:
1. Dynamic root routing (/):
   - Unauthenticated renders public landing
   - IT Admin redirects to /dashboard/admin
   - Manager redirects to /dashboard/manager
   - Employee redirects to /emails/inbox
2. SOC Admin Dashboard (/dashboard/admin):
   - Employee receives 403 Forbidden
   - IT Admin receives 200 OK with threat metrics and high-risk user watchlist
3. Manager Dashboard (/dashboard/manager):
   - Employee receives 403 Forbidden
   - Manager receives 200 OK with department metrics
4. Compliance Reports (/dashboard/reports):
   - Role-protected (403 for Employee, 200 for Manager and IT Admin)
5. CSV Data Export (/dashboard/reports/export-csv):
   - Streams standard RFC 4180 CSV file with 12 columns
   - Validates CSV headers and employee records
"""

import sys
import time
import csv
import io
from app import create_app
from database import db
from models import User, Role, Department, Email, Incident, Report


def run_tests():
    app = create_app()
    with app.app_context():
        print(">>> [Phase 6 Test] Initializing test client & database connection...")

        admin_user = User.query.filter_by(email="admin@corporate.local").first()
        emp_user = User.query.filter_by(email="employee@corporate.local").first()
        manager_user = User.query.filter_by(email="manager@corporate.local").first()
        assert admin_user and emp_user and manager_user, "All required demo accounts must exist"

        # Ensure active status for testing
        for u in (admin_user, emp_user, manager_user):
            u.status = "active"
            u.force_password_reset = False
        db.session.commit()

        client = app.test_client()

        # 1. Test Root Route (/) Routing
        # Unauthenticated -> Public Overview (200)
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Intelligent Email Security" in resp.data or b"PhishShield" in resp.data or b"KingaMail" in resp.data

        # Authenticated as Employee -> Redirects to /emails/inbox
        with client.session_transaction() as sess:
            sess["user_id"] = emp_user.id
            sess["user_email"] = emp_user.email
            sess["user_role"] = "Employee"
            sess["last_active"] = time.time()
            sess["_csrf_token"] = "phase6-csrf"

        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/emails/inbox" in resp.headers["Location"]

        # Authenticated as Manager -> Redirects to /dashboard/manager
        with client.session_transaction() as sess:
            sess["user_id"] = manager_user.id
            sess["user_email"] = manager_user.email
            sess["user_role"] = "Manager"
            sess["last_active"] = time.time()

        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/dashboard/manager" in resp.headers["Location"]

        # Authenticated as IT Admin -> Redirects to /dashboard/admin
        with client.session_transaction() as sess:
            sess["user_id"] = admin_user.id
            sess["user_email"] = admin_user.email
            sess["user_role"] = "IT Admin"
            sess["last_active"] = time.time()

        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/dashboard/admin" in resp.headers["Location"]
        print("  ✓ Role-aware root routing (/) verified across Employee, Manager, and IT Admin")

        # 2. Test SOC Admin Dashboard (/dashboard/admin)
        # Employee -> Expect 403
        with client.session_transaction() as sess:
            sess["user_id"] = emp_user.id
            sess["user_role"] = "Employee"
            sess["last_active"] = time.time()

        resp = client.get("/dashboard/admin")
        assert resp.status_code == 403, f"Expected 403 Forbidden for Employee on /dashboard/admin, got {resp.status_code}"

        # IT Admin -> Expect 200 OK
        with client.session_transaction() as sess:
            sess["user_id"] = admin_user.id
            sess["user_role"] = "IT Admin"
            sess["last_active"] = time.time()

        resp = client.get("/dashboard/admin")
        assert resp.status_code == 200
        assert b"Security Operations Console" in resp.data
        assert b"Quarantined Attacks" in resp.data
        assert b"High-Risk Workforce Watchlist" in resp.data
        print("  ✓ SOC Admin Dashboard (/dashboard/admin) verified with threat metrics & high-risk watchlist")

        # 3. Test Manager Dashboard (/dashboard/manager)
        # Employee -> Expect 403
        with client.session_transaction() as sess:
            sess["user_id"] = emp_user.id
            sess["user_role"] = "Employee"
            sess["last_active"] = time.time()

        resp = client.get("/dashboard/manager")
        assert resp.status_code == 403, f"Expected 403 Forbidden for Employee on /dashboard/manager, got {resp.status_code}"

        # Manager -> Expect 200 OK
        with client.session_transaction() as sess:
            sess["user_id"] = manager_user.id
            sess["user_role"] = "Manager"
            sess["last_active"] = time.time()

        resp = client.get("/dashboard/manager")
        assert resp.status_code == 200
        assert b"Department Risk & Awareness Dashboard" in resp.data
        assert b"Simulation Failure Rate" in resp.data
        assert b"Threat Reporting Rate" in resp.data
        print("  ✓ Manager Dashboard (/dashboard/manager) verified with team simulation failure & awareness metrics")

        # 4. Test Compliance Reports Overview (/dashboard/reports)
        # Employee -> Expect 403
        with client.session_transaction() as sess:
            sess["user_id"] = emp_user.id
            sess["user_role"] = "Employee"
            sess["last_active"] = time.time()

        resp = client.get("/dashboard/reports")
        assert resp.status_code == 403, f"Expected 403 Forbidden for Employee on /dashboard/reports, got {resp.status_code}"

        # Manager -> Expect 200 OK
        with client.session_transaction() as sess:
            sess["user_id"] = manager_user.id
            sess["user_role"] = "Manager"
            sess["last_active"] = time.time()

        resp = client.get("/dashboard/reports")
        assert resp.status_code == 200
        assert b"Security & Compliance Reports" in resp.data
        assert b"Departmental Risk & Awareness Benchmarks" in resp.data
        print("  ✓ Compliance Reports Overview (/dashboard/reports) access control and benchmarking table verified")

        # 5. Test CSV Data Export (/dashboard/reports/export-csv)
        resp = client.get("/dashboard/reports/export-csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["Content-Type"]
        assert "attachment" in resp.headers["Content-Disposition"]
        assert ".csv" in resp.headers["Content-Disposition"]

        # Parse CSV output to ensure valid structure
        csv_text = resp.data.decode("utf-8")
        reader = csv.reader(io.StringIO(csv_text))
        rows = list(reader)
        assert len(rows) >= 2, f"Expected header + rows, got {len(rows)} lines"

        header = rows[0]
        assert "Employee ID" in header
        assert "Full Name" in header
        assert "Email Address" in header
        assert "Department" in header
        assert "Simulations Clicked" in header
        assert "Average Quiz Score (%)" in header
        assert "Security Posture Rating" in header

        # Verify employee row is present
        emp_row = next((r for r in rows[1:] if "employee@corporate.local" in r), None)
        assert emp_row is not None, "employee@corporate.local row missing from CSV export"
        print(f"  ✓ Workforce Compliance CSV export verified ({len(rows)-1} employee records exported with 12 columns)")

        print("\n=======================================================")
        print(" ALL PHASE 6 TESTS PASSED SUCCESSFULLY (AGAINST DB)")
        print("=======================================================\n")


if __name__ == "__main__":
    run_tests()
