"""
test_phase4.py - Automated Test Suite for Phase 4 (Incident Response Workflow)
-------------------------------------------------------------------------------
Validates against live Supabase database:
1. Employee phishing report submission (Report record created, email.is_reported=True).
2. Admin triage queue access control (403 for employee, 200 for IT Admin).
3. SOC Admin triages report as 'phishing':
   - Incident created with format INC-YYYY-XXXX
   - Malicious sender blacklisted in blocked_sender table
   - Victim account flagged as 'compromised' with force_password_reset=True
   - Security broadcast Alert and AlertRecipient records created for all users
   - Immutable chronological actions_log audit trail recorded
4. Incident resolution workflow (/incidents/close/<id> marks status='resolved').
5. Alert viewing and acknowledgment by employees (/alerts/acknowledge/<id>).
"""

import sys
import time
from datetime import datetime
from app import create_app
from database import db
from models import User, Role, Email, Report, Incident, BlockedSender, Alert, AlertRecipient


def run_tests():
    app = create_app()
    with app.app_context():
        print(">>> [Phase 4 Test] Initializing test client & database connection...")

        admin_user = User.query.filter_by(email="admin@corporate.local").first()
        emp_user = User.query.filter_by(email="employee@corporate.local").first()
        assert admin_user and emp_user, "Required demo accounts must exist"

        # Ensure employee starts in active state for testing
        emp_user.status = "active"
        emp_user.force_password_reset = False
        db.session.commit()

        # 1. Create a fresh unique test email for this test run
        unique_subject = f"Phishing Threat Assessment {int(time.time())}"
        test_email = Email(
            recipient_id=emp_user.id,
            sender=f"scammer-{int(time.time())}@micr0soft-support.xyz",
            subject=unique_subject,
            body="Your account will be suspended. Click here to confirm credentials.",
            risk_score=85,
            verdict="Quarantine",
            status="inbox",
            is_reported=False
        )
        db.session.add(test_email)
        db.session.commit()

        client = app.test_client()

        # 2. Employee reports phishing
        with client.session_transaction() as sess:
            sess["user_id"] = emp_user.id
            sess["user_email"] = emp_user.email
            sess["user_role"] = "Employee"
            sess["last_active"] = time.time()
            sess["_csrf_token"] = "phase4-csrf-token"

        resp = client.post(f"/reports/submit/{test_email.id}", data={
            "csrf_token": "phase4-csrf-token",
            "reason": "Suspicious password request from micr0soft lookalike domain"
        }, follow_redirects=True)

        assert resp.status_code == 200
        db.session.refresh(test_email)
        assert test_email.is_reported is True, "email.is_reported should be True after reporting"

        report = Report.query.filter_by(email_id=test_email.id).first()
        assert report is not None, "Report record was not created"
        assert report.admin_verdict == "pending", f"Expected admin_verdict 'pending', got {report.admin_verdict}"
        print("  ✓ Employee 'Report Phishing' workflow verified (Report created, is_reported=True)")

        # 3. Test RBAC on Triage Queue (/reports/)
        # Employee should receive 403
        resp = client.get("/reports/")
        assert resp.status_code == 403, f"Expected 403 Forbidden for Employee on /reports/, got {resp.status_code}"

        # Switch to IT Admin
        with client.session_transaction() as sess:
            sess["user_id"] = admin_user.id
            sess["user_email"] = admin_user.email
            sess["user_role"] = "IT Admin"
            sess["last_active"] = time.time()
            sess["_csrf_token"] = "phase4-csrf-token"

        resp = client.get("/reports/")
        assert resp.status_code == 200, f"Expected 200 OK for IT Admin on /reports/, got {resp.status_code}"
        assert b"SOC Phishing Triage Queue" in resp.data
        print("  ✓ SOC Triage Queue access control validated (403 for Employee, 200 for IT Admin)")

        # 4. SOC Admin Triages Report as 'phishing'
        resp = client.post(f"/reports/triage/{report.id}", data={
            "csrf_token": "phase4-csrf-token",
            "verdict": "phishing",
            "notes": "Verified malicious credential harvesting domain."
        }, follow_redirects=False)

        assert resp.status_code == 302, f"Expected 302 redirect to incident docket, got {resp.status_code}"
        assert "/incidents/view/" in resp.headers["Location"], "Did not redirect to new incident docket"

        # Verify Report state
        db.session.refresh(report)
        assert report.admin_verdict == "phishing"
        assert report.reviewed_by_user_id == admin_user.id

        # Verify Incident was created
        incident = Incident.query.filter_by(report_id=report.id).first()
        assert incident is not None, "Incident was not created upon phishing triage"
        assert incident.incident_number.startswith("INC-"), f"Invalid incident number: {incident.incident_number}"
        assert incident.status == "open"
        assert incident.severity == "high"

        # Verify Sender was blacklisted in BlockedSender table
        blocked = BlockedSender.query.filter_by(sender_value=test_email.sender).first()
        assert blocked is not None, "Malicious sender was not added to BlockedSender table"

        # Verify Victim Account Containment (emp_user flagged compromised)
        db.session.refresh(emp_user)
        assert emp_user.status == "compromised", f"Expected victim status 'compromised', got {emp_user.status}"
        assert emp_user.force_password_reset is True, "force_password_reset was not set to True"

        # Verify Enterprise Security Advisory Alert and AlertRecipient records
        alert = Alert.query.filter_by(incident_id=incident.id).first()
        assert alert is not None, "Enterprise alert was not created for incident"
        assert alert.severity == "danger"
        assert "Active Phishing Threat Blocked" in alert.title

        all_user_count = User.query.count()
        recipients_count = AlertRecipient.query.filter_by(alert_id=alert.id).count()
        assert recipients_count == all_user_count, f"Alert should be broadcast to all {all_user_count} users, got {recipients_count}"

        # Verify Chronological actions_log
        assert incident.actions_log is not None
        assert len(incident.actions_log) >= 4, f"Expected >= 4 logged actions, got {len(incident.actions_log)}"
        actions = [a["action"] for a in incident.actions_log]
        assert "Security Incident Opened" in actions
        assert "Sender Blacklisted" in actions
        assert "Victim Account Contained" in actions
        assert "Enterprise Advisory Broadcast" in actions
        print(f"  ✓ Full incident response execution validated ({incident.incident_number} opened, sender blocked, victim contained, {recipients_count} alerts broadcast)")

        # 5. Test Incident Close / Resolution Workflow
        resp = client.post(f"/incidents/close/{incident.id}", data={
            "csrf_token": "phase4-csrf-token",
            "resolution_notes": "Sender domain blocked on firewall. Account verified."
        }, follow_redirects=True)

        assert resp.status_code == 200
        db.session.refresh(incident)
        assert incident.status == "resolved", f"Expected incident status 'resolved', got {incident.status}"
        assert incident.resolved_at is not None
        last_action = incident.actions_log[-1]
        assert "Incident Resolved & Closed" in last_action["action"]
        print("  ✓ Incident resolution & closing workflow validated with audit log entry")

        # 6. Test Alert Acknowledgment by Employee
        # Simulate user completing password reset remediation to restore account to active
        emp_user.status = "active"
        emp_user.force_password_reset = False
        db.session.commit()

        with client.session_transaction() as sess:
            sess["user_id"] = emp_user.id
            sess["user_role"] = "Employee"
            sess["last_active"] = time.time()
            sess["_csrf_token"] = "phase4-csrf-token"

        resp = client.post(f"/alerts/acknowledge/{alert.id}", data={
            "csrf_token": "phase4-csrf-token"
        }, follow_redirects=True)

        assert resp.status_code == 200
        emp_receipt = AlertRecipient.query.filter_by(alert_id=alert.id, user_id=emp_user.id).first()
        assert emp_receipt.is_read is True, "Alert receipt was not marked as read"
        assert emp_receipt.read_at is not None
        print("  ✓ Alert delivery and employee acknowledgment validated")

        # Restore emp_user status to active for subsequent tests
        emp_user.status = "active"
        emp_user.force_password_reset = False
        db.session.commit()

        print("\n=======================================================")
        print(" ALL PHASE 4 TESTS PASSED SUCCESSFULLY (AGAINST DB)")
        print("=======================================================\n")


if __name__ == "__main__":
    run_tests()
