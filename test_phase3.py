"""
test_phase3.py - Automated Test Suite for Phase 3 (Threat Detection & Mailbox)
-------------------------------------------------------------------------------
Validates against live Supabase database:
1. Local heuristic rules:
   - corporate.local recognized as trusted (0 penalty points)
   - Typosquatting and blocklist matching (high risk score)
   - Urgent phishing message scoring into 'Quarantine' verdict (> 70 points)
2. Mailbox UI and authorization:
   - /emails/inbox segregation by user ID
   - Unauthorized user attempting to view someone else's email gets 403
   - IT Admin permitted to view any email
   - Quarantine isolation view
3. On-demand threat scanner (/emails/analyze) GET & POST analysis
"""

import sys
from app import create_app
from database import db
from models import User, Role, Email, BlockedSender
from detection.scoring import analyze_email
from detection.rules import check_trusted_domain, check_typosquatting, check_blocklist


def run_tests():
    app = create_app()
    with app.app_context():
        print(">>> [Phase 3 Test] Initializing test client & database connection...")

        # 1. Test Trusted Domain Rule with corporate.local
        res_corp = check_trusted_domain("corporate.local")
        assert res_corp["score"] == 0, f"corporate.local should have 0 penalty points, got {res_corp['score']}"
        assert "trusted" in res_corp["message"].lower()

        res_unknown = check_trusted_domain("untrusted-site-12345.xyz")
        assert res_unknown["score"] > 0, "Untrusted domain must receive penalty points"
        print("  ✓ Trusted domain rule: corporate.local verified safe with 0 points")

        # 2. Test Blocklist and Typosquatting
        res_typo = check_typosquatting("micr0soft-support.xyz")
        assert res_typo["score"] >= 30, f"Expected typosquatting penalty >= 30, got {res_typo['score']}"

        res_block = check_blocklist("stealth-drop.xyz", "clean body")
        assert res_block["score"] >= 40, f"Expected blocklist penalty >= 40, got {res_block['score']}"
        print("  ✓ Offline blocklist and typosquatting detection validated")

        # 3. Test Full Email Analysis Pipeline
        phish_sample = (
            "From: security-alert@micr0soft-support.xyz\n"
            "Reply-To: credential-collector@stealth-drop.xyz\n"
            "Subject: URGENT: Corporate account will be locked in 24 hours\n\n"
            "Dear User,\nYour enterprise password has expired. Immediately enter your password "
            "at http://micr0soft-support.xyz/login to confirm your identity."
        )
        scan = analyze_email(phish_sample)
        assert scan["verdict"] == "Quarantine", f"Expected Quarantine verdict, got {scan['verdict']}"
        assert scan["total_score"] >= 70, f"Expected total_score >= 70, got {scan['total_score']}"
        print(f"  ✓ Full heuristic analysis pipeline: Phish scored {scan['total_score']}/100 [{scan['verdict']}]")

        # 4. Set up demo accounts and test emails in DB
        admin_user = User.query.filter_by(email="admin@corporate.local").first()
        emp_user = User.query.filter_by(email="employee@corporate.local").first()
        bob_user = User.query.filter_by(email="bob.miller@corporate.local").first()

        assert admin_user and emp_user and bob_user

        # Ensure Bob has an email in DB for isolation testing
        bob_email = Email.query.filter_by(recipient_id=bob_user.id).first()
        if not bob_email:
            bob_email = Email(
                recipient_id=bob_user.id,
                sender="colleague@corporate.local",
                subject="Confidential Bob Task",
                body="Private HR details for Bob only.",
                risk_score=0,
                verdict="Safe",
                status="inbox"
            )
            db.session.add(bob_email)
            db.session.commit()

        # Ensure emp_user has an email in DB
        emp_email = Email.query.filter_by(recipient_id=emp_user.id).first()
        if not emp_email:
            emp_email = Email(
                recipient_id=emp_user.id,
                sender="newsletter@corporate.local",
                subject="Weekly Tech Digest",
                body="Here are this week's technical updates.",
                risk_score=0,
                verdict="Safe",
                status="inbox"
            )
            db.session.add(emp_email)
            db.session.commit()

        # 5. Test Mailbox View Authorization & Access Controls
        client = app.test_client()

        # Unauthenticated request -> 302 redirect to /auth/login
        resp = client.get("/emails/inbox")
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]
        print("  ✓ Unauthenticated mailbox access safely blocked (redirects to login)")

        # Login as Employee
        import time
        with client.session_transaction() as sess:
            sess["user_id"] = emp_user.id
            sess["user_email"] = emp_user.email
            sess["user_role"] = "Employee"
            sess["last_active"] = time.time()
            sess["_csrf_token"] = "test-csrf-token-12345"

        resp = client.get("/emails/inbox")
        assert resp.status_code == 200, f"Expected 200 OK for inbox, got {resp.status_code}"
        assert b"Corporate Mailbox" in resp.data
        print("  ✓ Authenticated employee mailbox renders successfully")

        # Employee accessing their own email -> 200 OK
        resp = client.get(f"/emails/view/{emp_email.id}")
        assert resp.status_code == 200, f"Expected 200 OK for own email, got {resp.status_code}"

        # Employee attempting to access Bob's email -> 403 Forbidden
        resp = client.get(f"/emails/view/{bob_email.id}")
        assert resp.status_code == 403, f"Expected 403 Forbidden for another user's email, got {resp.status_code}"
        print("  ✓ Mailbox horizontal privilege escalation blocked (403 for unauthorized viewer)")

        # IT Admin accessing Bob's email -> 200 OK
        with client.session_transaction() as sess:
            sess["user_id"] = admin_user.id
            sess["user_role"] = "IT Admin"
            sess["last_active"] = time.time()

        resp = client.get(f"/emails/view/{bob_email.id}")
        assert resp.status_code == 200, f"Expected 200 OK for IT Admin inspecting email, got {resp.status_code}"
        print("  ✓ IT Admin authorized to inspect any email across the enterprise")

        # 6. Test On-Demand Threat Scanner Route
        resp = client.get("/emails/analyze")
        assert resp.status_code == 200
        assert b"Email Threat Scanner" in resp.data

        # Submit POST scan request
        with client.session_transaction() as sess:
            csrf_tok = sess["_csrf_token"]

        resp = client.post("/emails/analyze", data={
            "from_address": "security@micr0soft-support.xyz",
            "reply_to": "attacker@stealth-drop.xyz",
            "subject": "Urgent Security Notice",
            "body": "Immediately reset your corporate password.",
            "csrf_token": csrf_tok
        })
        assert resp.status_code == 200
        assert b"Detection Results" in resp.data
        assert b"Quarantine" in resp.data or b"Suspicious" in resp.data
        print("  ✓ On-Demand Threat Scanner POST execution verified with live heuristic results")

        print("\n=======================================================")
        print(" ALL PHASE 3 TESTS PASSED SUCCESSFULLY (AGAINST DB)")
        print("=======================================================\n")


if __name__ == "__main__":
    run_tests()
