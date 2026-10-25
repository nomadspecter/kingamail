"""
test_phase5.py - Automated Test Suite for Phase 5 (Simulation Engine & Awareness Training)
------------------------------------------------------------------------------------------
Validates against live Supabase database:
1. Quiz Question & Option tables:
   - Verified 5 questions per module seeded in database
   - Verified each question has valid options and exactly 1 correct answer
2. Phishing Simulation Campaign:
   - IT Admin creates campaign -> Campaign and SimResult records created
   - Simulated email placed in participant inbox with unique tracking token
   - Tracking link endpoint (/simulation/track/<token>) records click event only
   - Confirms NO credential fields exist on the landing page
   - Employee reporting the simulated email marks sim_result.is_reported=True
3. Quiz taking and scoring from database:
   - Submits answers evaluated against quiz_option.is_correct
   - Grades percentage score and saves to quiz_result table
"""

import sys
import time
from app import create_app
from database import db
from models import (
    User, Role, Email, Campaign, SimResult,
    TrainingModule, QuizQuestion, QuizOption, QuizResult, Report
)


def run_tests():
    app = create_app()
    with app.app_context():
        print(">>> [Phase 5 Test] Initializing test client & database connection...")

        admin_user = User.query.filter_by(email="admin@corporate.local").first()
        emp_user = User.query.filter_by(email="employee@corporate.local").first()
        assert admin_user and emp_user, "Required demo accounts must exist"

        # Ensure employee is active
        emp_user.status = "active"
        emp_user.force_password_reset = False
        db.session.commit()

        # 1. Verify Quiz Tables & 5 Questions per Module
        modules = TrainingModule.query.all()
        assert len(modules) >= 3, f"Expected >= 3 training modules, got {len(modules)}"

        for mod in modules:
            questions = QuizQuestion.query.filter_by(module_id=mod.id).all()
            assert len(questions) == 5, f"Module '{mod.title}' should have exactly 5 questions, found {len(questions)}"
            for q in questions:
                assert len(q.options) >= 2, f"Question #{q.id} must have >= 2 options"
                correct_opts = [o for o in q.options if o.is_correct]
                assert len(correct_opts) == 1, f"Question #{q.id} must have exactly 1 correct option"

        print("  ✓ Database migration & schema verified: 5 quiz questions & options per module loaded")

        client = app.test_client()

        # 2. IT Admin creates a Phishing Simulation Campaign
        with client.session_transaction() as sess:
            sess["user_id"] = admin_user.id
            sess["user_email"] = admin_user.email
            sess["user_role"] = "IT Admin"
            sess["last_active"] = time.time()
            sess["_csrf_token"] = "phase5-csrf-token"

        camp_name = f"Test Simulation {int(time.time())}"
        resp = client.post("/simulation/create", data={
            "csrf_token": "phase5-csrf-token",
            "name": camp_name,
            "description": "Simulated credential phishing audit",
            "subject": "Urgent Security Action Required",
            "body": "Please click the link below to verify your session.",
            "target_scope": "all"
        }, follow_redirects=True)

        assert resp.status_code == 200
        campaign = Campaign.query.filter_by(name=camp_name).first()
        assert campaign is not None, "Campaign was not created"
        assert len(campaign.results) > 0, "No SimResults generated for campaign"

        # Verify simulated email in employee inbox
        sim_res = SimResult.query.filter_by(campaign_id=campaign.id, user_id=emp_user.id).first()
        assert sim_res is not None, "SimResult for employee not found"
        assert sim_res.is_clicked is False
        assert sim_res.is_reported is False

        sim_email = Email.query.filter_by(
            recipient_id=emp_user.id,
            subject=f"[Simulated] {campaign.template_subject}"
        ).order_by(Email.id.desc()).first()
        assert sim_email is not None, "Simulated email was not delivered to recipient inbox"
        assert sim_res.tracking_token in sim_email.body
        print("  ✓ Phishing simulation campaign created and email delivered to mailbox")

        # 3. Test Tracking Link (/simulation/track/<token>)
        # Click tracking must record the click and display the landing page with zero credentials
        resp = client.get(f"/simulation/track/{sim_res.tracking_token}")
        assert resp.status_code == 200
        assert b"You Clicked a Simulated Phishing Link" in resp.data
        assert b"Your Privacy is Protected" in resp.data

        # CRITICAL PRIVACY ASSERTIONS: Never collect or store credentials
        assert b'type="password"' not in resp.data, "SECURITY VIOLATION: Password field found on landing page"
        assert b'name="password"' not in resp.data, "SECURITY VIOLATION: Password input found on landing page"

        db.session.refresh(sim_res)
        assert sim_res.is_clicked is True, "sim_result.is_clicked was not updated to True"
        assert sim_res.clicked_at is not None
        print("  ✓ Simulation click tracking verified (click recorded, landing page rendered, zero credentials collected)")

        # 4. Test Employee Reporting the Simulation Email
        with client.session_transaction() as sess:
            sess["user_id"] = emp_user.id
            sess["user_email"] = emp_user.email
            sess["user_role"] = "Employee"
            sess["last_active"] = time.time()
            sess["_csrf_token"] = "phase5-csrf-token"

        resp = client.post(f"/reports/submit/{sim_email.id}", data={
            "csrf_token": "phase5-csrf-token",
            "reason": "Reported simulated test email"
        }, follow_redirects=True)

        assert resp.status_code == 200
        db.session.refresh(sim_res)
        assert sim_res.is_reported is True, "sim_result.is_reported was not marked True on reporting"
        assert sim_res.reported_at is not None
        print("  ✓ Simulated email reporting hook verified (sim_result.is_reported=True)")

        # 5. Test Quiz Taking and Scoring from Database
        first_mod = modules[0]
        questions = QuizQuestion.query.filter_by(module_id=first_mod.id).order_by(QuizQuestion.id).all()

        # Submit 4 correct answers and 1 incorrect answer (80% score)
        quiz_data = {"csrf_token": "phase5-csrf-token"}
        for i, q in enumerate(questions):
            correct_opt = next(o for o in q.options if o.is_correct)
            wrong_opt = next(o for o in q.options if not o.is_correct)
            # Make the first question wrong, remaining 4 correct
            selected = wrong_opt if i == 0 else correct_opt
            quiz_data[f"question_{q.id}"] = str(selected.id)

        resp = client.post(f"/training/quiz/{first_mod.id}", data=quiz_data)
        assert resp.status_code == 200
        assert b"Assessment Passed" in resp.data
        assert b"80%" in resp.data

        # Verify quiz_result in database
        result_record = QuizResult.query.filter_by(
            user_id=emp_user.id,
            training_module_id=first_mod.id
        ).first()
        assert result_record is not None, "QuizResult was not recorded in database"
        assert result_record.score == 80, f"Expected 80% score, got {result_record.score}"
        assert result_record.correct_answers == 4
        assert result_record.total_questions == 5
        assert result_record.passed is True
        print(f"  ✓ Interactive quiz scoring verified against DB questions (Score: {result_record.score}%, 4/5 correct, Passed: {result_record.passed})")

        print("\n=======================================================")
        print(" ALL PHASE 5 TESTS PASSED SUCCESSFULLY (AGAINST DB)")
        print("=======================================================\n")


if __name__ == "__main__":
    run_tests()
