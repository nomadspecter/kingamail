"""
seed.py - Database Seed Script
-------------------------------
Student explanation:
Populates the database with initial required records:
1. Standard Roles: Employee, IT Admin, Manager
2. Corporate Departments: IT, Finance, HR, Operations
3. Demo Users with hashed passwords
4. Sample Safe, Suspicious, and Phishing emails
5. Sample Cybersecurity Training Modules

Can be executed directly via:
    python seed.py
"""

from app import create_app
from database import db
from models import (
    Department, Role, User, Email, TrainingModule,
    BlockedSender, Campaign, SimResult, Alert
)

def run_seed():
    app = create_app()
    with app.app_context():
        print("🌱 Initializing database schema...")
        db.create_all()

        # ── 1. SEED ROLES ──────────────────────────────────────────
        print("👤 Seeding roles...")
        roles_data = [
            ("Employee", "Standard corporate staff user with access to mailbox and awareness modules."),
            ("IT Admin", "Security operations administrator with full triage, incident response, and simulation control."),
            ("Manager", "Department head with access to department risk analytics and compliance reporting.")
        ]
        roles = {}
        for name, desc in roles_data:
            role = Role.query.filter_by(name=name).first()
            if not role:
                role = Role(name=name, description=desc)
                db.session.add(role)
                db.session.flush()
            roles[name] = role

        # ── 2. SEED DEPARTMENTS ────────────────────────────────────
        print("🏢 Seeding departments...")
        depts_data = [
            ("Information Technology", "IT", "Core engineering, cybersecurity, and tech infrastructure"),
            ("Finance & Accounting", "FIN", "Financial planning, payroll, and corporate treasury"),
            ("Human Resources", "HR", "Personnel onboarding, employee benefits, and workplace policy"),
            ("Sales & Operations", "OPS", "Client relations, logistics, and supply chain management")
        ]
        depts = {}
        for name, code, desc in depts_data:
            dept = Department.query.filter_by(code=code).first()
            if not dept:
                dept = Department(name=name, code=code, description=desc)
                db.session.add(dept)
                db.session.flush()
            depts[code] = dept

        # ── 3. SEED USERS ──────────────────────────────────────────
        print("👥 Seeding demo users with hashed credentials...")
        users_data = [
            {
                "email": "employee@corporate.local",
                "full_name": "Jane Doe",
                "password": "Employee123!",
                "role": roles["Employee"],
                "dept": depts["FIN"],
                "status": "active"
            },
            {
                "email": "admin@corporate.local",
                "full_name": "Alex Rivera",
                "password": "Admin123!",
                "role": roles["IT Admin"],
                "dept": depts["IT"],
                "status": "active"
            },
            {
                "email": "manager@corporate.local",
                "full_name": "Sarah Jenkins",
                "password": "Manager123!",
                "role": roles["Manager"],
                "dept": depts["OPS"],
                "status": "active"
            },
            {
                "email": "bob.miller@corporate.local",
                "full_name": "Bob Miller",
                "password": "Employee123!",
                "role": roles["Employee"],
                "dept": depts["HR"],
                "status": "compromised",
                "force_password_reset": True
            }
        ]

        users = {}
        for u_data in users_data:
            user = User.query.filter_by(email=u_data["email"]).first()
            if not user:
                user = User(
                    email=u_data["email"],
                    full_name=u_data["full_name"],
                    role_id=u_data["role"].id,
                    department_id=u_data["dept"].id if u_data["dept"] else None,
                    status=u_data["status"],
                    force_password_reset=u_data.get("force_password_reset", False)
                )
                user.set_password(u_data["password"])
                db.session.add(user)
                db.session.flush()
            users[u_data["email"]] = user

        # ── 4. SEED SAMPLE EMAILS ──────────────────────────────────
        print("✉️  Seeding sample safe, suspicious, and quarantined emails...")
        demo_emp = users["employee@corporate.local"]

        emails_data = [
            {
                "recipient_id": demo_emp.id,
                "sender": "support@microsoft.com",
                "reply_to": "support@microsoft.com",
                "subject": "Scheduled Microsoft 365 Maintenance This Weekend",
                "body": (
                    "Hello Team,\n\n"
                    "Please be advised that Microsoft will perform scheduled maintenance on our corporate Office 365 "
                    "tenant this Saturday between 02:00 UTC and 04:00 UTC. No disruption to email service is expected.\n\n"
                    "Best regards,\nCorporate IT Service Desk"
                ),
                "risk_score": 0,
                "verdict": "Safe",
                "confidence": "High",
                "indicators": [{"name": "Trusted Domain", "score": 0, "message": "Domain microsoft.com is trusted"}],
                "status": "inbox",
                "is_read": True
            },
            {
                "recipient_id": demo_emp.id,
                "sender": "hr-benefits@corporate.local",
                "reply_to": "hr-benefits@corporate.local",
                "subject": "Open Enrollment: Review Your 2026 Health and Dental Benefits",
                "body": (
                    "Dear Colleague,\n\n"
                    "Annual open enrollment for corporate health, vision, and dental benefits begins next Monday. "
                    "Please review the employee benefits portal guide on our internal intranet before submitting your elections.\n\n"
                    "Thank you,\nHuman Resources Department"
                ),
                "risk_score": 0,
                "verdict": "Safe",
                "confidence": "High",
                "indicators": [{"name": "Formatting", "score": 0, "message": "Normal formatting"}],
                "status": "inbox",
                "is_read": False
            },
            {
                "recipient_id": demo_emp.id,
                "sender": "billing-notice@unknown-contractor.com",
                "reply_to": "billing-notice@unknown-contractor.com",
                "subject": "Invoice attached for review - Please verify payment details",
                "body": (
                    "Hello,\n\n"
                    "Please see attachment regarding the outstanding invoice for services rendered last month. "
                    "Please verify payment details and invoice approved for $12,450. Open attached document immediately.\n\n"
                    "Regards,\nVendor Accounts"
                ),
                "risk_score": 45,
                "verdict": "Suspicious",
                "confidence": "Medium",
                "indicators": [
                    {"name": "Attachment Keyword", "score": 25, "message": "Prompt to open attached invoice"},
                    {"name": "Financial Fraud", "score": 20, "message": "High dollar amount $12,450 referenced"}
                ],
                "status": "inbox",
                "is_read": False
            },
            {
                "recipient_id": demo_emp.id,
                "sender": "tracking-update@dhl-express-security.xyz",
                "reply_to": "stealth-drop@gmail.com",
                "subject": "URGENT: Your DHL Package Delivery Has Been Suspended!",
                "body": (
                    "URGENT NOTICE!\n\n"
                    "Your pending package with tracking #DHL-8891244 could not be delivered due to an incorrect delivery address.\n\n"
                    "ACT NOW! Failure to act within 24 hours will result in your package being destroyed.\n\n"
                    "Please verify your credit card and billing information immediately at: "
                    "http://192.168.1.105/secure-login/dhl-verify to pay the $3.50 redelivery fee.\n\n"
                    "DHL Express Courier Service"
                ),
                "risk_score": 145,
                "verdict": "Quarantine",
                "confidence": "High",
                "indicators": [
                    {"name": "Urgency", "score": 30, "message": "Urgent act now, 24 hours, suspended keywords"},
                    {"name": "Suspicious Links", "score": 50, "message": "Raw IP address link and lookalike prefix secure-login"},
                    {"name": "Reply-To Mismatch", "score": 35, "message": "Reply-To gmail.com does not match sender domain"},
                    {"name": "Credential Harvesting", "score": 30, "message": "Requests credit card and billing information"}
                ],
                "status": "quarantined",
                "is_read": False
            },
            {
                "recipient_id": demo_emp.id,
                "sender": "security-alert@micr0soft-support.xyz",
                "reply_to": "attacker@scam-collect.top",
                "subject": "CRITICAL: Your corporate password expires in 2 hours - Confirm now",
                "body": (
                    "Dear employee,\n\n"
                    "Your enterprise single-sign-on password is scheduled to expire today. "
                    "Your account will be locked immediately if you do not confirm now.\n\n"
                    "Visit: http://bit.ly/m365-verify-credentials to enter your current password, bank account verification, and PIN number.\n\n"
                    "Corporate Security Operations"
                ),
                "risk_score": 155,
                "verdict": "Quarantine",
                "confidence": "High",
                "indicators": [
                    {"name": "Typosquatting", "score": 40, "message": "micr0soft-support.xyz impersonating microsoft.com"},
                    {"name": "Credential Harvesting", "score": 60, "message": "Requests password, bank account, and PIN"},
                    {"name": "Suspicious Links", "score": 25, "message": "URL shortener bit.ly used"},
                    {"name": "Urgency", "score": 30, "message": "Artificial urgency and threat of account lock"}
                ],
                "status": "quarantined",
                "is_read": False
            }
        ]

        for e_data in emails_data:
            existing = Email.query.filter_by(
                recipient_id=e_data["recipient_id"],
                subject=e_data["subject"]
            ).first()
            if not existing:
                email_obj = Email(**e_data)
                db.session.add(email_obj)

        # ── 5. SEED TRAINING MODULES ───────────────────────────────
        print("📚 Seeding cybersecurity awareness training modules...")
        modules_data = [
            {
                "title": "Recognizing Social Engineering & Artificial Urgency",
                "description": "Learn how threat actors exploit psychological pressure, false deadlines, and panic triggers.",
                "category": "Phishing Awareness",
                "difficulty": "Beginner",
                "estimated_minutes": 10,
                "content": (
                    "### The Psychology of Urgency\n\n"
                    "Attackers often manipulate emotions such as fear, curiosity, or greed. Phrases like 'Account Suspended in 24 Hours' "
                    "or 'Action Required Immediately' are designed to bypass rational skepticism. Always pause and independently "
                    "verify communications through official enterprise channels."
                )
            },
            {
                "title": "Spear Phishing & Executive Impersonation (CEO Fraud)",
                "description": "Understand targeted Business Email Compromise (BEC) and wire transfer spoofing schemes.",
                "category": "Advanced Threats",
                "difficulty": "Intermediate",
                "estimated_minutes": 15,
                "content": (
                    "### Defending Against Executive Spoofing\n\n"
                    "Business Email Compromise occurs when an attacker impersonates a C-level executive requesting secret gift cards, "
                    "urgent supplier payments, or payroll records. Never execute out-of-band wire transfers without voice confirmation."
                )
            }
        ]

        for m_data in modules_data:
            existing_mod = TrainingModule.query.filter_by(title=m_data["title"]).first()
            if not existing_mod:
                mod = TrainingModule(**m_data)
                db.session.add(mod)

        # ── 6. SEED SAMPLE BLOCKED SENDER ──────────────────────────
        print("🚫 Seeding initial blocked senders...")
        sample_blocked = "tracking-update@dhl-express-security.xyz"
        if not BlockedSender.query.filter_by(sender_value=sample_blocked).first():
            blocked = BlockedSender(
                sender_value=sample_blocked,
                blocked_by_user_id=users["admin@corporate.local"].id,
                reason="Confirmed active phishing credential harvester"
            )
            db.session.add(blocked)

        db.session.commit()
        print("\n✅ Database seeding successfully completed!")
        print("--------------------------------------------------")
        print("Demo Logins Seeded:")
        print("  • Employee: employee@corporate.local / Employee123!")
        print("  • IT Admin: admin@corporate.local    / Admin123!")
        print("  • Manager:  manager@corporate.local  / Manager123!")
        print("--------------------------------------------------")

if __name__ == "__main__":
    run_seed()
