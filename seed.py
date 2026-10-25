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

        # ── 5. SEED TRAINING MODULES & QUIZ QUESTIONS ──────────────
        print("📚 Seeding cybersecurity awareness training modules & quiz questions...")
        from models import QuizQuestion, QuizOption

        modules_data = [
            {
                "title": "Recognizing Social Engineering & Artificial Urgency",
                "description": "Learn how threat actors exploit psychological pressure, false deadlines, and panic triggers.",
                "category": "Phishing Awareness",
                "difficulty": "Beginner",
                "estimated_minutes": 10,
                "content": (
                    "### The Psychology of Urgency\n\n"
                    "Attackers often manipulate emotions such as fear, curiosity, or panic. Phrases like 'Account Suspended in 24 Hours' "
                    "or 'Action Required Immediately' are designed to bypass rational skepticism. Always pause and independently "
                    "verify communications through official enterprise channels."
                ),
                "questions": [
                    {
                        "text": "What is the primary objective of artificial urgency in phishing emails?",
                        "explanation": "Attackers manufacture artificial time pressure to cause victims to act impulsively without verifying authenticity.",
                        "options": [
                            ("To help recipients complete their tasks ahead of company deadlines.", False),
                            ("To trigger panic and bypass the recipient's critical skepticism.", True),
                            ("To comply with enterprise security auditing protocols.", False),
                            ("To test server network bandwidth under heavy load.", False)
                        ]
                    },
                    {
                        "text": "An email claims your payroll direct deposit failed and provides a link to 're-enter your bank account immediately'. What is the safest response?",
                        "explanation": "Always verify payroll or banking requests through verified, out-of-band channels like the corporate intranet or direct phone calls.",
                        "options": [
                            ("Click the link and quickly submit your bank credentials to avoid delay.", False),
                            ("Forward the email to all department coworkers to warn them.", False),
                            ("Do not click any link; navigate directly to the company intranet or contact HR via phone.", True),
                            ("Reply to the email with your updated bank routing number.", False)
                        ]
                    },
                    {
                        "text": "Which of the following phrases is a classic indicator of emotional manipulation in phishing?",
                        "explanation": "Threats of immediate legal action or account termination are common psychological coercion tactics used in phishing attacks.",
                        "options": [
                            ("Please find the quarterly team meeting minutes attached for review.", False),
                            ("URGENT: Legal action will be taken if you do not confirm your credentials within 2 hours.", True),
                            ("The company cafeteria menu has been updated for this week.", False),
                            ("Reminder: Holiday office closure schedule is posted on the bulletin board.", False)
                        ]
                    },
                    {
                        "text": "Why do attackers often instruct victims to 'keep this request confidential and do not inform anyone'?",
                        "explanation": "Isolation prevents the victim from double-checking with IT security or managers, making the fraud harder to detect before completion.",
                        "options": [
                            ("To maintain trade secrecy under standard nondisclosure agreements.", False),
                            ("To prevent the victim from consulting IT or colleagues who might identify the scam.", True),
                            ("To minimize internal network traffic on mail servers.", False),
                            ("Because executive bonuses must remain private by law.", False)
                        ]
                    },
                    {
                        "text": "If an email appears to come from an internal colleague but creates intense urgency and asks for sensitive data, what should you inspect first?",
                        "explanation": "Display names are trivial to spoof. Inspecting the actual header address and verifying via a secondary communication channel is essential.",
                        "options": [
                            ("Inspect the font family and color scheme of the text.", False),
                            ("Check the full email address, reply-to header, and verify with the sender in person or by phone.", True),
                            ("Assume it is legitimate if the colleague's name is spelled correctly.", False),
                            ("Open all attachments in full screen to check for watermarks.", False)
                        ]
                    }
                ]
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
                ),
                "questions": [
                    {
                        "text": "What is Business Email Compromise (BEC)?",
                        "explanation": "BEC specifically involves highly targeted impersonation of high-level personnel to redirect funds or steal sensitive data.",
                        "options": [
                            ("A distributed denial-of-service attack on email exchange servers.", False),
                            ("A targeted scam where attackers impersonate corporate executives or vendors to authorize fraudulent payments.", True),
                            ("An automated spam bot that sends mass promotional newsletters.", False),
                            ("A hardware failure occurring on enterprise email storage arrays.", False)
                        ]
                    },
                    {
                        "text": "You receive an email from the CEO asking you to urgently purchase $2,000 in gift cards for an undisclosed client meeting. What should you do?",
                        "explanation": "Gift card purchase requests are almost always fraudulent because gift card funds are untraceable and cannot be refunded.",
                        "options": [
                            ("Buy the gift cards immediately using your company card and email the activation codes.", False),
                            ("Recognize this as a classic CEO fraud pattern and report it to IT Security.", True),
                            ("Ask the sender to reimburse you in cash upon delivery.", False),
                            ("Post the codes on the company Slack channel.", False)
                        ]
                    },
                    {
                        "text": "What makes spear phishing significantly more dangerous than generic bulk phishing?",
                        "explanation": "Spear phishing uses research on the victim's role, projects, and colleagues to construct convincing, highly relevant lures.",
                        "options": [
                            ("It always carries encrypted malware binaries.", False),
                            ("It uses tailored, personalized information about the target gathered from public sources.", True),
                            ("It bypasses all corporate network firewalls automatically.", False),
                            ("It can only be sent from government-registered servers.", False)
                        ]
                    },
                    {
                        "text": "An email claims to be from the CFO and demands an immediate wire transfer to a new vendor bank account. What corporate policy applies?",
                        "explanation": "Wire transfers must always require out-of-band verification and dual-control approval to prevent unauthorized financial diversion.",
                        "options": [
                            ("Transfer up to 50% of the funds if the deadline is under 1 hour.", False),
                            ("Execute dual-authorization and verify the account number via a pre-established voice phone number.", True),
                            ("Reply to the email asking the sender to confirm the bank name.", False),
                            ("Approve the payment if the vendor's invoice looks professionally designed.", False)
                        ]
                    },
                    {
                        "text": "Why do executive impersonators often claim they are 'in a board meeting and cannot take phone calls'?",
                        "explanation": "Preempting voice verification forces the victim to rely solely on the attacker's email communications.",
                        "options": [
                            ("To comply with corporate conference room quiet policies.", False),
                            ("To preemptively prevent the victim from calling them to verify the request.", True),
                            ("Because email is legally required for financial authorizations.", False),
                            ("To show that the executive is busy and productive.", False)
                        ]
                    }
                ]
            },
            {
                "title": "Spotting Typosquatting & Malicious Hyperlinks",
                "description": "Learn how lookalike domains, disguised links, and URL shorteners are weaponized to harvest credentials.",
                "category": "Technical Defense",
                "difficulty": "Intermediate",
                "estimated_minutes": 12,
                "content": (
                    "### Analyzing Links & Domains\n\n"
                    "Attackers register lookalike domains with subtle typos (e.g. micr0soft.com) or deceptive subdomains "
                    "(e.g. login.microsoft.com.attacker.xyz). Always inspect the root domain before entering credentials."
                ),
                "questions": [
                    {
                        "text": "What is typosquatting?",
                        "explanation": "Typosquatting exploits human visual oversight by using lookalike characters (e.g. 0 for o, rn for m) in domain names.",
                        "options": [
                            ("Typing too fast and causing spelling mistakes in internal corporate memos.", False),
                            ("Registering lookalike domain names with subtle character swaps to deceive users into trusting a fake site.", True),
                            ("Compressing email attachments into zip archives.", False),
                            ("Using keyboard shortcuts to navigate web pages.", False)
                        ]
                    },
                    {
                        "text": "In the link 'http://login.microsoft.com.attacker-controlled.xyz/auth', what is the actual destination domain?",
                        "explanation": "The destination domain is determined by the portion immediately preceding the top-level domain and first slash (attacker-controlled.xyz).",
                        "options": [
                            ("microsoft.com", False),
                            ("login.microsoft.com", False),
                            ("attacker-controlled.xyz", True),
                            ("auth", False)
                        ]
                    },
                    {
                        "text": "What danger does a URL shortener (e.g., bit.ly, tinyurl.com) present in an email?",
                        "explanation": "Shortened links obscure the final destination address, hiding malicious or typosquatted landing pages from visual inspection.",
                        "options": [
                            ("It causes the email to exceed attachment file size limits.", False),
                            ("It conceals the true destination URL, preventing the user from inspecting the real target domain before clicking.", True),
                            ("It automatically decrypts private corporate databases.", False),
                            ("It turns off HTTPS encryption on the recipient's computer.", False)
                        ]
                    },
                    {
                        "text": "When an email display text reads 'https://mybank.com' but hovering reveals 'http://phish-secure.top', what has occurred?",
                        "explanation": "Anchor text spoofing displays legitimate text while directing the browser's hyperlink to an attacker-controlled server.",
                        "options": [
                            ("The web browser has automatically upgraded the connection to a backup server.", False),
                            ("The sender has used anchor text spoofing to disguise a malicious destination address.", True),
                            ("A standard DNS load balancing switch has occurred.", False),
                            ("The bank has updated its corporate top-level domain.", False)
                        ]
                    },
                    {
                        "text": "Which Top-Level Domain (TLD) is recognized as corporate internal and trusted within our system?",
                        "explanation": "corporate.local is the designated internal corporate domain recognized on our trusted whitelist with zero penalty score.",
                        "options": [
                            (".xyz", False),
                            (".top", False),
                            ("corporate.local", True),
                            (".cf", False)
                        ]
                    }
                ]
            }
        ]

        for m_data in modules_data:
            questions_data = m_data.pop("questions", [])
            mod = TrainingModule.query.filter_by(title=m_data["title"]).first()
            if not mod:
                mod = TrainingModule(**m_data)
                db.session.add(mod)
                db.session.flush()

            # Seed 5 questions per module
            for q_idx, q_data in enumerate(questions_data, 1):
                existing_q = QuizQuestion.query.filter_by(
                    module_id=mod.id,
                    question_text=q_data["text"]
                ).first()

                if not existing_q:
                    question = QuizQuestion(
                        module_id=mod.id,
                        question_text=q_data["text"],
                        explanation=q_data["explanation"]
                    )
                    db.session.add(question)
                    db.session.flush()

                    for opt_text, is_corr in q_data["options"]:
                        opt = QuizOption(
                            question_id=question.id,
                            option_text=opt_text,
                            is_correct=is_corr
                        )
                        db.session.add(opt)

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
