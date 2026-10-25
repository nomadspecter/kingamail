# System Architecture & Phase Implementation Notes
**System Name:** PhishShield (Configurable via `SYSTEM_NAME` in `config.py`)  
**Stack:** Python Flask, SQLAlchemy ORM, Supabase Cloud PostgreSQL, Jinja2, Bootstrap 5.  
**Philosophy:** 100% Rule-based heuristic email threat detection (zero machine learning), parameterized SQL queries only, CSRF protection on state-changing requests, RBAC enforcement on all routes, secure session handling.

---

## Phase 1: Foundation, Database Architecture & Offline Detection
### 1. What Was Added
- Application Factory pattern with modular Flask Blueprints.
- 14 database entity models in `models.py` acting as the single source of truth.
- Alembic database migration pipeline with Flask-Migrate targeting Supabase Cloud PostgreSQL.
- Initial enterprise seed script populating departments, roles, demo users, sample emails, and training modules.
- Refactored threat detection engine (`detection/parser.py`, `detection/rules.py`, `detection/scoring.py`) with 12 heuristic rules.
- Local offline blocklist (`check_blocklist`) using `KNOWN_BAD_DOMAINS` and the database `blocked_sender` table.
- Optional external threat intelligence toggle (`ENABLE_VIRUSTOTAL=False` by default).

### 2. Files Involved
- `config.py`: Environment configuration, URL normalizer for Supabase pooler, connection limits, and offline domain lists.
- `database.py`: SQLAlchemy and Flask-Migrate extension instantiation.
- `models.py`: 14 ORM models (`Department`, `Role`, `User`, `LoginLog`, `Email`, `BlockedSender`, `Incident`, `Report`, `Campaign`, `SimResult`, `QuizResult`, `Alert`, `AlertRecipient`, `TrainingModule`).
- `migrations/`: Alembic migration scripts.
- `detection/parser.py`: RFC-822 email parser, domain extractor, and homoglyph normalizer.
- `detection/rules.py`: 12 heuristic rule functions.
- `detection/scoring.py`: Verdict calculation (Safe, Suspicious, Malicious Phishing).
- `seed.py`: Enterprise demo data populator.

### 3. How It Works (Student Explanation)
When an email enters the system, `parser.py` breaks it down into sender, subject, plain-text body, HTML, attachments, and URLs. Rather than using unpredictable machine learning, `scoring.py` passes the parsed components through 12 deterministic rules in `rules.py`. Each triggered rule adds penalty points. If the total score is 0–29 points, the email is classified as **Safe**; 30–59 points is **Suspicious**; and 60+ points is **Malicious Phishing**. When `ENABLE_VIRUSTOTAL` is False, no external HTTP requests are made, ensuring complete data privacy and offline resilience.

---

## Phase 2: Authentication, 2FA OTP, Sessions & RBAC
### 1. What Was Added
- Secure credential authentication using PBKDF2/SHA256 password hashing.
- Two-Factor Authentication (2FA) via a 6-digit One-Time Passcode (OTP).
  - Stored securely hashed in the database (`user.otp_code` as VARCHAR(255)) with a strict 5-minute expiry (`user.otp_expiry`).
  - `DEMO_MODE=True` prints OTPs to the console and renders an informational callout on screen for live grading/testing.
- Account lockout policy: Automatically locks the account after 5 consecutive failed login attempts (`failed_login_count >= 5` -> `status='locked'`).
- Inactivity session timeout: Re-authenticates users if idle for more than 15 minutes (`900` seconds).
- Audit logging: Every login attempt (successful, failed, or locked) is recorded in the `login_log` table with timestamp, IP, and failure reason.
- Role-Based Access Control (RBAC):
  - `@login_required`: Restricts routes to authenticated, non-locked users.
  - `@role_required(*allowed_roles)`: Enforces permission boundaries across `Employee`, `IT Admin`, and `Manager`.
- Compromised account confinement: Victims of confirmed attacks (`status='compromised'`, `force_password_reset=True`) are restricted to the password reset view until remediation is completed.
- Dynamic navigation bar in `base.html` displaying current user, role badge, quick switcher, and security status.

### 2. Files Involved
- `config.py`: Added `DEMO_MODE`, `TRUSTED_DOMAINS` (including `corporate.local`), and secure cookie parameters.
- `models.py`: Updated `User` model with `set_otp()`, `check_otp()`, and `clear_otp()`.
- `migrations/versions/60b452761b66_alter_otp_code_column_to_varchar_255_.py`: Alembic migration expanding `otp_code` to `VARCHAR(255)`.
- `routes/auth.py`: Authentication controllers, RBAC decorators, session helpers, and audit logging.
- `app.py`: Integrated 15-minute session timeout and CSRF validation in `before_request`.
- `templates/login.html`: Branded sign-in screen using `SYSTEM_NAME`.
- `templates/verify_otp.html`: 2FA passcode submission screen with demo code helper.
- `templates/reset_password.html`: Mandatory password reset interface for compromised accounts.
- `templates/errors/403.html`: Styled HTTP 403 Forbidden access denial page.
- `templates/base.html`: Dynamic header with user identity badge and role navigation.
- `test_phase2.py`: Automated test suite validating against Supabase PostgreSQL.

### 3. How It Works (Student Explanation)
Authentication occurs in two distinct stages. In Stage 1, the user enters their email and password. The system retrieves the user record via a parameterized query and verifies the password hash using `werkzeug.security.check_password_hash`. If the password is wrong, `failed_login_count` increments; upon reaching 5, the account status changes to `locked` and further attempts are blocked. 

If Stage 1 succeeds, Stage 2 generates a cryptographically random 6-digit OTP. The system hashes this OTP and stores it alongside a timestamp set to `now + 5 minutes`. The user is redirected to `/auth/verify-otp`. When the user enters the code, `check_otp()` checks both that `datetime.utcnow() < otp_expiry` and that the hash matches. Upon verification, the OTP is cleared from the database, a secure session is minted, and the user's role is inspected by `@role_required` to permit access to authorized areas.

---

## Phase 3: Threat Detection, Mailbox & Security Inspection UI
### 1. What Was Added
- Complete Corporate Mailbox interface (`/emails/inbox`) displaying real-time risk scores, verdict badges, read/unread states, and search filtering.
- Strict Mailbox authorization: Parameterized queries ensure users can only view their own emails; attempts to access emails belonging to other users return HTTP 403 Forbidden.
- Email Threat Detail Inspection View (`/emails/view/<email_id>`):
  - Risk score gauge (0-100) and confidence rating.
  - Detailed heuristic breakdown table showing all triggered indicators, penalty points, and detection messages.
  - Sanitized body viewer with disarmed links to prevent accidental compromise.
  - One-click "Report as Phishing" button.
- Quarantine Module (`/emails/quarantine`):
  - Isolates malicious messages (score > 70) from employee inboxes.
  - Role-aware visibility: Employees view personal quarantined emails; IT Admins inspect enterprise-wide quarantined items with "Release to Inbox" and "Delete" capabilities.
- On-Demand Threat Scanner (`/emails/analyze`):
  - Interactive analyzer accepting raw email text or discrete sender/subject/body fields.
  - Interactive demo presets ("Clean Staff Memo", "Typosquatted IT Alert", "DHL Scam Link").
  - Evaluates against all 12 heuristic rules and the database `blocked_sender` table in a 100% offline, self-contained pipeline.
- Whitelist protection: Verified internal `corporate.local` domain is recognized in `check_trusted_domain` and never receives penalty points.

### 2. Files Involved
- `routes/emails.py`: Mailbox, threat inspection, quarantine, and on-demand scanner controllers.
- `routes/reports.py`: Added `submit_report` endpoint to allow reporting emails from the mailbox.
- `detection/rules.py`: Enhanced `check_typosquatting` with brand detection and `check_blocklist` with automatic config fallback.
- `templates/inbox.html`: Mailbox table with risk meters and quick reporting.
- `templates/quarantine.html`: Isolated threat viewer with release and delete actions.
- `templates/email_detail.html`: Threat inspection layout with indicator cards and disarmed preview.
- `templates/analyze.html`: Interactive on-demand scanner with preset demo scenarios.
- `test_phase3.py`: Automated integration test suite validating offline detection and mailbox security against Supabase PostgreSQL.

### 3. How It Works (Student Explanation)
Emails in the system are evaluated through the 12 heuristic checks in `detection/rules.py`. An email with an internal sender ending in `@corporate.local` passes `check_trusted_domain` with 0 points. If an email comes from an untrusted or lookalike domain (such as `micr0soft-support.xyz`), it accumulates points for typosquatting (+40), local blocklist matching (+60), and psychological urgency (+30). If the accumulated score exceeds 70, its status is set to `quarantined`, automatically shielding the employee's inbox. 

In the web interface, the employee can safely inspect the email in the threat viewer, where dangerous links are rendered in sanitized text rather than executable hyperlinks. IT Administrators have elevated privileges: they can review all quarantined threats across the company and, if a message is deemed a false positive, release it back to the recipient's inbox.

---

## Phase 4: Incident Response, SOC Triage & Threat Containment
### 1. What Was Added
- Employee Phishing Reporting: One-click submission from the mailbox creates a `Report` record (`admin_verdict='pending'`) and flags `email.is_reported = True`.
- SOC Triage Queue (`/reports/`):
  - Protected with `@role_required('IT Admin')`.
  - Filterable triage view with status metric cards (Pending, Confirmed Phishing, Safe, Spam).
  - Modal-based triage workflows allowing analysts to confirm attacks or dismiss false alarms.
- Automated Enterprise Containment Workflow:
  - If triaged as 'phishing':
    1. Opens a formal Incident record (`INC-YYYY-XXXX`).
    2. Blacklists the attacker address/domain in the `blocked_sender` database table.
    3. Flags the victim employee account as `status='compromised'` and enforces `force_password_reset=True`.
    4. Generates an immutable chronological audit trail in `incident.actions_log`.
    5. Dispatches an enterprise `Alert` with `AlertRecipient` delivery records across all active employee mailboxes.
  - If triaged as 'safe' or 'spam': Resolves the report directly without creating an incident.
- Security Incidents Docket (`/incidents/` & `/incidents/view/<incident_id>`):
  - Displays complete investigation records, affected account profiles, attacker indicators, and chronological action audit logs.
  - Incident closing controller (`POST /incidents/close/<id>`) marking status as `resolved`, logging close timestamp and analyst post-mortem notes.
- Security Advisories Portal (`/alerts/`):
  - Workforce notification interface with unacknowledged warning counters.
  - Interactive acknowledgment workflow (`POST /alerts/acknowledge/<id>`) recording read timestamps in `alert_recipient`.
  - SOC manual emergency broadcast dispatch interface.

### 2. Files Involved
- `routes/reports.py`: Phishing submission and SOC triage controller.
- `routes/incidents.py`: Incident registry, investigation docket, and closure controllers.
- `routes/alerts.py`: Advisory broadcast and employee acknowledgment controllers.
- `templates/reports_list.html`: SOC triage queue interface with confirmation modals.
- `templates/incidents_list.html`: Enterprise security incidents dashboard.
- `templates/incident_detail.html`: Incident investigation docket with chronological audit logs.
- `templates/alerts_list.html`: Employee security advisory viewer with acknowledgment and admin broadcast forms.
- `test_phase4.py`: Integration test suite validating incident response, containment, and alert delivery against Supabase PostgreSQL.

### 3. How It Works (Student Explanation)
When an employee notices a suspicious email and clicks "Report as Phishing", the message is queued in the SOC Triage portal. An IT Administrator reviews the email headers and body. If the administrator confirms it is genuine phishing, clicking "Confirm Phishing" executes an automated containment chain:
1. An official incident number (e.g. `INC-2026-0001`) is generated.
2. The attacker's sender address is added to the `blocked_sender` database table so future incoming emails from that attacker are automatically quarantined.
3. The victim user account is immediately contained: their status is changed to `compromised` and `force_password_reset` is locked to True. As a result, the next time that user accesses the system, `login_required` confines them to the password reset page until new credentials are established.
4. An emergency security advisory is created and delivered to every employee's alerts feed, warning the workforce about the active campaign.
5. Every single one of these actions is logged with an immutable timestamp and analyst name in `actions_log`. Once containment is verified, the analyst enters resolution notes to close the incident docket.

---

## Phase 5: Phishing Awareness, Simulation Engine & Interactive Quizzes
### 1. What Was Added
- Database Schema Expansion via Flask-Migrate:
  - Created `quiz_question` table (with `module_id`, `question_text`, `explanation`).
  - Created `quiz_option` table (with `question_id`, `option_text`, `is_correct`).
  - Seeded 5 comprehensive questions and 20 option choices per module (15 questions total across 3 training modules).
- Phishing Simulation Engine (`/simulation/campaigns` & `/simulation/create`):
  - IT Admin campaign builder with targeted audience selection (company-wide or specific users).
  - Automatically mints cryptographically secure tracking tokens (`secrets.token_urlsafe(32)`) per participant.
  - Generates `SimResult` records and delivers simulated test emails directly into participant inboxes containing the tracking link.
- Tracked Link Click Engagement Handler (`/simulation/track/<token>`):
  - Records click timestamp in `sim_result.clicked_at` and sets `sim_result.is_clicked = True`.
  - Renders educational awareness landing page (`simulation_landing.html`) detailing the email red flags.
  - Strict Privacy Guard: Records clicks ONLY. Contains zero login fields, zero password boxes, and never captures or stores user input.
- Simulation Reporting Hook:
  - When an employee clicks "Report Phishing" on a simulated message, the system matches the tracking token, marks `sim_result.is_reported = True`, records `reported_at`, and flashes a commendation message.
- Interactive Training & Quiz Engine (`/training/` & `/training/module/<id>`):
  - Course catalog displaying lesson duration, difficulty, and user's completion status.
  - Dynamic question loading directly from the `quiz_question` and `quiz_option` tables.
  - Real-time quiz scoring controller (`POST /training/quiz/<id>`): Evaluates submitted answers against `is_correct`, computes percentage score, checks passing threshold (>= 70%), records performance in `quiz_result`, and provides immediate educational rationale for each question.

### 2. Files Involved
- `models.py`: Added `QuizQuestion` and `QuizOption` models and linked `TrainingModule.questions`.
- `migrations/versions/bfaa1479c244_add_quiz_question_and_quiz_option_tables.py`: Migration creating quiz tables on Supabase.
- `seed.py`: Updated to seed 5 quiz questions & 4 options per question for all training modules.
- `routes/simulation.py`: Campaign launching and click tracking controllers.
- `routes/training.py`: Training module catalog, lesson viewer, and dynamic quiz scoring controllers.
- `routes/reports.py`: Integrated simulation reporting hook to update `sim_result.is_reported`.
- `templates/campaigns_list.html`: Simulation management dashboard with launch modal and progress metrics.
- `templates/simulation_landing.html`: Credential-free educational landing page explaining red flags.
- `templates/training_modules.html`: Training course catalog with progress tracking.
- `templates/training_detail.html`: Lesson reader with dynamic 5-question multiple choice assessment.
- `templates/quiz_result.html`: Score feedback page with cybersecurity rationale for each question.
- `test_phase5.py`: Integration test suite validating quiz tables, simulation delivery, click tracking, and quiz grading against Supabase PostgreSQL.

### 3. How It Works (Student Explanation)
To proactively train employees before real cyberattacks strike, IT Administrators configure simulated phishing campaigns. The system generates a distinct tracking token for each employee and injects a simulated email into their inbox. If an employee is deceived by the email's urgency and clicks the link, the tracking endpoint records that the link was clicked, but crucially, never asks for or stores any credentials. Instead, it immediately displays an educational page explaining the subtle warning signs present in the email. 

If the employee instead spots the attack and reports it, the reporting controller detects the simulation token and credits the employee with a successful detection. Finally, employees solidify their learning through the interactive training courses, where 5 multiple-choice questions per topic are retrieved from PostgreSQL, graded on submission, and recorded in `quiz_result` to demonstrate compliance.

---
