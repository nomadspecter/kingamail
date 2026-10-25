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
