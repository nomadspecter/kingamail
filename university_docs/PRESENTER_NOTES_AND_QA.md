# KingaMail Corporate Shield — Oral Defense Presenter Script & Q&A Guide

Use this guide alongside `/home/nomad/kingamail/university_docs/KingaMail_End_Of_Semester_Presentation.pptx` (or `.pdf`) during your **10–12 minute** Zetech University End-of-Semester Final Year Project defense.

---

## Pre-Defense Checklist (Run 30 Minutes Before Presentation)

> **CRITICAL NOTICE (Verified 14 Nov 2026):** During final pre-packaging checks, the configured Supabase cloud pooler host (`aws-0-eu-west-1.pooler.supabase.com:6543`) returned `FATAL: (ENOTFOUND) tenant/user postgres.kdalwgxcksveyjuteqem not found` (paused or deleted project). **Reactivate or point `.env` to a live PostgreSQL / Supabase database BEFORE entering the defense room!**

Run these exact commands in `/home/nomad/kingamail` with the virtual environment active (`.sitonik/bin/python` or `venv/bin/python`):

```bash
# 1. Verify database migrations are at head (all 16 tables across 3 revisions)
flask db upgrade

# 2. Seed roles, departments, demo accounts, emails, training modules & 15 quiz questions
python seed.py

# 3. Verify health and unit checks
python test_original_suite.py

# 4. Start the local server (listen on port 5000)
flask run
```

Have 3 browser tabs/windows ready or incognito profiles for smooth role switching:
* **Employee:** `employee@corporate.local` / `Employee123!` *(5 seeded messages ready)*
* **IT Admin:** `admin@corporate.local` / `Admin123!` *(SOC Console, Triage Queue, Campaigns)*
* **Manager:** `manager@corporate.local` / `Manager123!` *(OPS Department Team Risk Dashboard)*
* **Compromised Demo:** `bob.miller@corporate.local` / `Employee123!` *(Shows mandatory forced password reset)*

*(Keep `DEMO_MODE=True` in `.env` so 6-digit OTPs show cleanly on the verification screen and Flask terminal.)*

---

## Slide-by-Slide Speaker Notes (Target: ~10 Minutes + Live Demo)

* **Slide 1 (Title — 30 sec):** Good morning/afternoon panel members. I am presenting **KingaMail Corporate Shield**, an original, rule-based enterprise email threat detection, closed-loop incident triage, and phishing awareness training platform designed specifically for Kenyan organizations.
* **Slide 2 (Problem — 45 sec):** Generic international email filters struggle with Kenyan social engineering tactics—fake M-Pesa float reversals, KRA iTax PIN penalties, eCitizen/SHIF payroll updates, and fake fellowship offers—while commercial enterprise tools cost USD 4–12 per mailbox monthly. KingaMail closes both the contextual detection gap and the containment gap at zero software licensing cost.
* **Slide 3 (Objectives — 45 sec):** Walk briefly through all five objectives: Role-Based 2FA authentication, 12 offline Kenyan heuristic rules, automated 5-step SOC containment, zero-credential phishing simulations with 15 DB-graded quiz questions, and Chart.js + CSV compliance reporting.
* **Slide 4 (Methodology — 30 sec):** Built iteratively across Milestones 1–5 matching the university progress logbook—moving cleanly from Alembic schema design to detection, triage, awareness, and executive dashboards.
* **Slide 5 (Architecture — 45 sec):** Built on Python 3.14 and Flask 3.1.3 across 8 modular Blueprints and a stateless `detection/` tier connected via SQLAlchemy 2.1.6 and Alembic migrations to PostgreSQL. Notice `config.py` has no SQLite fallback—it fails fast if `DATABASE_URL` is absent.
* **Slide 6 (16-Table DB — 45 sec):** Highlight the 4 schema clusters across 3 Alembic revisions: Identity/Audit (`users`, `login_logs`), Mail/Detection (`emails`, `blocked_senders`), Incident Response (`reports`, `incidents`, `alerts`, `alert_recipients`), and Awareness (`campaigns`, `sim_results`, `training_modules`, `quiz_questions`, `quiz_options`, `quiz_results`).
* **Slide 7 (Auth & Security — 45 sec):** Explain salted password hashing, 5-attempt lockout, 6-digit hashed OTP (`5-minute` expiry), `15-minute` idle auto-logout (`last_active`), and `secrets.compare_digest` CSRF tokens.
* **Slide 8 (12 Kenyan Rules — 60 sec):** Explain how Unicode normalization defeats lookalike spoofs (`safar1com`, `micr0soft`), how `.go.ke` and `corporate.local` prevent false positives on legitimate staff/government mail, and how cumulative uncapped scoring assigns Safe (`0–24`), Suspicious (`25–54`), or Quarantine (`55+`). Emphasize zero external VirusTotal API dependency (`ENABLE_VIRUSTOTAL=False`).
* **Slide 9 (Mailbox & Quarantine — 30 sec):** Point out clean risk separation: safe internal emails reach the inbox (`Score 0`), borderline lures get a caution banner (`Score 50`), and high-risk KRA (`200`) / M-Pesa (`170`) lures isolate into Quarantine.
* **Slide 10 (5-Step Containment — 60 sec):** This is our closed-loop responder. When an employee reports a phish and IT Admin clicks Confirm, KingaMail atomically creates `INC-YYYY-XXXX`, flags the victim as `compromised` forcing password reset, blocks the sender domain (`blocked_senders`), quarantines the message, and broadcasts a mandatory org-wide advisory.
* **Slide 11 (Simulations & Quizzes — 45 sec):** Highlight the ethical privacy guarantee: clicking `/simulation/track/<token>` logs click telemetry only—our landing template has zero HTML forms or password inputs. Follow up with 3 modules × 5 DB questions requiring `>=70%`.
* **Slide 12 (Dashboards & CSV — 30 sec):** Contrast IT Admin SOC visibility with Manager department-scoped views and the 12-column audit CSV.
* **Slide 13 (Testing & Cost — 45 sec):** Be transparently honest: offline rule tests and template privacy tests pass directly (`Clean=0`, `Training=50`, `KRA=300`), note static vs DB-driven chart series transparently, and highlight KSh 0 licensing savings.
* **Slide 14 (Demo & Future Work — 30 sec):** Summarize Phase 2 roadmap (Postfix SMTP Milter hook, SQL rule counters, SMS OTP) and transition straight into the live browser walkthrough.

---

## Anticipated Examiner Q&A

**Q1: Why choose a deterministic rule-based engine instead of Machine Learning (ML)?**
> **Answer:** In an enterprise SOC, explainability matters. ML models often act as black boxes requiring thousands of labelled Kenyan emails before generalizing well. Our 12 heuristic rules produce an exact per-rule score and plain-English explanation (e.g., *+45 Mismatched Display Name Spoofing*, *+40 Kenyan Telecom Fraud*), require zero GPU/cloud training cost, and let SOC admins add newly blocked domains instantaneously via `blocked_senders`.

**Q2: Why is your risk score uncapped rather than capped at 100?**
> **Answer:** Each rule evaluates an orthogonal risk dimension (`detection/scoring.py`: `total_score = sum(c["score"] for c in checks)`). Leaving scores uncapped preserves severity separation among quarantined attacks—for example, distinguishing a borderline Suspicious fellowship email (`50`) from a multi-vector KRA iTax credential spoof (`200–300`) so triage analysts prioritize critical incidents first.

**Q3: How do you guarantee simulation landing pages never leak employee credentials?**
> **Answer:** By architectural constraint in `templates/simulation_landing.html` and `routes/simulation.py`. The tracking endpoint (`/simulation/track/<token>`) accepts only a `GET` click event, updates `sim_results.is_clicked=True`, and renders a static debrief card with **no `<form>` tags and no `<input type="password">` elements**. Even if an employee wanted to type a password, no input box exists.

**Q4: How do you justify displaying the 2FA OTP on screen (`DEMO_MODE=True`)?**
> **Answer:** Under `DEMO_MODE=False` in production, OTPs would dispatch over an enterprise SMTP or SMS gateway; in both modes, `users.otp_code` stores only a one-way cryptographic hash with a 5-minute `otp_expires_at` timestamp, never plaintext. `DEMO_MODE=True` allows classroom and examiner demonstration of the complete 2FA verification lifecycle without paid SMS credits.

**Q5: What stops a compromised user from simply clicking around the application after being flagged?**
> **Answer:** Every request passes through `app.before_request` in `app.py`. When `user.force_password_reset` or `user.is_compromised()` is true, access to `/emails/*`, `/reports/*`, `/training/*`, and dashboards is blocked and redirected strictly to `/auth/reset-password` until a compliant 8+ character password is saved.

**Q6: How does KingaMail prevent false positives on legitimate government (.go.ke) or internal corporate emails?**
> **Answer:** Two explicit checks handle this: `RULE-02-TRUSTED-ORIGIN` checks `config.TRUSTED_DOMAINS` (which includes `corporate.local`) awarding `0` risk points, and `RULE-05-KENYA-GOV-COMPLIANCE` explicitly inspects sender domains for `.go.ke` and `.mil.ke` suffixes before penalizing KRA/eCitizen/HELB/NTSA keywords.

**Q7: Notice `test_original_suite.py` failed on DB routes during offline verification — why?**
> **Answer:** The test harness runs against `DATABASE_URL` in `.env` cleanly with no SQLite fallback (`config.py` intentionally stops fast if PostgreSQL is unreachable). When our hosted Supabase project pauses or changes pooler tenant status, live HTTP route tests fail cleanly at connection time rather than silently falling back to an unmigrated local file; unpausing/updating Supabase and seeding restores live route execution immediately.
