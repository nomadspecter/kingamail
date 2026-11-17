# ZETECH UNIVERSITY — FINAL YEAR PROJECT DOCUMENTATION

## KingaMail Corporate Shield: Rule-Based Email Threat Detection, Incident Triage & Phishing Awareness System for Kenyan Enterprises

---

### STUDENT & INSTITUTION METADATA *(Complete Before Binding)*

| Field | Details |
|---|---|
| **University** | Zetech University |
| **School / Department** | School of ICT, Media & Engineering — Department of Information Technology & Computer Science |
| **Project Title** | KingaMail Corporate Shield: Enterprise Email Security & Phishing Awareness Platform |
| **Student Name** | `[STUDENT FULL NAME]` |
| **Registration Number** | `[REGISTRATION NUMBER]` |
| **Programme / Year & Semester** | `[BSc. Information Technology / BSc. Computer Science — Year X, Semester Y]` |
| **Academic Supervisor** | `[SUPERVISOR NAME]` |
| **Submission Date** | November 2026 |
| **Code Repository Workspace** | `/home/nomad/kingamail` |

---

### DECLARATION

I hereby declare that this Final Year Project documentation and the accompanying software system titled **KingaMail Corporate Shield** are my original work submitted in partial fulfillment of the requirements for the award of an undergraduate degree at **Zetech University**. All detection rules in `detection/rules.py`, scoring thresholds in `detection/scoring.py`, user interface stylesheets (`static/css/style.css`), templates, and Kenyan-themed simulation templates were authored specifically for this system, and all external open-source frameworks are duly acknowledged.

* **Student Signature:** `___________________________` &nbsp;&nbsp; **Date:** `________________`
* **Supervisor Signature:** `___________________________` &nbsp;&nbsp; **Date:** `________________`

---

### ABSTRACT

Email phishing and social engineering remain the primary initial access vectors compromising Kenyan corporate, financial, government, and SME networks. Attackers routinely impersonate local trusted institutions — including Safaricom M-Pesa, the Kenya Revenue Authority (KRA iTax), eCitizen, HELB, SHIF/NHIF, SACCOs, and commercial banks — while exploiting urgent procurement tender lures and fake fully-funded fellowship invitations. Commercial Secure Email Gateways (SEGs) carry prohibitive per-seat USD licensing costs and frequently miss Kiswahili/Kenyan contextual lures, while disconnected training platforms fail to link simulated click behavior with active SOC containment.

This project designs and implements **KingaMail Corporate Shield**, a self-contained, zero-cost, full-stack Flask web platform built on **Python 3.14**, **Flask 3.1.3**, **Flask-Migrate (Alembic 1.20.1)**, **Chart.js 4.4.1**, and a **16-table PostgreSQL** schema hosted via Supabase Session/Transaction Pooling. The system delivers four integrated pillars: (1) defense-in-depth authentication combining Werkzeug scrypt/PBKDF2 password hashing, 5-attempt brute-force lockout, 6-digit hashed Two-Factor OTP (`5-minute` expiry), CSRF tokens (`secrets.token_hex`), `15-minute` inactivity auto-logout, and 3-tier Role-Based Access Control (Employee, Manager, IT Admin); (2) a fully offline, deterministic **12-rule Kenyan heuristic inspection engine** (`RULE-01-BLOCKLIST` through `RULE-12-SUSPICIOUS-HYPERLINK`) using cumulative uncapped scoring thresholds (`0–24 Safe`, `25–54 Suspicious`, `55+ Quarantine`) with external Threat Intelligence disabled by default (`ENABLE_VIRUSTOTAL=False`); (3) an end-to-end **5-step SOC incident containment workflow** generating `INC-YYYY-XXXX` references, automatically locking compromised victim accounts (`force_password_reset=True`), blocking attacker origins in `blocked_senders`, and dispatching mandatory advisories; and (4) an ethical **zero-credential-capture phishing simulation & DB-backed awareness quiz module** (`3` modules × `5` questions = `15` questions) paired with Chart.js executive analytics and a `12-column` CSV audit export.

---

### MASTER SCREENSHOT CAPTURE CHECKLIST (MILESTONES 1 – 6)

All screenshot frames throughout Chapters 4 and Milestone Sections are intentionally left blank with bordered markers indicating the exact capture required prior to print binding.

| Screenshot ID | Milestone | Screen / Artifact Title | Exact URL / Command | Required Role |
|---|---|---|---|---|
| `M1.1` | Milestone 1: Proposal, Environment & Initial Setup | Project Directory Structure & Environment Configuration | `tree -L 2 -I '__pycache__|*.pyc|.git|venv|.venv|.sitonik' && flask --version` | Developer Terminal (No Login) |
| `M1.2` | Milestone 1: Proposal, Environment & Initial Setup | Public Platform Overview & Architecture Landing Page | `http://127.0.0.1:5000/` | Unauthenticated Visitor |
| `M2.1` | Milestone 2: Design, Schema & Access Control | PostgreSQL / Alembic Migration History (16 Tables across 3 Revisions) | `flask db history && flask db current` | Developer Terminal |
| `M2.2` | Milestone 2: Design, Schema & Access Control | Employee Sign-In Screen & 5-Attempt Lockout Guard | `http://127.0.0.1:5000/auth/login` | Unauthenticated User |
| `M2.3` | Milestone 2: Design, Schema & Access Control | Two-Factor Authentication (6-Digit OTP Verification with DEMO_MODE Banner) | `http://127.0.0.1:5000/auth/verify-otp` | Authenticating User (e.g. employee@corporate.local / Employee123!) |
| `M2.4` | Milestone 2: Design, Schema & Access Control | Role-Based Navigation Comparison (Employee vs Manager vs IT Admin) | `Login as employee@corporate.local, manager@corporate.local, admin@corporate.local` | Side-by-Side or Sequential Logins |
| `M3.1` | Milestone 3: Core Implementation & Detection Engine | Employee Personal Inbox Showing Safe & Suspicious Messages | `http://127.0.0.1:5000/emails/inbox` | Employee (employee@corporate.local) |
| `M3.2` | Milestone 3: Core Implementation & Detection Engine | Quarantined Attacks Vault (KRA iTax & Safaricom M-Pesa Phishes) | `http://127.0.0.1:5000/emails/quarantine` | Employee or IT Admin |
| `M3.3` | Milestone 3: Core Implementation & Detection Engine | Live On-Demand Threat Scanner with 12-Rule Breakdown | `http://127.0.0.1:5000/emails/analyze` | Employee / Manager / IT Admin |
| `M3.4` | Milestone 3: Core Implementation & Detection Engine | Offline Heuristic Engine Unit Test Verification | `python test_original_suite.py (or offline detection.scoring check)` | Developer Terminal |
| `M4.1` | Milestone 4: Incident Response & SOC Triage | Email Detail View with 'Report Phishing' Action Button | `http://127.0.0.1:5000/emails/view/<email_id>` | Employee (employee@corporate.local) |
| `M4.2` | Milestone 4: Incident Response & SOC Triage | SOC Triage Queue & Automated 5-Step Containment Execution | `http://127.0.0.1:5000/reports/` | IT Admin (admin@corporate.local) |
| `M4.3` | Milestone 4: Incident Response & SOC Triage | Incident Docket Detail (INC-YYYY-XXXX), Victim Lock & Forced Reset | `http://127.0.0.1:5000/incidents/view/<incident_id>` | IT Admin (admin@corporate.local) |
| `M4.4` | Milestone 4: Incident Response & SOC Triage | Mandatory Password Reset Gate & Organization-Wide Security Advisory | `http://127.0.0.1:5000/auth/reset-password & http://127.0.0.1:5000/alerts/` | Compromised User (bob.miller@corporate.local / Employee123!) |
| `M5.1` | Milestone 5: Phishing Simulations, Training, Analytics & Export | Phishing Simulation Campaign Console with Kenyan Lure Presets | `http://127.0.0.1:5000/simulation/campaigns` | IT Admin (admin@corporate.local) |
| `M5.2` | Milestone 5: Phishing Simulations, Training, Analytics & Export | Zero-Credential-Capture Simulation Educational Landing Page | `http://127.0.0.1:5000/simulation/track/<token>` | Employee clicking tracked link |
| `M5.3` | Milestone 5: Phishing Simulations, Training, Analytics & Export | Interactive Security Awareness Quiz & Database-Graded Results | `http://127.0.0.1:5000/training/module/1 -> Submit Quiz` | Employee (employee@corporate.local) |
| `M5.4` | Milestone 5: Phishing Simulations, Training, Analytics & Export | IT Admin SOC Console with Chart.js Analytics | `http://127.0.0.1:5000/dashboard/admin` | IT Admin (admin@corporate.local) |
| `M5.5` | Milestone 5: Phishing Simulations, Training, Analytics & Export | Manager Department Risk Dashboard & High-Risk Staff Table | `http://127.0.0.1:5000/dashboard/manager` | Department Manager (manager@corporate.local) |
| `M5.6` | Milestone 5: Phishing Simulations, Training, Analytics & Export | Compliance Benchmarking Matrix & 12-Column Audit CSV Export | `http://127.0.0.1:5000/dashboard/reports & /dashboard/reports/export-csv` | IT Admin or Manager |
| `M5.7` | Milestone 5: Phishing Simulations, Training, Analytics & Export | Responsive Mobile Viewport Layout Check | `Chrome/Firefox DevTools Device Toolbar -> 390x844` | Any Authenticated User (Browser DevTools 390x844 Mobile View) |
| `M6.1` | Milestone 6: Final Integration & Defense Verification | Git Commit History Across Phases 1-6 & Health JSON Endpoint | `git log --oneline -n 10 && curl http://127.0.0.1:5000/health` | Developer Terminal / Browser |

---

### ZETECH UNIVERSITY PROJECT PROGRESS MONITORING LOGBOOK (MILESTONES 1 – 6)

This table aligns directly with the Zetech University **Project Progress Monitoring Logbook** (Pages 1–3).

| Milestone | Zetech Monitoring Scope | KingaMail Implemented Deliverables | Date | Student Sign | Supervisor Sign |
|---|---|---|---|---|---|
| **Milestone 1:** Proposal & Problem Definition | Problem statement, objectives, feasibility, methodology, system architecture, work plan | Proposal documented (Ch. 1–3); 3-tier Flask Blueprint architecture & `.env` / PostgreSQL pooler config completed; **`SCREENSHOTS M1.1 – M1.2`** | `____/____/2026` | `________` | `________` |
| **Milestone 2:** System Analysis & Design | Use cases, process flows, database design (ERD), architectural design, UI wireframes | 16 normalized SQLAlchemy models across 3 Alembic migrations; Auth/2FA OTP + 3-role RBAC + Deep African Navy / Safari Emerald responsive UI; **`SCREENSHOTS M2.1 – M2.4`** | `____/____/2026` | `________` | `________` |
| **Milestone 3:** Core System Development | Database setup, core functional modules, integration & Chapter 3/4 write-up | 12-rule offline Kenyan phishing detection engine (`rules.py` / `scoring.py`), Inbox, Quarantine vault, and Raw Threat Scanner (`/emails/analyze`); **`SCREENSHOTS M3.1 – M3.4`** | `____/____/2026` | `________` | `________` |
| **Milestone 4:** Advanced Modules & Testing | Secondary workflows, containment logic, security validation & testing | Employee reporting (`/reports/submit/<id>`), SOC Triage executing 5-step containment, `INC-YYYY-XXXX` dockets, forced password resets & advisories; **`SCREENSHOTS M4.1 – M4.4`** | `____/____/2026` | `________` | `________` |
| **Milestone 5:** Evaluation, Reporting & User Guide | Evaluation metrics, dashboards, exports, deployment guide & Chapters 5–6 | Zero-credential simulation campaigns, 15-question DB quiz engine, Chart.js SOC/Manager dashboards, 12-column CSV export, test audit & cost evaluation; **`SCREENSHOTS M5.1 – M5.7`** | `____/____/2026` | `________` | `________` |
| **Milestone 6:** Final Documentation & Defense | Final bound project report, logbook sign-off & oral end-of-semester presentation | Complete Final Report (`.md`/`.docx`/`.pdf`), 14-slide Defense Deck (`.pptx`/`.pdf`), Presenter Q&A & live walkthrough; **`SCREENSHOT M6.1`** | `____/____/2026` | `________` | `________` |

#### Official University Clearance Block *(Matches Logbook Page 3)*

| Authority Role | Full Name | Signature | Date |
|---|---|---|---|
| **Supervisor** | `______________________________` | `__________________` | `____/____/2026` |
| **Internal Project Coordinator 1** | `______________________________` | `__________________` | `____/____/2026` |
| **Internal Project Coordinator 2** | `______________________________` | `__________________` | `____/____/2026` |
| **Head of Department (HOD)** | `______________________________` | `__________________` | `____/____/2026` |

---

## CHAPTER 1: INTRODUCTION

### 1.1 Background of the Study
Small, Medium, and Large Enterprises across Kenya increasingly depend on cloud-hosted email for statutory filings, supplier invoicing, staff payroll alerts, and customer service. However, social engineering attacks specifically crafted around Kenyan digital infrastructure—such as Safaricom M-Pesa reversals, KRA iTax PIN compliance threats, eCitizen verification notices, HELB loan disbursements, NHIF/SHIF payroll updates, and fake NGO fellowships—exploit employee trust faster than conventional signature-based spam filters update.

### 1.2 Problem Statement
Existing email defense tools exhibit three critical gaps for Kenyan organizations:
1. **Context Blindness:** Generic foreign Secure Email Gateways rarely detect local lures mentioning *Paybill*, *Fuliza*, *CRB listing*, *IFMIS tender fees*, *iTax PIN*, or Kenyan SACCOs (`Mwalimu`, `Stima`).
2. **Siloed Response & Slow Containment:** Phishing detection, employee reporting, victim account lockdown, and awareness training typically live in disconnected products, leaving compromised mailboxes active long after an employee reports a threat.
3. **Prohibitive Licensing Costs & Privacy Risks:** Commercial enterprise platforms (typically USD 4–12 per user per month plus SOC retainers) are unaffordable for local SMEs and universities, and ethical compliance under Kenya's Data Protection Act (2019) requires awareness simulations that measure susceptibility **without** harvesting typed employee passwords.

### 1.3 Aim and Specific Objectives
The main aim of this project is to design, implement, and test **KingaMail Corporate Shield**, an integrated, locally tailored email threat detection, incident response, and phishing awareness web platform.

The specific objectives are:
1. **To implement hardened role-based authentication** supporting scrypt/PBKDF2 password hashing, 5-attempt lockout, 6-digit hashed OTP verification (`5-minute` TTL), CSRF guards, and `15-minute` inactivity auto-logout across three distinct roles (`IT Admin`, `Manager`, `Employee`).
2. **To build a self-contained Kenyan heuristic detection engine** comprising 12 deterministic rules (`RULE-01-BLOCKLIST` through `RULE-12-SUSPICIOUS-HYPERLINK`) and uncapped risk classification thresholds (`0–24 Safe`, `25–54 Suspicious`, `55+ Quarantine`) requiring zero paid external APIs.
3. **To automate closed-loop SOC incident triage** allowing employees to report suspicious messages while enabling IT Admins to generate `INC-YYYY-XXXX` dockets, isolate victim accounts via `force_password_reset=True`, add attacker domains to `blocked_senders`, and issue mandatory advisories.
4. **To develop a privacy-safe phishing awareness simulator and quiz system** tracking link clicks via cryptographic tokens (`secrets.token_urlsafe(32)`) on zero-form educational landing pages, coupled with `3` Kenyan corporate training modules and `15` DB-graded quiz questions (`>=70%` pass threshold).
5. **To deliver executive analytics and audit readiness** using Chart.js dashboards tailored by role and a `12-column` CSV compliance export.

### 1.4 Scope and Feasibility
* **In Scope:** Authenticated web mailbox workflow, raw RFC-email heuristic analysis, PostgreSQL persistence with Alembic migrations, 5-step incident triage, controlled internal simulation campaigns, interactive training quizzes, Chart.js reporting, and CSV export.
* **Out of Scope / Future Integration:** Live SMTP/IMAP MX mail-server proxying (Postfix/Milter), Active Directory SSO/SAML, and paid external VirusTotal lookups (strictly disabled by default via `ENABLE_VIRUSTOTAL=False`).
* **Economic & Technical Feasibility:** 100% open-source Python/PostgreSQL/Bootstrap stack (`KSh 0` software licensing cost), deployable locally or on free-tier cloud infrastructure.

---

## CHAPTER 2: LITERATURE REVIEW & COMPARATIVE ANALYSIS

Enterprise email security architectures fall broadly into three categories:
* **Rule-Based Gateways (e.g., SpamAssassin):** Deterministic header/body pattern matching that offers full explainability (`why` an email was flagged) but requires regional rule curation to avoid missing local lures.
* **Commercial Cloud SEGs & Simulation Suites (e.g., KnowBe4, Cofense, Proofpoint):** Rich threat feeds and simulations, yet priced per seat in USD, often storing sensitive campaign telemetry on third-party clouds, and lacking built-in M-Pesa/KRA/SHIF rule sets.
* **Pure Machine-Learning Classifiers:** Require large labelled Kenyan phishing corpora to train and often operate as opaque "black boxes" without clear rule attribution for SOC analysts.

### Comparative Feature Matrix

| Capability | Commercial Cloud SEGs | Standard Webmail Filters | **KingaMail Corporate Shield** |
|---|---|---|---|
| **Kenyan Context Rules (M-Pesa, KRA, SHIF, SACCO)** | Limited / Generic | Absent | **Native (12 Dedicated Heuristics)** |
| **Explainable Indicator Breakdown** | Partial | No (Binary Spam Folder) | **Yes (Per-rule point & reason trace)** |
| **External API Dependency** | Required (Cloud API) | Cloud-only | **Optional (`ENABLE_VIRUSTOTAL=False` default)** |
| **Integrated 5-Step Victim Containment** | Separate SOAR needed | No | **Built-in (`INC-YYYY-XXXX` + Forced Reset)** |
| **Zero-Credential Simulation Landing Page** | Varies by template | N/A | **Strict Policy (`<form>`-free by design)** |
| **Software Licensing Cost** | High (USD/user/month) | Bundled | **KSh 0 (Open-Source Stack)** |

---

## CHAPTER 3: METHODOLOGY, DATABASE DESIGN & ARCHITECTURE

### 3.1 Agile Milestone Methodology
Development followed an iterative six-phase engineering methodology aligned directly with the five core university project milestones plus final defense integration:
* **Phase 1 (Foundation — Milestone 1):** Application factory (`app.py`), fail-fast `config.py` requiring `DATABASE_URL`, Supabase pooler URL normalizer (`normalize_db_url`), Alembic migration setup, and deterministic seeding (`seed.py`).
* **Phase 2 (Authentication & RBAC — Milestone 2):** Blueprint `auth_bp`, `login_required`/`role_required` decorators, 5-attempt lockout, 6-digit hashed OTP (`5-min` expiry, `DEMO_MODE` console/UI reveal), `15-min` inactivity timeout (`session["last_active"] > 900`), and CSRF protection.
* **Phase 3 (Threat Detection Engine — Milestone 3):** Domain/Unicode parser (`detection/parser.py`), 12 original Kenyan rules (`detection/rules.py`), uncapped cumulative scoring (`detection/scoring.py`), mailbox/quarantine isolation, and live raw scanner (`/emails/analyze`).
* **Phase 4 (Incident Response — Milestone 4):** Employee phishing reporting (`/reports/submit/<id>`), SOC triage engine (`/reports/triage/<id>`), incident dossier management (`/incidents/`), forced victim password resets, and org-wide advisories (`/alerts/`).
* **Phase 5 (Phishing Awareness — Milestone 5):** Controlled simulations (`/simulation/`), zero-credential tracking links (`/simulation/track/<token>`), and 3 training modules with 15 DB-backed quiz questions/60 options (`/training/`).
* **Phase 6 (Executive Analytics & Defense — Milestone 5/6):** Role-scoped Chart.js dashboards (`/dashboard/admin`, `/dashboard/manager`, `/dashboard/reports`), 12-column CSV export (`/dashboard/reports/export-csv`), original responsive UI overhaul, and final documentation.

### 3.2 System Architecture & Technology Stack

```
+-----------------------------------------------------------------------------+
|                     PRESENTATION TIER (Browser / Mobile)                    |
|   Jinja2 Templates (21 Views) + Bootstrap 5.3.3 + Chart.js 4.4.1            |
|   Original Kenyan Enterprise Theme (Deep African Navy #0f172a, Emerald)     |
+--------------------------------------+--------------------------------------+
                                       | HTTPS / Session Cookie + CSRF Token
+--------------------------------------v--------------------------------------+
|                APPLICATION TIER (Flask 3.1.3 / Python 3.14)                 |
|   8 Blueprints: dashboard, auth, emails, reports, incidents,                |
|                 simulation, training, alerts                                |
|   Security Middleware: 15-min last_active timeout, force_password_reset,    |
|                        secrets.compare_digest CSRF validation               |
+-------------------+----------------------------------+----------------------+
                    |                                  |
+-------------------v--------------+   +---------------v----------------------+
|  THREAT DETECTION ENGINE         |   |  ORM & MIGRATION LAYER               |
|  - detection/parser.py (Unicode) |   |  SQLAlchemy 2.1.6                    |
|  - detection/rules.py (12 rules) |   |  Flask-Migrate 4.1.0 / Alembic       |
|  - detection/scoring.py (Uncapped|   |  (3 Schema Revisions -> 16 Tables)   |
|    Safe<=24 / Susp<=54 / Quar>=55|   +---------------+----------------------+
+----------------------------------+                   | psycopg2-binary
                                       +---------------v----------------------+
                                       |  DATA TIER (PostgreSQL / Supabase)   |
                                       |  Port 6543 Pooler / 5432 Migrations  |
                                       +--------------------------------------+
```

* **Runtime & Packages (`requirements.txt`):** Python `3.14`, `Flask>=3.1.0` (`3.1.3`), `Flask-SQLAlchemy>=3.1.0` (`3.1.1`), `Flask-Migrate>=4.1.0` (`4.1.0` / `alembic 1.20.1`), `SQLAlchemy>=2.0.0` (`2.1.6`), `psycopg2-binary>=2.9.9` (`2.9.13`), `python-dotenv>=1.0.0`, `requests>=2.31.0`, `Werkzeug>=3.0.0` (`3.1.9`).
* **UI Identity (`static/css/style.css`):** Typography `Plus Jakarta Sans`; Palette `--km-sidebar-bg: #0f172a` (Deep African Navy), `--km-sidebar-active: #059669` (Safari Emerald), `--km-primary: #0284c7` (Deep Cerulean), `--km-amber: #d97706` (Savanna Amber), `--km-crimson: #dc2626` (Threat Crimson), `--km-canvas-bg: #f8fafc`.

### 3.3 Normalized Relational Database Schema (16 Tables)
Managed strictly via `models.py` and Alembic migrations (`857b527918a8`, `60b452761b66`, `bfaa1479c244`):

| # | Table Name | SQLAlchemy Model | Purpose & Key Attributes |
|---|---|---|---|
| 1 | `departments` | `Department` | Organizational units (IT, FIN, HR, OPS) scoping manager dashboards. |
| 2 | `roles` | `Role` | Strict 3-tier RBAC roles: IT Admin, Manager, Employee. |
| 3 | `users` | `User` | Staff accounts, scrypt/PBKDF2 hashes, status (active/locked/compromised), 2FA OTP hash + TTL. |
| 4 | `login_logs` | `LoginLog` | Authentication audit trail logging IP, user-agent, outcome, and timestamps. |
| 5 | `emails` | `Email` | Scanned inbox/quarantine messages storing risk_score, verdict, confidence, and JSON indicators. |
| 6 | `blocked_senders` | `BlockedSender` | SOC-maintained sender/domain blocklist integrated directly into RULE-01-BLOCKLIST. |
| 7 | `reports` | `Report` | Employee-submitted phishing reports tracking triage status and linked incident reference. |
| 8 | `incidents` | `Incident` | Containment records (incident_ref INC-YYYY-XXXX, affected_user_id, created_by_user_id, severity, actions_log). |
| 9 | `campaigns` | `Campaign` | Phishing awareness drills created by IT Admins with subject/body metadata. |
| 10 | `sim_results` | `SimResult` | Unique cryptographic tracking tokens recording click and report events with zero credential fields. |
| 11 | `training_modules` | `TrainingModule` | Interactive Kenyan cybersecurity courses (3 seeded modules). |
| 12 | `quiz_questions` | `QuizQuestion` | 5 DB-persisted multiple-choice questions per module (15 seeded total) with explanations. |
| 13 | `quiz_options` | `QuizOption` | Selectable options per question (60 seeded total) storing is_correct boolean flag. |
| 14 | `quiz_results` | `QuizResult` | Historical employee quiz percentage attempts and >=70% pass status. |
| 15 | `alerts` | `Alert` | Organization-wide SOC security advisories triggered by incidents or admin broadcasts. |
| 16 | `alert_recipients` | `AlertRecipient` | Per-user delivery and acknowledgment timestamps for mandatory security advisories. |

### 3.4 Security Controls & Defense-in-Depth Architecture
* **Startup Fail-Fast Config (`config.py`):** Raises `RuntimeError` immediately if `DATABASE_URL` is missing (zero hidden SQLite fallback); normalizes `postgres://` and strips `pgbouncer=true` cleanly for psycopg2 compatibility; uses optional `MIGRATION_DATABASE_URL` (port `5432`) for DDL operations.
* **Authentication & Session Hardening (`routes/auth.py`, `app.py`):** Passwords hashed via Werkzeug (`generate_password_hash`); `5` failed login attempts trigger `status="locked"` logged in `login_logs`; login requires 6-digit OTP stored hashed (`otp_code VARCHAR(255)`) with `5-minute` expiry; `app.before_request` checks `(now - session["last_active"]) > 900` seconds for automatic `15-minute` idle timeout; cookies enforce `SESSION_COOKIE_HTTPONLY=True` and `SESSION_COOKIE_SAMESITE="Lax"` (`SESSION_COOKIE_SECURE=True` in `ProductionConfig`).
* **CSRF & Parameterized Queries:** Every state-changing `POST` form validates `secrets.compare_digest(session["_csrf_token"], submitted)` (exempting only the `GET /simulation/track/<token>` click tracker); all database queries use parameterized SQLAlchemy ORM bindings preventing SQL injection.

---

## CHAPTER 4: SYSTEM IMPLEMENTATION BY MILESTONE

### 4.1 Milestone 1: Environment Setup, Config & Public Platform Overview
Completed modular application factory (`create_app()`), `.env` environment parsing without SQLite fallback, database initialization, and public overview page (`templates/index.html`).


> **[SCREENSHOT PLACEHOLDER M1.1 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 1: Proposal, Environment & Initial Setup
> * **Title:** Project Directory Structure & Environment Configuration
> * **Login / Role Required:** Developer Terminal (No Login)
> * **URL / Command to Capture:** `tree -L 2 -I '__pycache__|*.pyc|.git|venv|.venv|.sitonik' && flask --version`
> * **What Should Appear in Screenshot:** Capture terminal showing modular Flask blueprint layout (app.py, config.py, models.py, detection/, routes/, migrations/, templates/) and active Python 3.14 / Flask 3.1.3 environment.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M1.2 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 1: Proposal, Environment & Initial Setup
> * **Title:** Public Platform Overview & Architecture Landing Page
> * **Login / Role Required:** Unauthenticated Visitor
> * **URL / Command to Capture:** `http://127.0.0.1:5000/`
> * **What Should Appear in Screenshot:** Capture the KingaMail Corporate Shield hero overview page showing the left navigation bar, Kenyan threat defense overview, and Sign In call-to-action (templates/index.html).
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


### 4.2 Milestone 2: Database Migrations, 2FA Auth & Role-Based Access Control
Initialized Flask-Migrate (`flask db migrate` / `flask db upgrade`) generating all 16 PostgreSQL tables, seeded demo departments (`IT`, `FIN`, `HR`, `OPS`), roles, users, and implemented the 2FA OTP login flow alongside role-tailored left sidebars in `templates/base.html`.


> **[SCREENSHOT PLACEHOLDER M2.1 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 2: Design, Schema & Access Control
> * **Title:** PostgreSQL / Alembic Migration History (16 Tables across 3 Revisions)
> * **Login / Role Required:** Developer Terminal
> * **URL / Command to Capture:** `flask db history && flask db current`
> * **What Should Appear in Screenshot:** Capture terminal output showing migrations 857b527918a8 (initial), 60b452761b66 (OTP hash varchar(255)), and bfaa1479c244 (quiz_question & quiz_option) at head, OR Supabase Table Editor showing all 16 tables.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M2.2 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 2: Design, Schema & Access Control
> * **Title:** Employee Sign-In Screen & 5-Attempt Lockout Guard
> * **Login / Role Required:** Unauthenticated User
> * **URL / Command to Capture:** `http://127.0.0.1:5000/auth/login`
> * **What Should Appear in Screenshot:** Capture the KingaMail login form displaying SYSTEM_NAME branding, CSRF hidden token protection, and demo login guidance without exposing secrets in production mode.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M2.3 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 2: Design, Schema & Access Control
> * **Title:** Two-Factor Authentication (6-Digit OTP Verification with DEMO_MODE Banner)
> * **Login / Role Required:** Authenticating User (e.g. employee@corporate.local / Employee123!)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/auth/verify-otp`
> * **What Should Appear in Screenshot:** Capture the OTP verification page showing the 5-minute expiry warning, Resend OTP button, and the DEMO_MODE on-screen code alert (code is hashed in users.otp_code in PostgreSQL).
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M2.4 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 2: Design, Schema & Access Control
> * **Title:** Role-Based Navigation Comparison (Employee vs Manager vs IT Admin)
> * **Login / Role Required:** Side-by-Side or Sequential Logins
> * **URL / Command to Capture:** `Login as employee@corporate.local, manager@corporate.local, admin@corporate.local`
> * **What Should Appear in Screenshot:** Capture the left sidebar menus changing per role: Employee (Inbox/Quarantine/Scan/Advisories/Courses), Manager (Team Risk Dashboard/Compliance Benchmarks/CSV Export), and IT Admin (SOC Console/Triage/Campaigns).
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


### 4.3 Milestone 3: Offline Kenyan Heuristic Detection Engine & Mailbox
Unlike black-box external APIs, KingaMail evaluates raw email text strictly locally using Unicode normalization (`NFKC` + homoglyph translation of lookalike digits/characters such as `0 -> o`, `1 -> l`, `rn -> m`, `vv -> w`) and domain parsing (`detection/parser.py`). Each of the **12 rules** returns an integer point contribution; `detection/scoring.py` sums scores **uncapped** across all 12 rules (`total_score = sum(c["score"] for c in checks)`):

* **Verdict Thresholds (`detection/scoring.py`):**
  * `0 – 24` points &rarr; **`Safe`** (Delivered to Inbox)
  * `25 – 54` points &rarr; **`Suspicious`** (Inbox with caution alert badge)
  * `55+` points &rarr; **`Quarantine`** (Isolated to Quarantine Vault)
* **Confidence Calculation:**
  * `High` if `triggered_count >= 3` or `total_score >= 60`
  * `Medium` if `triggered_count >= 1` or `total_score >= 25`
  * `Low` otherwise

#### The 12 Kenyan Heuristic Detection Rules (`detection/rules.py`)

| Rule ID | Rule Name | Weight | Detection Logic Summary |
|---|---|---|---|
| `RULE-01-BLOCKLIST` | Local Malicious Blocklist | +60 max | Matches sender or URL domains against config KNOWN_BAD_DOMAINS (15 domains) and live DB blocked_sender table. |
| `RULE-02-TRUSTED-ORIGIN` | Trusted Domain Verification | 0 or +15 | Exempts 21 corporate/major domains including corporate.local (0 pts); flags unverified external origins (+15). |
| `RULE-03-DISPLAY-NAME-SPOOF` | Mismatched Display Name Spoofing | +45 | Flags executive titles or protected brands (KRA, Safaricom, CBK, CEO/CFO) paired with mismatched external domains. |
| `RULE-04-KENYA-TELECOM-MPESA` | Kenyan Telecom & M-Pesa Fraud | +40 | Detects M-Pesa reversals, Fuliza limits, Safaricom/Airtel promo scams, Till/Paybill lures, and SIM swap bait. |
| `RULE-05-KENYA-GOV-COMPLIANCE` | Government & Statutory Scam Detector | +45 (0 .go.ke) | Flags fake KRA iTax, eCitizen, HELB, SHIF/NHIF, NSSF, and NTSA notices unless sent from verified .go.ke domains. |
| `RULE-06-KENYA-FINANCIAL-SACCO` | Kenyan Bank & SACCO Security | +40 | Detects fraudulent alerts impersonating KCB, Equity, Co-op, NCBA, Absa, Stima/Mwalimu SACCOs, and Pesalink. |
| `RULE-07-TENDER-INVOICE-FRAUD` | Procurement & BEC Invoice Fraud | +40 | Flags unauthorized RFP/tender fee requests, IFMIS payment redirections, and urgent supplier bank-detail changes. |
| `RULE-08-FREE-TRAINING-LURE` | Free Training & Fellowship Lure | +35 | Detects fake NGO fellowships, free CPD credit offers, per diem lures, and sponsored scholarship credential traps. |
| `RULE-09-TYPOSQUAT-HOMOGLYPH` | Lookalike & Typosquatting Defense | +40 | Normalizes Unicode homoglyphs/digits (0/o, 1/l, rn/m) and flags spoofs like safar1com-support.com or micr0soft. |
| `RULE-10-URGENCY-COERCION` | Coercive Urgency & Pressure | +25 | Detects artificial deadlines (24 hours, immediate suspension), CRB blacklisting threats, and secrecy demands. |
| `RULE-11-CREDENTIAL-HARVEST` | Credential & Sensitive Data Probe | +40 | Flags solicitation of passwords, OTPs, M-Pesa PINs, KRA iTax PINs, National IDs, or bank card CVV data. |
| `RULE-12-SUSPICIOUS-HYPERLINK` | Suspicious Link Anatomy | +30 | Penalizes raw IP URLs, URL shorteners (bit.ly, tinyurl), anchor-text mismatches, and high-risk TLDs (.xyz, .top, .tk, .cf, .ga, .ml). |

*Implementation Note:* External intelligence (`ENABLE_VIRUSTOTAL`) defaults to `False`, so `scan_domain_virustotal()` and `scan_urls_virustotal()` return neutral `score=0` stubs without issuing outbound HTTP requests. Notice also that an outdated docstring comment inside `routes/emails.py` mentions `score > 70`, whereas actual runtime quarantine enforcement (`analyze_email`) uses `>= 55`.


> **[SCREENSHOT PLACEHOLDER M3.1 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 3: Core Implementation & Detection Engine
> * **Title:** Employee Personal Inbox Showing Safe & Suspicious Messages
> * **Login / Role Required:** Employee (employee@corporate.local)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/emails/inbox`
> * **What Should Appear in Screenshot:** Capture inbox listing seeded messages: ERP Maintenance (Score 0, Safe), Q4 Strategy Briefing (Score 0, Safe), and Nairobi Leadership Fellowship lure (Score 50, Suspicious) with color-coded badges.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M3.2 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 3: Core Implementation & Detection Engine
> * **Title:** Quarantined Attacks Vault (KRA iTax & Safaricom M-Pesa Phishes)
> * **Login / Role Required:** Employee or IT Admin
> * **URL / Command to Capture:** `http://127.0.0.1:5000/emails/quarantine`
> * **What Should Appear in Screenshot:** Capture quarantine table displaying auto-isolated high-risk messages (>=55 pts): KRA Suspension Notice (Score 200) and M-Pesa Float Reversal (Score 170) isolated away from the main inbox.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M3.3 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 3: Core Implementation & Detection Engine
> * **Title:** Live On-Demand Threat Scanner with 12-Rule Breakdown
> * **Login / Role Required:** Employee / Manager / IT Admin
> * **URL / Command to Capture:** `http://127.0.0.1:5000/emails/analyze`
> * **What Should Appear in Screenshot:** Submit a raw KRA or M-Pesa phishing email (using quick-load sample or pasted RFC email) and capture the verdict banner (Quarantine, High Confidence), uncapped point score, and triggered RULE-01..RULE-12 table.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M3.4 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 3: Core Implementation & Detection Engine
> * **Title:** Offline Heuristic Engine Unit Test Verification
> * **Login / Role Required:** Developer Terminal
> * **URL / Command to Capture:** `python test_original_suite.py (or offline detection.scoring check)`
> * **What Should Appear in Screenshot:** Capture terminal verifying RULE-01 through RULE-12 outputs: Clean corporate email = 0 (Safe), Free Training lure = 50 (Suspicious), and KRA Phish = 300 (Quarantine).
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


### 4.4 Milestone 4: Employee Reporting & Closed-Loop Incident Containment
When an employee clicks **Report Phishing** on `/emails/view/<email_id>`, a `Report` record enters the IT Admin Triage Queue (`/reports/`). Confirming the threat (`POST /reports/triage/<report_id>`) atomically executes five containment actions:
1. Creates a structured `Incident` dossier with reference format `INC-YYYY-XXXX` (severity `High` if `risk_score >= 75` or simulated click occurred, else `Medium`) and timestamped `actions_log`.
2. Evaluates `affected_user_id` — if malicious link risk exists or simulation click is confirmed, marks the victim's account `status="compromised"` and `force_password_reset=True`, locking out normal routes via `app.before_request`.
3. Extracts the attacker's sender address/domain and persists it to `blocked_senders` so future scans immediately trigger `RULE-01-BLOCKLIST` (+60 points).
4. Moves the offending message status to `"quarantined"`.
5. Creates an urgent organization-wide `Alert` and dispatches `AlertRecipient` rows to all active employees.


> **[SCREENSHOT PLACEHOLDER M4.1 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 4: Incident Response & SOC Triage
> * **Title:** Email Detail View with 'Report Phishing' Action Button
> * **Login / Role Required:** Employee (employee@corporate.local)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/emails/view/<email_id>`
> * **What Should Appear in Screenshot:** Capture full email headers (From, Reply-To, Verdict badge, confidence, triggered rules) alongside the 'Report Phishing to SOC' button (routes/reports.py -> /reports/submit/<email_id>).
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M4.2 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 4: Incident Response & SOC Triage
> * **Title:** SOC Triage Queue & Automated 5-Step Containment Execution
> * **Login / Role Required:** IT Admin (admin@corporate.local)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/reports/`
> * **What Should Appear in Screenshot:** Capture pending employee reports queue showing sender, risk score, user comment, and Confirm Malicious / Dismiss False Positive triage action buttons.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M4.3 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 4: Incident Response & SOC Triage
> * **Title:** Incident Docket Detail (INC-YYYY-XXXX), Victim Lock & Forced Reset
> * **Login / Role Required:** IT Admin (admin@corporate.local)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/incidents/view/<incident_id>`
> * **What Should Appear in Screenshot:** Capture incident dossier displaying auto-generated INC-YYYY-XXXX reference, severity, affected victim user (status=compromised, force_password_reset=True), BlockedSender entry, and timestamped actions_log.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M4.4 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 4: Incident Response & SOC Triage
> * **Title:** Mandatory Password Reset Gate & Organization-Wide Security Advisory
> * **Login / Role Required:** Compromised User (bob.miller@corporate.local / Employee123!)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/auth/reset-password & http://127.0.0.1:5000/alerts/`
> * **What Should Appear in Screenshot:** Capture compromised user redirected strictly to /auth/reset-password after OTP login, plus the Security Advisories acknowledgment panel at /alerts/.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


### 4.5 Milestone 5: Phishing Simulations, Quizzes, Chart.js Dashboards & CSV Export
* **Ethical Phishing Simulation (`routes/simulation.py`, `templates/campaigns_list.html`):** Admins can launch custom drills or select from three built-in Kenyan presets (**Free Training Lure**, **HR Payroll & SHIF**, **M-Pesa Reimbursement**). Each targeted employee receives an isolated `[Simulated]` message containing a unique `secrets.token_urlsafe(32)` token. Clicking `/simulation/track/<token>` logs `is_clicked=True` and renders `templates/simulation_landing.html`, which contains **zero HTML `<form>` or password `<input>` elements** — safeguarding privacy. Reporting the message marks `is_reported=True`.
* **Training Modules & Database Quizzes (`routes/training.py`, `seed.py`):** Three seeded courses (*Recognizing Social Engineering & Artificial Urgency*, *Spotting Typosquatting & Malicious Hyperlinks*, and *Spear Phishing & Executive Impersonation (CEO Fraud)*), each holding **5 multiple-choice questions** (`15` questions / `60` options in PostgreSQL). Quizzes require `>=70%` to pass and store question-by-question explanations.
* **Analytics & Audit Exports (`routes/dashboard.py`):**
  * **IT Admin (`/dashboard/admin`):** KPI counts + 3 Chart.js visualizations (`verdictsChart` doughnut, `rulesBarChart` bar, `weeklyReportsLineChart` trend). *(Transparency note: `verdictsChart` and Week 4 of the trend line query live PostgreSQL tables, while `rulesBarChart` `[14, 11, 8, 7, 5, 4, 3]` and Weeks 1–3 `[3, 6, 4]` supply baseline historical context in the demo template.)*
  * **Manager (`/dashboard/manager`):** Strictly scoped to `department_id`, rendering PostgreSQL-driven team simulation bar & quiz outcome doughnut charts plus high-risk employee alerts.
  * **Compliance CSV (`/dashboard/reports/export-csv`):** Streams a 12-column audit file: `Employee ID`, `Full Name`, `Email Address`, `Department`, `Role`, `Account Status`, `Simulations Targeted`, `Simulations Clicked`, `Simulations Reported`, `Quizzes Taken`, `Average Quiz Score (%)`, and `Security Posture Rating`.


> **[SCREENSHOT PLACEHOLDER M5.1 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 5: Phishing Simulations, Training, Analytics & Export
> * **Title:** Phishing Simulation Campaign Console with Kenyan Lure Presets
> * **Login / Role Required:** IT Admin (admin@corporate.local)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/simulation/campaigns`
> * **What Should Appear in Screenshot:** Capture existing campaigns table (Click Rate % & Report Rate % progress bars) and the Launch Campaign modal showing the 3 Kenyan preset buttons: Free Training Lure, HR Payroll & SHIF, M-Pesa Reimbursement.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M5.2 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 5: Phishing Simulations, Training, Analytics & Export
> * **Title:** Zero-Credential-Capture Simulation Educational Landing Page
> * **Login / Role Required:** Employee clicking tracked link
> * **URL / Command to Capture:** `http://127.0.0.1:5000/simulation/track/<token>`
> * **What Should Appear in Screenshot:** Capture the simulation debrief notice confirming the click was logged while explicitly showing ZERO HTML input forms or password fields, paired with direct link to Training Modules.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M5.3 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 5: Phishing Simulations, Training, Analytics & Export
> * **Title:** Interactive Security Awareness Quiz & Database-Graded Results
> * **Login / Role Required:** Employee (employee@corporate.local)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/training/module/1 -> Submit Quiz`
> * **What Should Appear in Screenshot:** Capture one of the 3 Kenyan corporate awareness courses (5 multiple-choice questions stored in quiz_question/quiz_option) and the resulting >=70% pass/fail explanation breakdown (quiz_result.html).
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M5.4 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 5: Phishing Simulations, Training, Analytics & Export
> * **Title:** IT Admin SOC Console with Chart.js Analytics
> * **Login / Role Required:** IT Admin (admin@corporate.local)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/dashboard/admin`
> * **What Should Appear in Screenshot:** Capture KPI tiles plus all 3 Chart.js visualizations: Email Verdicts Doughnut (DB-driven), Top Triggered Rules Bar Chart, and Weekly Reports Trend Line Chart.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M5.5 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 5: Phishing Simulations, Training, Analytics & Export
> * **Title:** Manager Department Risk Dashboard & High-Risk Staff Table
> * **Login / Role Required:** Department Manager (manager@corporate.local)
> * **URL / Command to Capture:** `http://127.0.0.1:5000/dashboard/manager`
> * **What Should Appear in Screenshot:** Capture manager-scoped analytics for Operations (OPS): Team Simulation Engagement bar chart, Quiz Outcomes doughnut chart, and flagged high-risk employees.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M5.6 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 5: Phishing Simulations, Training, Analytics & Export
> * **Title:** Compliance Benchmarking Matrix & 12-Column Audit CSV Export
> * **Login / Role Required:** IT Admin or Manager
> * **URL / Command to Capture:** `http://127.0.0.1:5000/dashboard/reports & /dashboard/reports/export-csv`
> * **What Should Appear in Screenshot:** Capture inter-department benchmarking table/chart alongside an opened CSV spreadsheet displaying the 12 columns (Employee ID through Security Posture Rating).
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


> **[SCREENSHOT PLACEHOLDER M5.7 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 5: Phishing Simulations, Training, Analytics & Export
> * **Title:** Responsive Mobile Viewport Layout Check
> * **Login / Role Required:** Any Authenticated User (Browser DevTools 390x844 Mobile View)
> * **URL / Command to Capture:** `Chrome/Firefox DevTools Device Toolbar -> 390x844`
> * **What Should Appear in Screenshot:** Capture KingaMail collapsing the left sidebar into the responsive slide-out drawer with hamburger toggle and readable cards on a smartphone viewport.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


### 4.6 Milestone 6: Final Integration & Defense Verification

> **[SCREENSHOT PLACEHOLDER M6.1 — INSERT IMAGE HERE]**
> 
> * **Milestone:** Milestone 6: Final Integration & Defense Verification
> * **Title:** Git Commit History Across Phases 1-6 & Health JSON Endpoint
> * **Login / Role Required:** Developer Terminal / Browser
> * **URL / Command to Capture:** `git log --oneline -n 10 && curl http://127.0.0.1:5000/health`
> * **What Should Appear in Screenshot:** Capture clean commit history from Phase 1 Foundation through Phase 6 Dashboards & CSV Export plus live /health JSON response {'status': 'healthy', 'system_name': 'KingaMail Corporate Shield', 'version': '1.0.0'}.
> 
> *(Leave space blank in draft; paste screenshot directly above this caption box before final binding.)*


---

## CHAPTER 5: TESTING, VERIFICATION & ECONOMIC EVALUATION

### 5.1 Verification & Test Results (Executed 14 November 2026)

| Verification Suite | Scope Checked | Result (14 Nov 2026) | Notes / Exact Evidence |
|---|---|---|---|
| **Offline Detection Rules (`test_original_suite.py` part 1)** | All `12` Kenyan rules (`RULE-01`..`RULE-12`) | **PASSED** | Checked directly against `detection.rules` & `detection.scoring` |
| **Scoring Thresholds & Sample Payloads** | Clean (`0` Safe), Free Training (`50` Suspicious), KRA Phish (`300` Quarantine) | **PASSED** | Uncapped cumulative sum + exact confidence classification verified |
| **PostgreSQL / Flask Route Integration (`test_original_suite.py` part 2)** | `client.get("/")` and live Supabase pooler routes | **FAILED (External DB Paused)** | `psycopg2.OperationalError: FATAL: (ENOTFOUND) tenant/user postgres.kdalwgxcksveyjuteqem not found` at `aws-0-eu-west-1.pooler.supabase.com:6543` |

> **Pre-Defense Action Required:** Before running live demonstrations at Zetech University, reactivate or update the Supabase PostgreSQL connection string in `.env` (`DATABASE_URL` / `MIGRATION_DATABASE_URL`), then run:
> ```bash
> flask db upgrade
> python seed.py
> python test_original_suite.py
> ```

### 5.2 Economic & Cost Comparison Summary
* **Development & Software Licensing Cost:** `KSh 0` (Python, Flask, PostgreSQL/Supabase Free Tier, Bootstrap, Chart.js).
* **Comparable Commercial Alternative:** Commercial email security + awareness suites typically cost USD 4–12/user/month (`~KSh 620,000 – KSh 1,870,000+` annually for a 100-user SME), giving KingaMail immediate ROI for Kenyan SMEs, SACCOs, NGOs, and academic institutions.

---

## CHAPTER 6: CONCLUSION, LIMITATIONS & FUTURE WORK

### 6.1 Conclusion
KingaMail Corporate Shield achieves all five project objectives, unifying Kenyan-context threat detection, closed-loop incident containment, ethical phishing simulations, database-backed awareness testing, and compliance analytics inside an original, mobile-responsive Flask web platform with zero mandatory external API cost.

### 6.2 Observed System Limitations
1. **Simulated Mailbox vs Live MX Proxy:** Currently ingests/scans emails persisted in PostgreSQL or submitted through `/emails/analyze` rather than intercepting live SMTP traffic directly.
2. **Chart.js Baseline Data Points:** On `dashboard_admin.html`, `rulesBarChart` and Weeks 1–3 of `weeklyReportsLineChart` display static illustrative arrays while `verdictsChart`, Week 4 reports, Manager analytics, and Department benchmarking read live PostgreSQL records.
3. **Database Availability Sensitivity:** Enforces strict fail-fast connectivity to Supabase PostgreSQL; if a Supabase free-tier tenant pauses due to inactivity, the project must be unpaused before launch.

### 6.3 Recommendations for Future Work
1. **Postfix / SMTP Milter Daemon Integration:** Hook `detection.scoring.analyze_email()` directly into enterprise mail relays for inline gateway quarantine.
2. **Event-Log Aggregation for Rules Chart:** Persist per-rule trigger counters in SQL so the admin `rulesBarChart` reflects live cumulative rule hits across time.
3. **Production Email Relay for 2FA:** Connect SMTP/SMS gateway delivery for OTP codes when `DEMO_MODE=False`.

---

## APPENDIX A: COMPLETE ROUTE & RBAC ACCESS MATRIX

| Route Pattern | HTTP Methods | Allowed Role(s) | Function Summary |
|---|---|---|---|
| `/` | `GET` | Public | Platform landing overview or role redirect |
| `/health` | `GET` | Public | JSON service health check |
| `/auth/login, /verify-otp, /resend-otp` | `GET/POST` | Public | Credential check, 5-attempt lockout, 6-digit hashed OTP (5-min TTL) |
| `/auth/reset-password, /auth/logout` | `GET/POST` | Authenticated | Mandatory reset when force_password_reset=True; session wipe |
| `/emails/inbox, /quarantine, /view/<id>` | `GET` | All Roles | Ownership-checked personal mailbox & isolated quarantine vault |
| `/emails/analyze` | `GET/POST` | All Roles | On-demand 12-rule email analyzer querying BlockedSender |
| `/emails/quarantine/release/<id>, /delete/<id>` | `POST` | Admin / Owner | Release false positive or delete message |
| `/reports/submit/<email_id>` | `POST` | All Roles | Report suspicious email; auto-flags simulation is_reported=True |
| `/reports/, /reports/triage/<report_id>` | `GET/POST` | IT Admin | SOC queue; Confirm executes 5-step containment workflow |
| `/incidents/, /view/<id>, /close/<id>` | `GET/POST` | IT Admin | Incident dossier tracking & resolution closure |
| `/alerts/, /acknowledge/<id>` | `GET/POST` | All Roles | Read & confirm SOC security advisories |
| `/alerts/broadcast` | `POST` | IT Admin | Broadcast organization-wide security advisory |
| `/simulation/campaigns, /create` | `GET/POST` | IT Admin | Manage/launch Kenyan phishing drills via CSRF POST |
| `/simulation/track/<token>` | `GET` | Token Link | Records click only & renders zero-form debrief page |
| `/training/, /modules, /module/<id>, /quiz/<id>` | `GET/POST` | All Roles | Interactive awareness courses & 5-question DB quizzes (>=70% pass) |
| `/dashboard/admin` | `GET` | IT Admin | SOC Console with KPIs and 3 Chart.js visualizations |
| `/dashboard/manager` | `GET` | Manager | Department-scoped team risk charts & high-risk staff monitor |
| `/dashboard/reports, /export-csv` | `GET` | Admin, Manager | Cross-department compliance table + 12-column CSV export |

---

## APPENDIX B: SEEDED DEMO CREDENTIALS (`seed.py`)

> Note: Passwords apply after seeding PostgreSQL via `python seed.py`. In `DEMO_MODE=True`, the 6-digit OTP appears both on the verification banner and in the Flask server terminal console.

| Full Name | Login Email | Password | Role | Department | Initial Account Status |
|---|---|---|---|---|---|
| Alex Rivera | `admin@corporate.local` | `Admin123!` | IT Admin | IT (`IT`) | `active` |
| Sarah Jenkins | `manager@corporate.local` | `Manager123!` | Manager | Operations (`OPS`) | `active` |
| Jane Doe | `employee@corporate.local` | `Employee123!` | Employee | Finance (`FIN`) | `active` *(5 sample emails)* |
| Bob Miller | `bob.miller@corporate.local` | `Employee123!` | Employee | HR (`HR`) | `compromised` *(Triggers mandatory `/auth/reset-password`)* |

---

## REFERENCES
1. Communications Authority of Kenya (National KE-CIRT/CC) — *Cybersecurity Sector Statistics & Phishing Advisory Bulletins*.
2. Republic of Kenya — *The Data Protection Act, No. 24 of 2019* & *Computer Misuse and Cybercrimes Act, 2018*.
3. OWASP Foundation — *OWASP Top 10 & Authentication / CSRF Prevention Cheat Sheets*.
4. Pallets Projects — *Flask 3.1, Werkzeug Security & Jinja2 Documentation*.
5. SQLAlchemy & Alembic — *Flask-Migrate Database Schema Versioning Documentation*.
