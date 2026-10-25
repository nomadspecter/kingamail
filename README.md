# 🇰🇪 KingaMail — Enterprise Email Security & Threat Awareness Platform

A corporate, web-based email security operations (SOC) and human-layer cyber-awareness platform built with **Python Flask**, **SQLAlchemy**, **Flask-Migrate (Alembic)**, **Supabase Cloud PostgreSQL**, and **Chart.js**.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Architecture & Design Philosophy](#-architecture--design-philosophy)
- [12 Kenyan Heuristic Threat Rules & Scoring Matrix](#-12-kenyan-heuristic-threat-rules--scoring-matrix)
  - [Custom Scoring Brackets](#custom-scoring-brackets)
  - [Rule Matrix](#rule-matrix)
- [Original UI & Dashboards](#-original-ui--dashboards)
  - [Left Sidebar Navigation by Role](#left-sidebar-navigation-by-role)
  - [Chart.js Interactive Analytics](#chartjs-interactive-analytics)
- [Kenyan Workplace Phishing Simulation Engine](#-kenyan-workplace-phishing-simulation-engine)
  - [Strict Privacy Guard](#strict-privacy-guard)
  - [Available Regional Simulation Scenarios](#available-regional-simulation-scenarios)
- [Two-Factor Authentication & Account Lockout](#-two-factor-authentication--account-lockout)
- [Database Schema (models.py) & Migrations](#-database-schema-modelspy--migrations)
- [Supabase Cloud PostgreSQL Setup](#-supabase-cloud-postgresql-setup)
- [Quickstart & Demo Credentials](#-quickstart--demo-credentials)
- [Test Verification Suite](#-test-verification-suite)

---

## 🔍 Overview

**KingaMail** is an enterprise-grade cybersecurity platform engineered specifically for African and Kenyan corporate operating environments. Rather than relying on opaque machine learning models or third-party cloud scanners, KingaMail employs **100% deterministic, explainable, rule-based heuristics** tailored to regional threat tactics:

* **Mobile Money Fraud:** M-Pesa reversals, Fuliza settlement demands, Bonga points expiry scams, and SIM swap coercion.
* **Public Sector Impersonation:** Fake KRA iTax compliance certificates, withholding tax VAT penalties, eCitizen payment mandates, and HELB loan default threats.
* **Banking & SACCO Defense:** Unauthorized account suspensions targeting KCB, Equity Bank, Co-operative Bank, NCBA, and SACCOs (Stima, Harambee, Police SACCO).
* **Procurement & BEC Invoice Fraud:** Forged County Government Local Purchase Orders (LPOs), bogus tender awards, and fraudulent bank account redirection.
* **Social Engineering Lures:** Unsolicited fully-funded corporate training fellowships in Nairobi/Mombasa, fake CPD credit vouchers, and mismatched display-name executive spoofing.

---

## 🛡️ Architecture & Design Philosophy

1. **Zero External Network Dependencies:** The threat engine operates completely offline using local pattern matrices, regex tokenizers, the `KNOWN_BAD_DOMAINS` blocklist in `config.py`, and the dynamic `blocked_sender` database table. External threat intelligence (VirusTotal) is strictly optional and disabled by default (`ENABLE_VIRUSTOTAL=False`).
2. **Explainable Point Scoring:** Every flagged indicator carries an explicit point value and an educational finding message so security analysts and employees understand exactly why a message was scored as safe, suspicious, or quarantined.
3. **Internal Origin Whitelist:** Internal corporate senders ending in `@corporate.local` pass `check_trusted_domain` with **0 penalty points**, ensuring routine staff memos are never penalized.
4. **Strict Security Controls:** Parameterized queries via SQLAlchemy ORM, CSRF tokens on all state-changing requests, 15-minute inactivity session timeouts, account lockouts after 5 consecutive failed logins, and hashed 2FA OTP passcodes.

---

## ⚙️ 12 Kenyan Heuristic Threat Rules & Scoring Matrix

### Custom Scoring Brackets

All email messages evaluated by `detection/scoring.py` are mapped into three distinct operational security verdicts:

* **0 to 24 Points — Safe:** Delivered directly to the employee's inbox.
* **25 to 54 Points — Suspicious:** Delivered with an amber security caution banner warning the recipient to exercise vigilance.
* **55+ Points — Quarantine:** Isolated immediately from the employee's inbox into the quarantine repository for SOC review.

### Rule Matrix

| # | Rule Identifier | Rule Name | Points | Heuristic Focus & Forensic Detection |
| :- | :--- | :--- | :--- | :--- |
| 1 | `RULE-01-BLOCKLIST` | **Local Malicious Blocklist** | **+60 pts** | Matches sender domain or any link hostname against `KNOWN_BAD_DOMAINS` and the database `blocked_sender` table. (Direct Quarantine) |
| 2 | `RULE-02-TRUSTED-ORIGIN` | **Trusted Domain Verification** | **0 / +15 pts** | Verified internal corporate (`corporate.local`) and reputable providers receive 0 pts; unknown external domains receive baseline caution (+15 pts). |
| 3 | `RULE-03-DISPLAY-NAME-SPOOF` | **Mismatched Display Name Spoofing** | **+45 pts** | **[Original Check #1]** Flags display names claiming authority (KRA, Safaricom, Equity, IT Helpdesk) when sent from unrelated infrastructure. |
| 4 | `RULE-04-KENYA-TELECOM-MPESA` | **Kenyan Telecom & M-Pesa Fraud** | **+40 pts** | Detects fake M-Pesa reversals, float settlement claims, Fuliza overdrafts, Bonga points expiry, and airtime scratchcard lures. |
| 5 | `RULE-05-KENYA-GOV-COMPLIANCE` | **Government & Statutory Scam Detector** | **+45 pts** | Scans for fake KRA iTax compliance certificates, VAT penalties, eCitizen payment mandates, HELB loan default threats, and SHIF/NHIF levies. |
| 6 | `RULE-06-KENYA-FINANCIAL-SACCO` | **Kenyan Bank & SACCO Security** | **+40 pts** | Flags unauthorized communications mimicking commercial banks (KCB, Equity, Co-op, NCBA) and SACCOs (Stima, Harambee, Police). |
| 7 | `RULE-07-TENDER-INVOICE-FRAUD` | **Procurement & BEC Invoice Fraud** | **+40 pts** | Uncovers forged County Government LPOs, tender pre-qualifications, and fraudulent requests to redirect invoice bank accounts. |
| 8 | `RULE-08-FREE-TRAINING-LURE` | **Free Training & Fellowship Lure** | **+35 pts** | **[Original Check #2]** Detects unsolicited fully funded workshops in Nairobi/Mombasa, free CPD credits, and fake NGO fellowships. |
| 9 | `RULE-09-TYPOSQUAT-HOMOGLYPH` | **Lookalike & Typosquatting Defense** | **+40 pts** | Normalizes leetspeak substitutions (`1`$\to$`i`/`l`, `0`$\to$`o`, `rn`$\to$`m`) to catch lookalikes (`safar1com`, `kra-portal`, `ecit1zen`). |
| 10 | `RULE-10-URGENCY-COERCION` | **Coercive Urgency & Pressure** | **+25 pts** | Detects psychological panic deadlines ("act within 2 hours", "immediate police arrest/CRB listing", "keep strictly secret"). |
| 11 | `RULE-11-CREDENTIAL-HARVEST` | **Credential & Sensitive Data Probe** | **+40 pts** | Flags requests for passwords, M-Pesa PINs, ATM PINs, National ID numbers, KRA PIN passwords, or card CVVs. |
| 12 | `RULE-12-SUSPICIOUS-HYPERLINK` | **Suspicious Link Anatomy** | **+30 pts** | Scans embedded URLs for raw IP addresses, URL shorteners (bit.ly, tinyurl), and untrusted high-risk TLDs (`.xyz`, `.top`, `.buzz`, `.work`). |

---

## 🎨 Original UI & Dashboards

KingaMail features an original, bespoke user interface designed specifically for high-efficiency enterprise security operations:

* **Typography:** Modern Google Font `'Plus Jakarta Sans'` (weights 400 to 800).
* **Color Palette:** Deep African Navy (`#0f172a`), Safari Emerald Green (`#059669`), Savanna Amber (`#d97706`), Threat Crimson (`#dc2626`), and clean Slate Canvas (`#f8fafc`).
* **Mobile-Ready:** Fully responsive layout with an offcanvas slide-out navigation drawer for smartphone and tablet viewports.

### Left Sidebar Navigation by Role

The interface employs a fixed, role-specific left sidebar:

* **IT Admin (SOC):** SOC Console, Incidents Docket, Triage Queue, Quarantined Attacks, Phishing Campaigns, Compliance Reports, Security Advisories, Personal Mailbox, Threat Scanner, Training Catalog.
* **Department Manager:** Team Risk Dashboard, Compliance Benchmarks, Export Audit CSV, My Mailbox, Quarantined Items, Threat Scanner, Security Alerts, Training Modules.
* **Employee:** Corporate Inbox, Quarantined Items, Threat Scanner, Security Advisories, Awareness Training Courses.
* **Unauthenticated Visitor:** Platform Overview, Employee Sign-In.

### Chart.js Interactive Analytics

KingaMail integrates **Chart.js 4.4** across its dashboards (no obsolete radar charts or dark cyberpunk gauges):

1. **SOC Executive Console (`/dashboard/admin`):**
   * **Doughnut Chart:** Threat Verdict Distribution (Safe, Suspicious, Quarantined Phish).
   * **Horizontal Bar Chart:** Top Triggered Heuristic Rules across incoming emails.
   * **Line Chart:** Staff Phishing Reports & Triage Volume trend over time.
2. **Department Manager Dashboard (`/dashboard/manager`):**
   * **Comparative Bar Chart:** Simulation Clicks (Vulnerability) vs. Threat Reports (Vigilance) by team member.
   * **Doughnut Chart:** Team Training Assessment Pass/Fail compliance.
3. **Compliance Reports (`/dashboard/reports`):**
   * **Grouped Bar Chart:** Departmental Benchmarking comparing Click Failure Rates against Reporting Rates across IT, Finance, HR, and Operations.

---

## 🎯 Kenyan Workplace Phishing Simulation Engine

KingaMail allows security administrators to launch controlled, educational phishing assessments to build workforce cyber-resilience.

### Strict Privacy Guard
* Simulation links (`/simulation/track/<token>`) record the **click timestamp only**.
* The educational landing page contains **ZERO input forms, ZERO password fields, and never captures or stores user input**.

### Available Regional Simulation Scenarios
1. **Free Professional Training Lure:** Unsolicited invitation for an executive governance fellowship in Nairobi with 25 free CPD credits and full per diem coverage.
2. **HR Payroll & SHIF Directive:** Urgent directive regarding the national transition from NHIF to the Social Health Insurance Fund (SHIF) demanding bank re-verification.
3. **M-Pesa Business Float & Reimbursement:** Petty cash voucher disbursement alert for corporate airtime and travel expenses.
4. **County Tender Pre-Qualification Award:** Notice of an approved supply contract under Local Purchase Order (LPO) asking to confirm recipient bank coordinates.

---

## 🔐 Two-Factor Authentication & Account Lockout

* **2FA One-Time Passcode (OTP):** Generated using a cryptographically random 6-digit integer, stored securely hashed using PBKDF2/SHA256 in PostgreSQL (`user.otp_code`), and bound to a strict 5-minute expiry window (`user.otp_expiry`).
* **Demo Mode (`DEMO_MODE=True`):** Prints OTP verification codes directly to the server terminal and renders an informational callout on the screen for live demonstration and evaluation.
* **Account Lockout Policy:** Automatically locks user accounts (`status='locked'`) after 5 consecutive failed password attempts.
* **Compromised Account Containment:** Victims of confirmed phishing attacks (`status='compromised'`) are confined to `/auth/reset-password` until new credentials are established.

---

## 🏛️ Database Schema (models.py) & Migrations

[models.py](file:///home/nomad/kingamail/models.py) is the **single source of truth** for all 16 database tables:

1. `department`: Organizational units (IT, FIN, HR, OPS).
2. `role`: Access tiers (`Employee`, `IT Admin`, `Manager`).
3. `user`: Workforce identity, credentials, hashed OTPs, and status (`active`, `locked`, `compromised`).
4. `login_log`: Immutable authentication audit log (success, failure, IP, user-agent).
5. `email`: Ingested messages with risk scores, verdict badges, and heuristic indicators.
6. `blocked_sender`: Dynamic domain and sender blocklist.
7. `report`: Employee-submitted suspicious messages pending SOC triage.
8. `incident`: Formal security incident records (`INC-YYYY-XXXX`) with chronological `actions_log`.
9. `alert`: Security broadcast bulletins delivered to staff.
10. `alert_recipient`: Individual delivery and read acknowledgment tracking.
11. `campaign`: Phishing awareness simulation campaigns.
12. `sim_result`: Per-user simulation metrics (tokens, clicks, reports).
13. `training_module`: Cybersecurity awareness courses.
14. `quiz_question`: 5 multiple-choice questions per training module.
15. `quiz_option`: 4 choices per question with `is_correct` flags.
16. `quiz_result`: User assessment scores, percentages, and pass/fail records.

---

## ☁️ Supabase Cloud PostgreSQL Setup

KingaMail connects to Supabase Cloud PostgreSQL using **SQLAlchemy only** (no Supabase SDK or Supabase Auth).

### `DATABASE_URL` Format
Configure in `.env` using the transaction pooler URL (Port 6543):
```text
DATABASE_URL=postgresql://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres?sslmode=require
```

### Migration Commands (Flask-Migrate / Alembic)
```bash
# Generate migration from models.py changes
flask db migrate -m "migration description"

# Apply pending migrations to Supabase
flask db upgrade
```

---

## 🚀 Quickstart & Demo Credentials

### 1. Environment Configuration
```bash
# Clone and enter workspace
cd /home/nomad/kingamail

# Activate virtual environment
source .venv/bin/activate

# Seed database with initial roles, departments, demo users, and emails
python seed.py
```

### 2. Demo User Logins

| Role | Email Address | Password | Department | Landing View |
| :--- | :--- | :--- | :--- | :--- |
| **IT Admin** | `admin@corporate.local` | `Admin123!` | Information Technology | `/dashboard/admin` |
| **Manager** | `manager@corporate.local` | `Manager123!` | Sales & Operations | `/dashboard/manager` |
| **Employee** | `employee@corporate.local` | `Employee123!` | Finance & Accounting | `/emails/inbox` |
| **Compromised User** | `bob.miller@corporate.local` | `Employee123!` | Human Resources | `/auth/reset-password` |

### 3. Start Development Server
```bash
flask run --host=0.0.0.0 --port=5000
```

---

## 🧪 Test Verification Suite

Run the automated test suite directly against the live Supabase PostgreSQL database:

```bash
# Test Phase 2: Auth, Hashed 2FA OTP, Sessions, RBAC
python test_phase2.py

# Test Phase 3: Threat Detection & Mailbox Isolation
python test_phase3.py

# Test Phase 4: Incident Response & Threat Containment
python test_phase4.py

# Test Phase 5: Phishing Simulations & DB Quiz Assessments
python test_phase5.py

# Test Phase 6: Dashboards & Compliance CSV Exporter
python test_phase6.py

# Master Original Architecture & Kenyan Intelligence Suite
python test_original_suite.py
```
