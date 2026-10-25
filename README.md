# 🛡️ PhishShield — Intelligent Email Security and Awareness System

A corporate, web-based email security operations and human layer awareness platform built with **Python Flask**, **SQLAlchemy**, **Flask-Migrate (Alembic)**, and **Supabase Cloud PostgreSQL**.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Self-Contained Rule-Based Detection Engine](#-self-contained-rule-based-detection-engine)
  - [Local Blocklist Rule (`check_blocklist`)](#local-blocklist-rule-check_blocklist)
  - [Optional External Threat Intelligence (`ENABLE_VIRUSTOTAL`)](#optional-external-threat-intelligence-enable_virustotal)
- [Single Source of Truth (`models.py`)](#-single-source-of-truth-modelspy)
- [Database Migrations (Flask-Migrate / Alembic)](#-database-migrations-flask-migrate--alembic)
  - [Generating Migrations (`flask db migrate`)](#1-generate-a-new-migration)
  - [Applying Migrations (`flask db upgrade`)](#2-apply-migrations)
  - [Enabling Row Level Security (RLS) After Upgrade](#3-enable-row-level-security-rls-after-upgrade)
- [Supabase Cloud Postgres Setup](#-supabase-cloud-postgres-setup)
  - [`DATABASE_URL` vs. `MIGRATION_DATABASE_URL`](#database_url-vs-migration_database_url)
  - [How to Find the Pooler URLs in Supabase Dashboard](#how-to-find-the-pooler-urls-in-supabase-dashboard)
- [Supabase Row Level Security (RLS) Policy Guide](#-supabase-row-level-security-rls-policy-guide)
- [Demo Accounts & Seeding](#-demo-accounts--seeding)
- [How to Run (Quickstart)](#-how-to-run-quickstart)
- [14 Database Tables](#-14-database-tables)
- [Implementation Roadmap](#-implementation-roadmap)

---

## 🔍 Overview

**PhishShield** transitions a rule-based phishing analyzer into a comprehensive enterprise email security and workforce awareness platform.

> [!IMPORTANT]
> **Fully Rule-Based & Self-Contained:**
> Detection is **100% rule-based and self-contained**:
> - **NO machine learning models** are used; scoring is transparent, explainable, and deterministic.
> - **NO external network services** are called during standard operation. All checks run locally using heuristic patterns, regular expressions, the `KNOWN_BAD_DOMAINS` list in `config.py`, and the `blocked_sender` database table.
> - **Zero Supabase SDK / Auth:** Communicates with Supabase Cloud PostgreSQL using **SQLAlchemy only**. Authentication, sessions, and RBAC are handled natively in Flask.

---

## 🛡️ Self-Contained Rule-Based Detection Engine

All email analysis logic is isolated in the `detection/` module and runs completely offline.

### 12 Local Heuristic Rules:

| # | Rule Name | Function | Points Contributed |
| :- | :--- | :--- | :- |
| 1 | **Local Blocklist** | `check_blocklist` | **+50 to +80 pts** (Checks sender domain & embedded links against `KNOWN_BAD_DOMAINS` and `blocked_sender` table) |
| 2 | **Trusted Domain** | `check_trusted_domain` | **+20 pts** (Adds risk score if sender domain is not on corporate trusted whitelist) |
| 3 | **Typosquatting** | `check_typosquatting` | **+40 pts** (Replaces homoglyphs like `0`$\to$`o`, `1`$\to$`l`, `rn`$\to$`m` to catch brand impersonation) |
| 4 | **Reply-To Mismatch** | `check_reply_to_mismatch` | **+35 pts** (Flags return-path hijacking if From base domain $\ne$ Reply-To base domain) |
| 5 | **Artificial Urgency** | `check_urgency` | **+15 to +45 pts** (Scans for panic deadlines like "account will be closed in 24 hours") |
| 6 | **Credential Harvesting** | `check_sensitivity` | **+30 to +60 pts** (Flags requests for passwords, SSN, bank accounts, PINs) |
| 7 | **Suspicious Links** | `check_suspicious_links` | **+25 to +50 pts** (Flags raw IPs, shorteners, risky TLDs, and multi-hyphen patterns) |
| 8 | **Fraudulent Lures** | `check_too_good` | **+25 to +50 pts** (Flags lottery, unclaimed inheritance, and cash prize phrases) |
| 9 | **Psychological Secrecy** | `check_manipulation` | **+20 to +40 pts** (Flags isolation coercion like "keep this confidential", "between us") |
| 10 | **Brand Impersonation** | `check_brand_impersonation` | **+40 pts** (Flags famous brand names in text when sent from unofficial domains) |
| 11 | **Formatting Anomalies** | `check_formatting` | **+10 to +30 pts** (Detects excessive exclamation marks, question marks, and ALL CAPS) |
| 12 | **Financial Scam Signals** | `check_money_scam` | **+25 to +50 pts** (Flags stimulus keywords and prominent dollar figures) |

### Local Blocklist Rule (`check_blocklist`)

The local blocklist rule evaluates two sources offline:
1. `Config.KNOWN_BAD_DOMAINS` in `config.py` (e.g. `micr0soft-support.xyz`, `dhl-express-security.xyz`, `evil-phish.xyz`).
2. The dynamic `blocked_sender` database table, populated when administrators block malicious senders during incident triage.

If the sender domain or any link host in the body matches the blocklist, the rule triggers immediately (+60 to +80 pts), driving the email straight into **Quarantine**.

### Optional External Threat Intelligence (`ENABLE_VIRUSTOTAL`)

External threat intelligence is **strictly optional and disabled by default**:
* `ENABLE_VIRUSTOTAL = False` in `config.py` (read from `ENABLE_VIRUSTOTAL` in `.env`).
* When `ENABLE_VIRUSTOTAL` is `False`, `VIRUSTOTAL_API_KEY` is not loaded and the scanner **never calls VirusTotal or any external service**.
* Only if explicitly set to `True` with a valid key in `.env` will the scanner optionally query VirusTotal endpoints for domain and URL reputation.

---

## 🏛️ Single Source of Truth (`models.py`)

[models.py](file:///home/nomad/kingamail/models.py) is the **single source of truth** for all database schema definitions. Hand-maintained `schema.sql` files have been removed; all database tables, columns, indexes, and constraints are defined in `models.py` and managed via **Flask-Migrate (Alembic)**.

---

## ⚙️ Database Migrations (Flask-Migrate / Alembic)

All schema changes are tracked as reproducible Python version scripts inside the `migrations/` directory.

### 1. Generate a New Migration
When you modify or add models in `models.py`, generate a new migration file:
```bash
source .venv/bin/activate
flask db migrate -m "describe schema change here"
```

### 2. Apply Migrations
To execute pending migration scripts against your Supabase database:
```bash
source .venv/bin/activate
flask db upgrade
```
Migrations will automatically connect using `MIGRATION_DATABASE_URL` (port `5432` Session Pooler), falling back to `DATABASE_URL` if not set.

### 3. Enable Row Level Security (RLS) After Upgrade

> [!WARNING]
> **RLS Activation Required Post-Upgrade:**
> After executing `flask db upgrade` on a fresh database or adding new tables, **Row Level Security (RLS) must be enabled on all tables** in Supabase to enforce data privacy and zero-trust security.

Run this SQL snippet in the **Supabase Dashboard $\to$ SQL Editor**:

```sql
-- Enable Row Level Security on all 14 application tables
ALTER TABLE "department" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "role" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "user" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "login_log" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "email" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "blocked_sender" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "report" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "incident" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "campaign" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "sim_result" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "training_module" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "quiz_result" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "alert" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "alert_recipient" ENABLE ROW LEVEL SECURITY;
```

---

## ☁️ Supabase Cloud Postgres Setup

The application reads its database connections from your `.env` file. There is **no SQLite fallback**; if `DATABASE_URL` is missing, the application halts at startup with a fatal configuration error.

### `DATABASE_URL` vs. `MIGRATION_DATABASE_URL`

| Variable | Target & Port | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | **Transaction Pooler (Port `6543`)** | **Required.** Main runtime web application queries. Optimizes connection scaling and prevents connection exhaustion. |
| `MIGRATION_DATABASE_URL` | **Session Pooler (Port `5432`)** | **Recommended.** Used by `flask db migrate` and `flask db upgrade`. DDL statements and migration locking require session-level connection features. Falls back to `DATABASE_URL` if omitted. |

#### Connection String Formats:

```env
# Application Runtime (Transaction Pooler - Port 6543)
DATABASE_URL=postgresql://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres?sslmode=require

# Alembic Migrations (Session Pooler - Port 5432)
MIGRATION_DATABASE_URL=postgresql://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:5432/postgres?sslmode=require
```

> [!TIP]
> Special characters in database passwords (such as `@`) are automatically percent-encoded by `normalize_db_url()` in `config.py` (e.g. `@` becomes `%40`), preventing URI parsing errors.

---

## 👥 Demo Accounts & Seeding

After running `flask db upgrade`, populate demo accounts and sample emails via `seed.py`:

```bash
source .venv/bin/activate
python seed.py
```

All seeded passwords are encrypted with **PBKDF2/SHA-256** (`werkzeug.security`):

| Role | Demo Email Address | Password | Department | Account Status |
| :--- | :--- | :--- | :--- | :--- |
| **Employee** | `employee@corporate.local` | `Employee123!` | Finance & Accounting | `active` |
| **IT Admin** | `admin@corporate.local` | `Admin123!` | Information Technology | `active` |
| **Manager** | `manager@corporate.local` | `Manager123!` | Sales & Operations | `active` |
| **Employee (Compromised)** | `bob.miller@corporate.local` | `Employee123!` | Human Resources | `compromised` *(Force Reset)* |

---

## 🚀 How to Run (Quickstart)

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Apply database migrations to Supabase Postgres
flask db upgrade

# 4. Populate seed data
python seed.py

# 5. Start the web application
python app.py
```

Visit **http://localhost:5000** in your browser.

---

## 🗺️ Implementation Roadmap

- [x] **Phase 1: Foundation, Migrations & Self-Contained Detection (COMPLETED)**
  - Application factory architecture (`app.py`, `config.py`, `database.py`, `models.py`)
  - `models.py` as single source of truth
  - Flask-Migrate (Alembic) initialized with initial migration
  - `MIGRATION_DATABASE_URL` (Port 5432) with fallback to `DATABASE_URL` (Port 6543)
  - Fully self-contained detection engine with local blocklist rule (`check_blocklist`)
  - `ENABLE_VIRUSTOTAL` optional toggle (default `False`, zero external calls)
  - Seed script (`seed.py`) with hashed demo credentials
- [ ] **Phase 2: Authentication & RBAC (STOPPING FOR USER TEST)**
  - Password verification with hashing
  - 2FA one-time passcode second step
  - 15-minute inactivity session timeout
  - Role-based route decorators & login audit logging
- [ ] **Phase 3: Threat Detection & Mailbox UI**
- [ ] **Phase 4: Incident Response Workflow**
- [ ] **Phase 5: Phishing Awareness & Simulation Engine**
- [ ] **Phase 6: Executive Dashboards & CSV Reporting**
