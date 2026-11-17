# KingaMail Corporate Shield — Cloud Deployment Guide (Railway)

This guide documents deploying the complete **KingaMail Corporate Shield** platform (Flask web application + PostgreSQL database) to **Railway**.

---

## 1. Production Files Included in This Repository

| File | Purpose |
| :--- | :--- |
| [requirements.txt](requirements.txt) | Adds `gunicorn>=22.0.0` alongside `Flask>=3.1.0`, `Flask-SQLAlchemy>=3.1.0`, `Flask-Migrate>=4.1.0`, `SQLAlchemy>=2.0.0`, `psycopg2-binary>=2.9.9`, `python-dotenv>=1.0.0`, `requests>=2.31.0`, and `Werkzeug>=3.0.0`. |
| [Procfile](Procfile) | Runs `flask db upgrade && python seed.py && exec gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120 app:app`. |
| [.railwayignore](.railwayignore) | Excludes `.env`, virtual environments (`.venv/`, `venv/`, `.sitonik/`), `__pycache__/`, SQLite files, and `university_docs/` from deployment archives. |
| [app.py](app.py) | Wraps the WSGI app in Werkzeug `ProxyFix` so HTTPS reverse-proxy headers (`X-Forwarded-Proto`, `X-Forwarded-For`, `X-Forwarded-Host`) work cleanly on Railway. |

---

## 2. Cloud Architecture on Railway

- **Project:** `kingamail-corporate-shield` (`production` environment)
- **Database Service (`Postgres`):** Managed PostgreSQL 18 container with persistent `/var/lib/postgresql/data` volume (`ghcr.io/railwayapp-templates/postgres-ssl:18`).
- **Web Service (`kingamail-web`):** Python 3.12 (Railpack build) serving Flask through Gunicorn over HTTPS (`/health` readiness probe).
- **Private Database Routing:** `kingamail-web` communicates with `Postgres` over Railway's private network via `${{Postgres.DATABASE_URL}}`. `normalize_db_url()` in `config.py` converts `postgres://` to `postgresql+psycopg2://` automatically.

---

## 3. Required Environment Variables (`kingamail-web`)

| Variable | Value / Source | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` | Main SQLAlchemy PostgreSQL connection (fails fast if missing) |
| `MIGRATION_DATABASE_URL` | `${{Postgres.DATABASE_URL}}` | Alembic connection string used by `flask db upgrade` |
| `SECRET_KEY` | Strong 64-char random hex string | Session cookie signing & CSRF protection |
| `FLASK_APP` | `app.py` | Flask CLI entrypoint for `flask db upgrade` |
| `FLASK_ENV` | `production` | Enables `ProductionConfig` (`DEBUG=False`, `SESSION_COOKIE_SECURE=True`) |
| `COOKIE_SECURE` | `True` | Enforces HTTPS-only session cookies |
| `DEMO_MODE` | `True` | Displays generated 6-digit 2FA OTPs on-screen and in logs for live demos |
| `ENABLE_VIRUSTOTAL` | `False` | Keeps the 12 Kenyan heuristic rules 100% offline & self-contained |
| `SYSTEM_NAME` | `KingaMail Corporate Shield` | Global UI title, sidebar, and login screen branding |
| `RAILPACK_PYTHON_VERSION` | `3.12` | Pins Python 3.12 for prebuilt `psycopg2-binary` wheel compatibility |

---

## 4. Deploying From Local Workspace (Railway CLI)

1. Install the Railway CLI (if not already installed):
   ```bash
   curl -fsSL https://railway.com/install.sh | sh
   ```
2. Sign in to Railway:
   ```bash
   railway login
   ```
3. Link and deploy the workspace to `kingamail-web`:
   ```bash
   railway up --project ca42b1fb-f537-4251-8db8-f6c04423a732 --environment production --service e07fceb4-714d-4fd1-b814-7c5e90cda1b7 --detach
   ```
4. Verify deployment status and logs:
   ```bash
   railway deployment list --project ca42b1fb-f537-4251-8db8-f6c04423a732 --service kingamail-web --environment production --json
   railway logs --project ca42b1fb-f537-4251-8db8-f6c04423a732 --service kingamail-web --lines 100 --json
   ```

---

## 5. First-Boot Migrations, Seeding & Verification

Because `Procfile` chains `flask db upgrade && python seed.py` idempotently before starting Gunicorn:
- All **3 Alembic revisions** (`857b527918a8`, `60b452761b66`, `bfaa1479c244`) apply automatically on first boot to create all **16 tables**.
- `seed.py` creates demo records only if absent (`roles`, `departments`, `4` demo accounts, `5` sample emails, `3` modules × `5` quiz questions = `15` questions, and `1` blocked sender).

### Health & Login Verification
- **Live Public URL:** https://kingamail-web-production.up.railway.app
- Verify health endpoint:
  ```bash
  curl -fsS https://kingamail-web-production.up.railway.app/health
  ```
  Verified JSON response:
  `{"status":"healthy","system_name":"KingaMail Corporate Shield","version":"1.0.0"}`
- Demo Credentials after seeding:
  - **IT Admin:** `admin@corporate.local` / `Admin123!`
  - **Department Manager:** `manager@corporate.local` / `Manager123!`
  - **Employee:** `employee@corporate.local` / `Employee123!`
  - **Compromised Demo:** `bob.miller@corporate.local` / `Employee123!` (triggers forced password reset)

---

## 6. Using External Supabase PostgreSQL Instead (Optional)

If you prefer keeping **Supabase Cloud PostgreSQL** instead of Railway Postgres:
1. Replace `DATABASE_URL` with the Supabase **Transaction Pooler** URI (port `6543`, `?sslmode=require`).
2. Replace `MIGRATION_DATABASE_URL` with the Supabase **Session Pooler** URI (port `5432`, `?sslmode=require`).
3. Ensure the Supabase project is active (unpaused) and RLS policies are configured after running `flask db upgrade`.
