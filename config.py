"""
config.py - Application Configuration Module
---------------------------------------------
Student explanation:
This file loads configuration settings from environment variables (defined in .env)
into Python objects. Centralizing configuration here prevents hardcoding secrets
(like database passwords or encryption keys) directly into the code and allows
the app to easily switch between development and production environments.

DATABASE & MIGRATION ARCHITECTURE:
- models.py is the single source of truth for the database schema.
- The application connects to Supabase Cloud PostgreSQL using SQLAlchemy only
  (no Supabase SDK or Supabase Auth).
- DATABASE_URL: Main application runtime connection (Supabase Transaction Pooler, Port 6543).
  If missing, the application stops at startup with a clear error.
- MIGRATION_DATABASE_URI: Used by Flask-Migrate (Alembic) for DDL schema migrations
  (Supabase Session Pooler, Port 5432 or direct connection), falling back to DATABASE_URL
  if MIGRATION_DATABASE_URL is not set.

DETECTION ARCHITECTURE:
- Threat detection is fully rule-based, self-contained, and offline-capable.
- ENABLE_VIRUSTOTAL is False by default. When False, the app never calls VirusTotal
  or any external network service during scans.
- KNOWN_BAD_DOMAINS provides a fast, local blocklist evaluated alongside the database
  blocked_sender table.
"""

import os
import re
import urllib.parse
from datetime import timedelta

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Load variables from .env file into os.environ
# Includes a built-in fallback parser if run outside virtualenv without python-dotenv
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE_DIR, ".env"))
except ImportError:
    env_path = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v


def normalize_db_url(url: str) -> str:
    """
    Ensures PostgreSQL URLs use the 'postgresql+psycopg2://' SQLAlchemy driver prefix,
    automatically percent-encodes special characters (such as '@') in database passwords,
    and ensures 'sslmode=require' is present for Supabase cloud hosts.
    """
    if not url:
        return ""
    url = url.strip()

    # Normalize dialect prefix
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif url.startswith("postgresql://") and not url.startswith("postgresql+"):
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

    # Automatically handle unescaped characters in password (e.g. user:pass@word@host:port/db)
    match = re.match(r'^(?P<prefix>postgresql\+psycopg2://)(?P<user>[^:]+):(?P<pass>.+)@(?P<host>[^@/]+)(?P<rest>/.*)?$', url)
    if match:
        prefix = match.group('prefix')
        user = match.group('user')
        password = match.group('pass')
        host = match.group('host')
        rest = match.group('rest') or ''
        encoded_pass = urllib.parse.quote(urllib.parse.unquote(password), safe='')
        url = f'{prefix}{user}:{encoded_pass}@{host}{rest}'

    # Ensure sslmode=require for Supabase cloud endpoints
    if 'supabase.com' in url and 'sslmode=' not in url:
        separator = '&' if '?' in url else '?'
        url = f'{url}{separator}sslmode=require'

    return url


class Config:
    """Base configuration class containing shared settings."""

    # System branding - used throughout page titles, headers, and UI
    SYSTEM_NAME = os.getenv("SYSTEM_NAME", "KingaMail Corporate Shield")

    # Security: Secret key for session signing and CSRF tokens
    SECRET_KEY = os.getenv("SECRET_KEY", "kingamail-default-dev-secret-change-in-prod-2026")

    # Single DATABASE_URL read from .env - NO SQLite fallback
    raw_db_url = os.getenv("DATABASE_URL", "").strip()
    if not raw_db_url:
        raise RuntimeError(
            "FATAL CONFIG ERROR: DATABASE_URL environment variable is missing or empty in .env.\n"
            "KingaMail requires a valid Supabase Cloud PostgreSQL connection string to start.\n"
            "Example format (Supabase Transaction Pooler, Port 6543):\n"
            "  DATABASE_URL=postgresql://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres?sslmode=require"
        )

    SQLALCHEMY_DATABASE_URI = normalize_db_url(raw_db_url)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Migration connection URL: use MIGRATION_DATABASE_URL if set, fallback to DATABASE_URL
    raw_migration_url = os.getenv("MIGRATION_DATABASE_URL", "").strip()
    if raw_migration_url:
        MIGRATION_DATABASE_URI = normalize_db_url(raw_migration_url)
    else:
        MIGRATION_DATABASE_URI = SQLALCHEMY_DATABASE_URI

    # Connection pooling parameters (tuned for Supabase pooler compatibility)
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,  # Checks connection liveness before executing queries
        "pool_recycle": 300,    # Re-establish connections every 5 minutes
    }

    # Session Security settings (Server-side sessions, no Supabase Auth)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)  # 15-minute inactivity timeout
    SESSION_COOKIE_HTTPONLY = True                      # Mitigate XSS cookie theft
    SESSION_COOKIE_SAMESITE = "Lax"                     # Mitigate CSRF
    SESSION_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "False").lower() in ("true", "1", "t")

    # ─── THREAT DETECTION SETTINGS (SELF-CONTAINED & RULE-BASED) ───
    # External threat intelligence is strictly optional and disabled by default.
    ENABLE_VIRUSTOTAL = os.getenv("ENABLE_VIRUSTOTAL", "False").strip().lower() in ("true", "1", "t", "yes")

    # Only read API key from environment when explicitly enabled; otherwise keep empty
    if ENABLE_VIRUSTOTAL:
        VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    else:
        VIRUSTOTAL_API_KEY = ""

    # Demo Mode setting: Shows 2FA OTP codes on screen and logs to console (for demo only)
    DEMO_MODE = os.getenv("DEMO_MODE", "True").strip().lower() in ("true", "1", "t", "yes")

    # Trusted domain whitelist: internal corporate domain plus major service providers.
    # Emails from these domains are not penalised by check_trusted_domain.
    TRUSTED_DOMAINS = [
        "corporate.local", "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
        "icloud.com", "protonmail.com", "live.com", "github.com",
        "apple.com", "paypal.com", "amazon.com", "microsoft.com",
        "google.com", "facebook.com", "instagram.com", "twitter.com",
        "linkedin.com", "netflix.com", "spotify.com", "dropbox.com"
    ]

    # Local blocklist of known malicious / scam domains (evaluated offline)
    KNOWN_BAD_DOMAINS = [
        "micr0soft-support.xyz",
        "dhl-express-security.xyz",
        "stealth-drop.xyz",
        "scam-collect.top",
        "evil-phish.xyz",
        "secure-account-verify.cf",
        "paypal-security-update.com",
        "apple-id-verify.ml",
        "netflix-billing-update.tk",
        "banking-security-login.ga",
        "kra-portal.xyz",
        "safar1com-support.com",
        "mpesa-reversals.top",
        "ecitizen-verify.xyz",
        "kcb-auth.work"
    ]


class DevelopmentConfig(Config):
    """Configuration for local development."""
    DEBUG = True


class ProductionConfig(Config):
    """Configuration for production deployment."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True


# Default config mapping
config_dict = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig
}
