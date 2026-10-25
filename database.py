"""
database.py - Database & Migration Extensions
---------------------------------------------
Student explanation:
This file initializes Flask-SQLAlchemy (`db`) and Flask-Migrate (`migrate`).
By defining them here, we decouple database objects from app.py to prevent
circular imports.

models.py is the single source of truth for all schema definitions.
Database modifications are tracked and applied using Flask-Migrate (Alembic).
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()


def init_db(app):
    """
    Binds SQLAlchemy and Flask-Migrate extensions to the Flask application.
    """
    db.init_app(app)
    with app.app_context():
        # Import models so Alembic autogenerate discovers all 14 models from models.py
        import models  # noqa: F401
    migrate.init_app(app, db)
