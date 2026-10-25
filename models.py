"""
models.py - Database Models (Entities)
---------------------------------------
Student explanation:
This file defines the Object-Relational Mapping (ORM) models for the system.
Each class corresponds to a table in the PostgreSQL database. SQLAlchemy converts
Python class instances into database rows and allows querying using Python code
without writing raw SQL strings, which also prevents SQL injection attacks.
"""

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from database import db


class Department(db.Model):
    """
    Department Model:
    Represents organizational units within the corporate enterprise
    (e.g., Information Technology, Finance, Human Resources).
    """
    __tablename__ = "department"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)  # e.g., 'IT', 'FIN', 'HR'
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    users = db.relationship("User", backref="department", lazy=True)

    def __repr__(self):
        return f"<Department {self.code} - {self.name}>"


class Role(db.Model):
    """
    Role Model:
    Defines system permission levels: 'Employee', 'IT Admin', and 'Manager'.
    Used by RBAC (Role-Based Access Control) decorators to secure routes.
    """
    __tablename__ = "role"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # 'Employee', 'IT Admin', 'Manager'
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    users = db.relationship("User", backref="role", lazy=True)

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model):
    """
    User Model:
    Stores corporate user accounts with secure password hashing,
    OTP state for two-factor authentication, account status, and role assignment.
    Status can be:
      - 'active': normal operation
      - 'locked': too many failed login attempts or manually locked
      - 'compromised': victim of a confirmed phishing attack (requires forced password reset)
    """
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("department.id"), nullable=True)

    # Account status: active, locked, compromised
    status = db.Column(db.String(20), default="active", nullable=False)

    # 2FA One-Time Passcode (OTP) fields
    otp_code = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)

    # Security flags
    force_password_reset = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    emails = db.relationship("Email", backref="recipient", lazy=True, foreign_keys="Email.recipient_id")
    login_logs = db.relationship("LoginLog", backref="user", lazy=True)
    reports_submitted = db.relationship("Report", backref="reporter", lazy=True, foreign_keys="Report.reported_by_user_id")
    simulation_results = db.relationship("SimResult", backref="user", lazy=True)
    quiz_results = db.relationship("QuizResult", backref="user", lazy=True)
    alert_receipts = db.relationship("AlertRecipient", backref="user", lazy=True)

    def set_password(self, password):
        """Hashes the plain password securely using PBKDF2/SHA256."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifies a plain password against the stored password hash."""
        return check_password_hash(self.password_hash, password)

    def is_active(self):
        return self.status == "active"

    def is_locked(self):
        return self.status == "locked"

    def is_compromised(self):
        return self.status == "compromised"

    def has_role(self, role_name):
        """Checks if user possesses a specific role name."""
        return self.role.name == role_name if self.role else False

    def __repr__(self):
        return f"<User {self.email} ({self.status})>"


class LoginLog(db.Model):
    """
    LoginLog Model:
    Audit trail recording all authentication attempts (successful or failed),
    capturing source IP address, user-agent, and failure reasons.
    """
    __tablename__ = "login_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    email_attempted = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # 'success', 'failed', 'locked_blocked'
    failure_reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<LoginLog {self.email_attempted} - {self.status}>"


class Email(db.Model):
    """
    Email Model:
    Represents an inbox item received by a user.
    Stores sender details, message body, calculated risk score,
    detection indicators, security verdict, and inbox/quarantined status.
    """
    __tablename__ = "email"

    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    sender = db.Column(db.String(255), nullable=False)
    reply_to = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)

    # Heuristic detection results
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    verdict = db.Column(db.String(20), default="Safe", nullable=False)  # 'Safe', 'Suspicious', 'Quarantine'
    confidence = db.Column(db.String(20), default="Low", nullable=False)  # 'Low', 'Medium', 'High'
    indicators = db.Column(db.JSON, nullable=True)  # Structured array of triggered rules and findings

    # State in employee's mail viewer
    status = db.Column(db.String(20), default="inbox", nullable=False)  # 'inbox', 'quarantined'
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    is_reported = db.Column(db.Boolean, default=False, nullable=False)
    received_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    reports = db.relationship("Report", backref="email", lazy=True)

    def __repr__(self):
        return f"<Email #{self.id} '{self.subject}' [{self.verdict} - {self.status}]>"


class BlockedSender(db.Model):
    """
    BlockedSender Model:
    Enterprise blacklist containing malicious sender addresses or domains.
    Future emails from these senders can be automatically quarantined or dropped.
    """
    __tablename__ = "blocked_sender"

    id = db.Column(db.Integer, primary_key=True)
    sender_value = db.Column(db.String(255), unique=True, nullable=False)  # email address or domain
    blocked_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    blocked_by = db.relationship("User", foreign_keys=[blocked_by_user_id])

    def __repr__(self):
        return f"<BlockedSender {self.sender_value}>"


class Report(db.Model):
    """
    Report Model:
    Created when an employee clicks 'Report Phishing' on a suspicious email.
    IT administrators review reports to triage genuine attacks vs false alarms.
    """
    __tablename__ = "report"

    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey("email.id"), nullable=True)
    reported_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    report_reason = db.Column(db.Text, nullable=True)

    # Admin Triage status
    admin_verdict = db.Column(db.String(20), default="pending", nullable=False)  # 'pending', 'phishing', 'safe', 'spam'
    reviewed_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    reviewer = db.relationship("User", foreign_keys=[reviewed_by_user_id])
    incidents = db.relationship("Incident", backref="source_report", lazy=True)

    def __repr__(self):
        return f"<Report #{self.id} by User {self.reported_by_user_id} - Verdict: {self.admin_verdict}>"


class Incident(db.Model):
    """
    Incident Model:
    Security Incident Response record created when an admin confirms a phishing report.
    Tracks severity, investigation status, victim accounts, actions taken, and audit notes.
    """
    __tablename__ = "incident"

    id = db.Column(db.Integer, primary_key=True)
    incident_number = db.Column(db.String(50), unique=True, nullable=False)  # e.g., 'INC-2026-0001'
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default="medium", nullable=False)  # 'low', 'medium', 'high', 'critical'
    status = db.Column(db.String(20), default="open", nullable=False)  # 'open', 'in_progress', 'resolved', 'closed'

    report_id = db.Column(db.Integer, db.ForeignKey("report.id"), nullable=True)
    affected_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # Chronological log of incident response actions taken
    actions_log = db.Column(db.JSON, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    affected_user = db.relationship("User", foreign_keys=[affected_user_id])
    created_by = db.relationship("User", foreign_keys=[created_by_user_id])
    alerts = db.relationship("Alert", backref="incident", lazy=True)

    def __repr__(self):
        return f"<Incident {self.incident_number} - {self.title} ({self.status})>"


class Campaign(db.Model):
    """
    Campaign Model:
    Phishing awareness simulation campaigns scheduled by security administrators.
    Simulated attacks test employee readiness without risking actual security breach.
    """
    __tablename__ = "campaign"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    template_subject = db.Column(db.String(255), nullable=False)
    template_body = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="draft", nullable=False)  # 'draft', 'active', 'completed'

    created_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    start_date = db.Column(db.DateTime, nullable=True)
    end_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    created_by = db.relationship("User", foreign_keys=[created_by_user_id])
    results = db.relationship("SimResult", backref="campaign", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Campaign #{self.id} '{self.name}'>"


class SimResult(db.Model):
    """
    SimResult Model:
    Tracks individual employee interactions with a simulated phishing campaign.
    Uses unique tracking tokens to measure click-through rates and whether
    the employee reported the simulated threat. Never captures typed credentials.
    """
    __tablename__ = "sim_result"

    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaign.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    tracking_token = db.Column(db.String(64), unique=True, nullable=False, index=True)

    sent_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_clicked = db.Column(db.Boolean, default=False, nullable=False)
    clicked_at = db.Column(db.DateTime, nullable=True)
    is_reported = db.Column(db.Boolean, default=False, nullable=False)
    reported_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<SimResult Camp:{self.campaign_id} User:{self.user_id} Clicked:{self.is_clicked}>"


class TrainingModule(db.Model):
    """
    TrainingModule Model:
    Educational security content (lessons and awareness topics) presented
    to employees to educate them on phishing vectors and safe email handling.
    """
    __tablename__ = "training_module"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default="Phishing Awareness", nullable=False)
    estimated_minutes = db.Column(db.Integer, default=10, nullable=False)
    difficulty = db.Column(db.String(20), default="Beginner", nullable=False)  # 'Beginner', 'Intermediate', 'Advanced'
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    quiz_results = db.relationship("QuizResult", backref="module", lazy=True)

    def __repr__(self):
        return f"<TrainingModule #{self.id} '{self.title}'>"


class QuizResult(db.Model):
    """
    QuizResult Model:
    Stores quiz completion records and test scores when an employee completes
    a security awareness assessment.
    """
    __tablename__ = "quiz_result"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    training_module_id = db.Column(db.Integer, db.ForeignKey("training_module.id"), nullable=False)
    score = db.Column(db.Integer, nullable=False)  # e.g., percentage 0-100
    total_questions = db.Column(db.Integer, default=5, nullable=False)
    correct_answers = db.Column(db.Integer, default=4, nullable=False)
    passed = db.Column(db.Boolean, default=True, nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<QuizResult User:{self.user_id} Mod:{self.training_module_id} Score:{self.score}%>"


class Alert(db.Model):
    """
    Alert Model:
    Company-wide or targeted security broadcast issued by IT security
    (e.g., active credential harvesting campaign detected across organization).
    """
    __tablename__ = "alert"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default="warning", nullable=False)  # 'info', 'warning', 'danger'
    incident_id = db.Column(db.Integer, db.ForeignKey("incident.id"), nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    created_by = db.relationship("User", foreign_keys=[created_by_user_id])
    recipients = db.relationship("AlertRecipient", backref="alert", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Alert #{self.id} '{self.title}' [{self.severity}]>"


class AlertRecipient(db.Model):
    """
    AlertRecipient Model:
    Tracks receipt and read acknowledgment of an alert for each individual user.
    """
    __tablename__ = "alert_recipient"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alert.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    read_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<AlertRecipient Alert:{self.alert_id} User:{self.user_id} Read:{self.is_read}>"
