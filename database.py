"""Database models and initialization."""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def utc_now():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now)
    is_demo = db.Column(db.Boolean, default=False)
    scans = db.relationship("Scan", backref="user", cascade="all, delete-orphan", lazy=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    language = db.Column(db.String(20), nullable=False)
    code_snippet = db.Column(db.Text, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    issues_count = db.Column(db.Integer, nullable=False)
    issues_json = db.Column(db.Text, nullable=True)  # JSON string of issues
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)

    def __repr__(self):
        return f"<Scan {self.id} score={self.score}>"
