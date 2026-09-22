"""
Configuration / secret loading.

Loads secrets from a local `.env` file (via python-dotenv) into the
process environment at startup, and exposes them through a small
dataclass rather than sprinkling `os.environ` lookups throughout the
codebase. All filesystem paths use pathlib.Path, never os.path, per
the assignment's secret-management rubric.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"
DATA_DIR = PROJECT_ROOT / "data"
TASKS_FILE = DATA_DIR / "tasks.json"


@dataclass(frozen=True)
class Settings:
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_app_password: str
    smtp_from_address: str
    rate_limit_max_calls: int
    rate_limit_window_seconds: float


def load_settings() -> Settings:
    """Load settings from .env (if present) plus process environment.

    Missing SMTP credentials do not crash the whole server (the task
    tools should still work without email configured) -- the
    send_email_draft tool raises a clear, actionable error at call
    time instead if credentials are missing.
    """
    load_dotenv(dotenv_path=ENV_PATH)

    return Settings(
        smtp_host=os.environ.get("SMTP_HOST", "smtp.gmail.com"),
        smtp_port=int(os.environ.get("SMTP_PORT", "587")),
        smtp_username=os.environ.get("SMTP_USERNAME", ""),
        smtp_app_password=os.environ.get("SMTP_APP_PASSWORD", ""),
        smtp_from_address=os.environ.get("SMTP_FROM_EMAIL", ""),
        rate_limit_max_calls=int(os.environ.get("RATE_LIMIT_MAX_CALLS", "5")),
        rate_limit_window_seconds=float(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60")),
    )
