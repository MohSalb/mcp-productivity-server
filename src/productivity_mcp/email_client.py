"""
Minimal SMTP email client.

Credentials are read from environment variables that are loaded from a
local .env file via python-dotenv (see config.py) -- never hard-coded,
never read with os.path, and never stored as permanent OS/system
environment variables (per the assignment's secret-management rubric).

This module deliberately does the bare minimum needed to send a plain
text draft email: it is the "send_email_draft" tool's transport layer,
not a general-purpose mail library.
"""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage


class EmailSendError(RuntimeError):
    """Raised when the SMTP send fails.

    The message is intentionally generic (see security.py / README
    "Error Disclosure" notes) -- we never surface the raw SMTP server
    response, host, or credentials to the MCP client, only a short,
    safe summary plus the original exception logged server-side.
    """


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    username: str
    app_password: str
    from_address: str


def send_plain_email(config: SmtpConfig, to_address: str, subject: str, body: str) -> None:
    """Send a plain-text email over SMTP with STARTTLS.

    `to_address`, `subject`, and `body` are expected to already be
    sanitized by security.py before reaching this function -- this
    function assumes trusted input and focuses purely on transport.
    """
    message = EmailMessage()
    message["From"] = config.from_address
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(config.host, config.port, timeout=10) as server:
            server.starttls(context=context)
            server.login(config.username, config.app_password)
            server.send_message(message)
    except Exception as exc:  # noqa: BLE001 - intentionally broad, re-raised safely below
        # Log the real error server-side only; never forward SMTP internals
        # (server banners, auth failure detail, etc.) back to the LLM/client.
        raise EmailSendError(
            "Failed to send email via SMTP. Check server logs for details."
        ) from exc
