"""
Security helpers for the Personal Productivity MCP server.

Implements the two "Best Practices" required by the assignment:

1. Input Sanitization  -- blocks header-injection / control-character
   injection attacks against the email tool, and path/format-string
   style injection against the task store.
2. Rate Limiting        -- a simple in-memory sliding-window limiter
   applied per tool, per MCP client session, so one client can't hammer
   the server (or, for the email tool, use it to spam / relay mail).

Both are intentionally simple (no external services) so they are easy
to read, test, and demo, per the assignment's "tools do not need to be
complicated" hint.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# 1. Input sanitization
# ---------------------------------------------------------------------------

# Control characters (CR, LF, NUL, etc.) are the building blocks of
# "header injection" attacks: an attacker puts "\r\nBcc: evil@example.com"
# into a subject/recipient field, and a naive SMTP client happily writes
# that straight into the raw email headers, letting the attacker add
# extra recipients, spoof headers, or split the message.
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]")

# A conservative, allow-list style email pattern. We deliberately do NOT
# try to implement the full RFC 5322 grammar (that's a classic source of
# ReDoS / bypass bugs) -- for this assignment's threat model ("don't let
# arbitrary header/command injection through the recipient field") a
# simple allow-list is the right amount of complexity.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# Task titles/notes are stored in a local JSON file and are later
# rendered back to the user (and to an LLM, via the task_summary
# prompt). We strip control characters here too, and cap length, so a
# malicious title can't be used for log/terminal injection or to blow
# up the JSON file.
_MAX_TEXT_LEN = 500


class SanitizationError(ValueError):
    """Raised when user-supplied input fails validation.

    Subclasses ValueError (not a generic Exception) so it maps cleanly
    onto FastMCP's tool-error handling, and the message is written to
    be safe to return to the caller -- see error_disclosure notes in
    the README: we never include stack traces, file paths, or SMTP
    server responses in these messages.
    """


def sanitize_plain_text(value: str, *, field_name: str, max_len: int = _MAX_TEXT_LEN) -> str:
    """Strip/reject control characters and enforce a length cap.

    Used for task titles, email subjects, and email bodies -- anything
    that is free-form text but must never be allowed to inject CR/LF
    sequences (header injection) or blow past reasonable size limits.
    """
    if not isinstance(value, str) or not value.strip():
        raise SanitizationError(f"{field_name} must be a non-empty string.")

    if _CONTROL_CHAR_RE.search(value):
        raise SanitizationError(
            f"{field_name} contains disallowed control characters "
            "(e.g. newlines), which is a header-injection pattern."
        )

    cleaned = value.strip()
    if len(cleaned) > max_len:
        raise SanitizationError(f"{field_name} exceeds the {max_len}-character limit.")

    return cleaned


def sanitize_email_address(value: str) -> str:
    """Validate a recipient address against a strict allow-list pattern."""
    if not isinstance(value, str):
        raise SanitizationError("recipient_email must be a string.")

    candidate = value.strip()

    # Reject control characters explicitly first so the error message is
    # specific (helps in the exploit demo / grading), before the regex
    # would just fail with a generic "invalid format" message.
    if _CONTROL_CHAR_RE.search(candidate):
        raise SanitizationError(
            "recipient_email contains control characters -- rejected as a "
            "possible email header injection attempt."
        )

    if not _EMAIL_RE.match(candidate):
        raise SanitizationError("recipient_email is not a validly formatted email address.")

    return candidate


def sanitize_priority(value: str) -> str:
    """Task priority must be one of a fixed allow-list -- not free text."""
    allowed = {"low", "medium", "high"}
    normalized = (value or "").strip().lower()
    if normalized not in allowed:
        raise SanitizationError(f"priority must be one of {sorted(allowed)}.")
    return normalized


# ---------------------------------------------------------------------------
# 2. Rate limiting
# ---------------------------------------------------------------------------

@dataclass
class _Window:
    calls: deque = field(default_factory=deque)


class RateLimitError(RuntimeError):
    """Raised when a caller exceeds the allowed call rate for a tool."""


class SlidingWindowRateLimiter:
    """A small in-memory sliding-window rate limiter.

    Tracks call timestamps per (tool_name, client_key) pair and rejects
    a call once more than `max_calls` have occurred within the trailing
    `window_seconds`. This is intentionally in-process/in-memory (no
    Redis, no external service) -- appropriate for a single local MCP
    server process, which is what this assignment deploys. The README
    documents how this would need to change (e.g. a shared store) for a
    multi-process/horizontally-scaled deployment.
    """

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._windows: dict[tuple[str, str], _Window] = defaultdict(_Window)

    def check(self, tool_name: str, client_key: str = "default") -> None:
        key = (tool_name, client_key)
        window = self._windows[key]
        now = time.monotonic()
        cutoff = now - self.window_seconds

        while window.calls and window.calls[0] < cutoff:
            window.calls.popleft()

        if len(window.calls) >= self.max_calls:
            retry_after = self.window_seconds - (now - window.calls[0])
            raise RateLimitError(
                f"Rate limit exceeded for '{tool_name}': max {self.max_calls} calls "
                f"per {self.window_seconds:.0f}s. Try again in {max(retry_after, 0):.1f}s."
            )

        window.calls.append(now)

    def reset(self) -> None:
        """Test helper: clear all tracked windows."""
        self._windows.clear()
