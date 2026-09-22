"""
Personal Productivity MCP server.

Domain: Personal Productivity (task tracking + email summarization/drafting).

Implements the "two tools and a prompt" pattern required by the
assignment:

  Tools:
    - add_task            : create a task in a local JSON task list
    - send_email_draft     : send a plain-text email (e.g. a task
                              summary) via authenticated SMTP

  Prompt:
    - task_summary_prompt  : a reusable prompt template an MCP client
                              can pull to ask an LLM to summarize and
                              prioritize the current task list

Best practices implemented (see security.py for the implementations
and tests/test_exploits.py for the exploit demonstrations):
    A. Input Sanitization  -- blocks email header injection & enforces
                               an allow-list on task priority/email format
    B. Rate Limiting        -- sliding-window limiter per tool call

Reference: built against the official MCP Python SDK's FastMCP
high-level server API.
  https://github.com/modelcontextprotocol/python-sdk
The `@mcp.tool()` / `@mcp.prompt()` decorator pattern below follows the
SDK's own README "Quickstart" example (server construction, `mcp.tool()`,
`mcp.run()`), adapted to this assignment's domain/tools.
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from productivity_mcp.config import TASKS_FILE, load_settings
from productivity_mcp.email_client import EmailSendError, SmtpConfig, send_plain_email
from productivity_mcp.security import (
    RateLimitError,
    SanitizationError,
    SlidingWindowRateLimiter,
    sanitize_email_address,
    sanitize_plain_text,
    sanitize_priority,
)
from productivity_mcp.task_store import TaskStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("productivity_mcp")

settings = load_settings()
task_store = TaskStore(TASKS_FILE)
rate_limiter = SlidingWindowRateLimiter(
    max_calls=settings.rate_limit_max_calls,
    window_seconds=settings.rate_limit_window_seconds,
)

mcp = FastMCP(
    "personal-productivity",
    instructions=(
        "Tools for lightweight personal task tracking and sending short "
        "email drafts/summaries. Use add_task to record a task, "
        "task_summary_prompt to draft a prioritized summary of open "
        "tasks, and send_email_draft to email that summary (or any short "
        "message) to a recipient."
    ),
)


@mcp.tool()
def add_task(title: str, due_date: str | None = None, priority: str = "medium") -> dict:
    """Add a new task to the local task list.

    Args:
        title: Short description of the task (max 500 chars, no newlines).
        due_date: Optional due date as an ISO date string, e.g. "2026-10-01".
        priority: One of "low", "medium", "high". Defaults to "medium".

    Returns:
        A dict with the created task's fields, or an "error" key if the
        input failed validation or the rate limit was exceeded.
    """
    try:
        rate_limiter.check("add_task")
        clean_title = sanitize_plain_text(title, field_name="title")
        clean_priority = sanitize_priority(priority)
        clean_due_date = (
            sanitize_plain_text(due_date, field_name="due_date", max_len=32)
            if due_date
            else None
        )
    except (SanitizationError, RateLimitError) as exc:
        logger.warning("add_task rejected: %s", exc)
        return {"error": str(exc)}

    task = task_store.add_task(clean_title, clean_due_date, clean_priority)
    logger.info("Task added: %s", task.id)
    return {
        "id": task.id,
        "title": task.title,
        "due_date": task.due_date,
        "priority": task.priority,
        "created_at": task.created_at,
    }


@mcp.tool()
def list_open_tasks() -> dict:
    """List all open (not-yet-done) tasks currently in the task list."""
    try:
        rate_limiter.check("list_open_tasks")
    except RateLimitError as exc:
        return {"error": str(exc)}

    tasks = task_store.list_tasks(include_done=False)
    return {
        "count": len(tasks),
        "tasks": [
            {
                "id": t.id,
                "title": t.title,
                "due_date": t.due_date,
                "priority": t.priority,
            }
            for t in tasks
        ],
    }


@mcp.tool()
def send_email_draft(recipient_email: str, subject: str, body: str) -> dict:
    """Send a short plain-text email (e.g. a task summary) via SMTP.

    Requires SMTP_USERNAME / SMTP_APP_PASSWORD / SMTP_FROM_EMAIL to be
    configured in the server's .env file (see README.md). All three
    fields are sanitized before use to block email-header-injection
    attacks (e.g. a subject containing "\\r\\nBcc: attacker@example.com").

    Args:
        recipient_email: Destination address, must be a validly formatted
            single email address.
        subject: Email subject line (max 500 chars, no newlines).
        body: Email body text (max 500 chars, no newlines/control chars).

    Returns:
        A dict confirming the send, or an "error" key on failure.
    """
    try:
        rate_limiter.check("send_email_draft")
        clean_recipient = sanitize_email_address(recipient_email)
        clean_subject = sanitize_plain_text(subject, field_name="subject")
        clean_body = sanitize_plain_text(body, field_name="body", max_len=5000)
    except (SanitizationError, RateLimitError) as exc:
        logger.warning("send_email_draft rejected: %s", exc)
        return {"error": str(exc)}

    if not (settings.smtp_username and settings.smtp_app_password and settings.smtp_from_address):
        return {
            "error": (
                "Email is not configured on this server. Set SMTP_USERNAME, "
                "SMTP_APP_PASSWORD, and SMTP_FROM_EMAIL in .env."
            )
        }

    config = SmtpConfig(
        host=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_username,
        app_password=settings.smtp_app_password,
        from_address=settings.smtp_from_address,
    )

    try:
        send_plain_email(config, clean_recipient, clean_subject, clean_body)
    except EmailSendError as exc:
        logger.error("send_email_draft failed: %s", exc)
        return {"error": str(exc)}

    logger.info("Email sent to %s", clean_recipient)
    return {"status": "sent", "to": clean_recipient, "subject": clean_subject}


@mcp.prompt()
def task_summary_prompt(focus_area: str = "everything") -> str:
    """Build a prompt asking the assistant to summarize and prioritize open tasks.

    Args:
        focus_area: Optional filter/focus, e.g. "this week" or "high priority
            only". Defaults to "everything".
    """
    tasks = task_store.list_tasks(include_done=False)
    if not tasks:
        task_lines = "(no open tasks)"
    else:
        task_lines = "\n".join(
            f"- [{t.priority}] {t.title}" + (f" (due {t.due_date})" if t.due_date else "")
            for t in tasks
        )

    return (
        "You are helping the user plan their day. Here is their current "
        f"open task list, with a requested focus of: {focus_area}.\n\n"
        f"{task_lines}\n\n"
        "Summarize these tasks in priority order, flag anything overdue or "
        "due soon, and suggest a short, realistic plan for today. Keep the "
        "summary under 150 words and in plain prose (no headers, no "
        "bullet lists) so it reads well if emailed."
    )


def main() -> None:
    """Entry point used by `uv run productivity-mcp` and pyproject scripts."""
    mcp.run()


if __name__ == "__main__":
    main()
