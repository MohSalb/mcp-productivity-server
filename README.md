# Personal Productivity MCP Server

A local [Model Context Protocol](https://modelcontextprotocol.io/) server that
gives an MCP client (e.g. Claude Desktop) two tools and one prompt for
lightweight personal task tracking and email drafting.

Built with the official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
(`FastMCP` high-level API) and [`uv`](https://docs.astral.sh/uv/) for
environment/dependency management.

## What it does

| Kind | Name | Description |
|---|---|---|
| Tool | `add_task` | Add a task (title, optional due date, priority) to a local JSON task list. |
| Tool | `list_open_tasks` | List all not-yet-done tasks. (Bonus/helper tool — the two required tools are `add_task` and `send_email_draft`.) |
| Tool | `send_email_draft` | Send a short plain-text email (e.g. a task summary) via authenticated SMTP. |
| Prompt | `task_summary_prompt` | Builds a reusable prompt template asking the assistant to summarize and prioritize the current open tasks. |

**Authentication:** `send_email_draft` requires real SMTP credentials
(e.g. a Gmail account + [App Password](https://support.google.com/accounts/answer/185833)),
loaded from a local `.env` file — see [Setup](#setup) below.

## Best practices implemented

1. **Input Sanitization** (`src/productivity_mcp/security.py`) — blocks
   email-header-injection (CR/LF sequences that could add rogue `Bcc:`
   headers), enforces an allow-listed email format, an allow-listed
   task priority, and length limits on all free-text fields.
2. **Rate Limiting** (`src/productivity_mcp/security.py`) — an in-memory
   sliding-window limiter (default: 5 calls / 60s per tool) rejects a
   client that calls a tool too frequently.

Both are demonstrated with exploit tests in `tests/test_exploits.py`
(see [Running the exploit demos](#running-the-exploit-demos)).

## Project layout

```
mcp-productivity-server/
├── src/productivity_mcp/
│   ├── server.py        # FastMCP server: tool + prompt definitions
│   ├── security.py      # input sanitization + rate limiting
│   ├── task_store.py     # local JSON task persistence (pathlib)
│   ├── email_client.py   # SMTP transport (smtplib + STARTTLS)
│   └── config.py         # loads secrets from .env via python-dotenv
├── tests/test_exploits.py  # exploit demos for both best practices
├── .env.example
├── requirements.txt
├── claude_desktop_config.json
└── pyproject.toml
```

## Setup

### 1. Create and activate a virtual environment (with `uv`)

```bash
# install uv if you don't have it: https://docs.astral.sh/uv/getting-started/installation/
cd mcp-productivity-server
uv sync            # creates .venv/ and installs dependencies from uv.lock
```

`uv sync` creates the virtual environment for you automatically at
`.venv/`; you don't need a separate `uv venv` step. If you'd rather use
plain `pip`/`venv` (or Anaconda), a `requirements.txt` is also provided:

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure secrets

```bash
cp .env.example .env
```

Edit `.env` and fill in a real Gmail address + App Password (or any
SMTP provider's credentials). **Never commit `.env`** — it's already in
`.gitignore`. Secrets are loaded via `python-dotenv` in `config.py`
(not `os.path`, not permanent system environment variables).

If you skip this step, `add_task` / `list_open_tasks` / the prompt
still work — only `send_email_draft` will return a clear
"email is not configured" error.

### 3. Run the server directly (for local testing)

```bash
uv run productivity-mcp
```

The server speaks MCP over stdio and will simply wait for a client to
connect — that's expected, it won't print anything to a normal
terminal. Use the MCP Inspector to poke at it interactively:

```bash
uv run mcp dev src/productivity_mcp/server.py
```

### 4. Connect it to Claude Desktop

Open Claude Desktop's config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Merge in the contents of [`claude_desktop_config.json`](./claude_desktop_config.json)
from this repo, replacing the placeholder path with the **absolute path**
to this project on your machine:

```json
{
  "mcpServers": {
    "personal-productivity": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/mcp-productivity-server", "run", "productivity-mcp"]
    }
  }
}
```

> **Gotcha:** Claude Desktop launches this as a GUI app, which often
> doesn't inherit your shell's `PATH`, so `"command": "uv"` can fail to
> resolve. If that happens, run `which uv` in a terminal and use that
> full path instead (e.g. `/Users/you/.local/bin/uv`).

Restart Claude Desktop. You should see a 🔨 tools icon indicating the
`personal-productivity` server connected, with `add_task`,
`list_open_tasks`, and `send_email_draft` available, plus the
`task_summary_prompt` prompt template.

## Running the exploit demos

```bash
uv run pytest tests/test_exploits.py -v
```

This runs 5 tests:

- **Input Sanitization exploit:** attempts an SMTP header-injection
  attack by putting `\r\nBcc: attacker@evil.example.com` into the email
  subject and recipient fields, and asserts the request is rejected
  *before* it ever reaches the SMTP transport layer (plus a sanity
  check that a normal, valid email still sends).
- **Rate Limiting exploit:** calls `add_task` 5 times in a row against
  a 3-call limit and asserts exactly 3 succeed and 2 are rejected with
  a `Rate limit exceeded` error; also checks the limit is scoped
  per-tool, not global.

## Error handling / error disclosure

Tool functions never let raw exceptions (stack traces, SMTP server
banners, file paths) reach the MCP client. Validation failures return a
short, specific `{"error": "..."}` message; SMTP failures are logged
in full server-side but returned to the client as a generic "Failed to
send email via SMTP" message (see `email_client.py`'s `EmailSendError`).

## Code citations

- The overall server construction pattern (`FastMCP(...)`, `@mcp.tool()`
  decorator, `mcp.run()`) follows the official MCP Python SDK's own
  README "Quickstart" example:
  https://github.com/modelcontextprotocol/python-sdk#quickstart
- The `write_email_draft`-style tool signature was adapted from the
  assignment prompt's own example snippet.
- No other third-party code snippets were copied into this project;
  `smtplib`/`email.message.EmailMessage` usage in `email_client.py`
  follows the standard library documentation patterns at
  https://docs.python.org/3/library/smtplib.html and
  https://docs.python.org/3/library/email.examples.html.

## Ai Disclosure

I used Claude's Sonnet Model in this assignment
