"""
Local JSON-backed task store.

Uses pathlib.Path exclusively for all filesystem paths (per the
assignment's secret/file-management guidance -- no os.path). Tasks are
persisted to a single JSON file so the store survives server restarts
without needing an external database, keeping the assignment's scope
appropriately small ("tools do not need to be complicated").
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


@dataclass
class Task:
    id: str
    title: str
    due_date: str | None
    priority: str
    created_at: str
    done: bool = False


class TaskStore:
    """Thread-safe JSON file store for tasks.

    A Lock guards read-modify-write cycles because the MCP server can
    process concurrent tool calls (e.g. multiple stdio/session clients),
    and naive concurrent writes to the same JSON file would corrupt it.
    """

    def __init__(self, path: Path):
        self.path = path
        self._lock = Lock()
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._write_all([])

    def _read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        text = self.path.read_text(encoding="utf-8").strip()
        if not text:
            return []
        return json.loads(text)

    def _write_all(self, tasks: list[dict]) -> None:
        self.path.write_text(json.dumps(tasks, indent=2), encoding="utf-8")

    def add_task(self, title: str, due_date: str | None, priority: str) -> Task:
        task = Task(
            id=uuid.uuid4().hex[:8],
            title=title,
            due_date=due_date,
            priority=priority,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        with self._lock:
            tasks = self._read_all()
            tasks.append(asdict(task))
            self._write_all(tasks)
        return task

    def list_tasks(self, include_done: bool = False) -> list[Task]:
        with self._lock:
            raw = self._read_all()
        tasks = [Task(**t) for t in raw]
        if not include_done:
            tasks = [t for t in tasks if not t.done]
        return tasks
