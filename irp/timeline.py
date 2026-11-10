"""Shared incident timeline: the common memory every agent reads from and writes to.

Agents do not pass results to each other directly. Each agent writes its output as a
timeline event and the next agent reads what it needs from the timeline.

Guarantees
  * Append-only: events are deep-copied on write AND on read, so no caller can change
    an event after it has been recorded (the in-memory history always equals the file).
  * Thread-safe: a lock serialises writers.
  * Durable: every event is appended to a JSON Lines file, and a timeline can be
    re-loaded from that file (used to resume pending approvals after a restart).
"""
from __future__ import annotations

import copy
import json
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")


def validate_incident_id(incident_id: str) -> str:
    """Reject ids that could escape the output directory or break file names."""
    if not isinstance(incident_id, str) or not INCIDENT_ID_RE.match(incident_id):
        raise ValueError(f"invalid incident id: {incident_id!r}")
    return incident_id


def new_incident_id(prefix: str) -> str:
    """Globally unique, sortable, human-readable: A01-20261110T142233-3f9a."""
    prefix = re.sub(r"[^A-Za-z0-9]", "", prefix)[:16] or "INC"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{prefix}-{ts}-{secrets.token_hex(2)}"


def _to_jsonable(data: Any) -> Any:
    """Deep copy through JSON so stored events are plain data with no shared references."""
    return json.loads(json.dumps(data, default=str))


class IncidentTimeline:
    def __init__(self, incident_id: str, persist_path: Path | None = None,
                 overwrite: bool = False, _events: list | None = None):
        self.incident_id = validate_incident_id(incident_id)
        self._events: list[dict[str, Any]] = _events or []
        self._lock = threading.Lock()
        self._path = persist_path
        if self._path and _events is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if not overwrite and self._path.exists() and self._path.stat().st_size:
                raise FileExistsError(f"timeline already exists: {self._path}")
            self._path.write_text("", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "IncidentTimeline":
        events = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
        if not events:
            raise ValueError(f"empty timeline: {path}")
        return cls(events[0]["incident_id"], path, _events=events)

    def write(self, agent: str, event: str, data: Any = None) -> dict[str, Any]:
        with self._lock:
            entry = {
                "seq": len(self._events) + 1,
                "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                "incident_id": self.incident_id,
                "agent": agent,
                "event": event,
                "data": _to_jsonable(data),
            }
            self._events.append(entry)
            if self._path:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
            return copy.deepcopy(entry)

    def read(self, event: str | None = None, agent: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy([
                e for e in self._events
                if (event is None or e["event"] == event) and (agent is None or e["agent"] == agent)
            ])

    def latest(self, event: str) -> Any:
        """Return a copy of the data of the most recent event of the given type (or None)."""
        with self._lock:
            for e in reversed(self._events):
                if e["event"] == event:
                    return copy.deepcopy(e["data"])
        return None

    def count(self, event: str) -> int:
        with self._lock:
            return sum(1 for e in self._events if e["event"] == event)

    def all(self) -> list[dict[str, Any]]:
        return self.read()
