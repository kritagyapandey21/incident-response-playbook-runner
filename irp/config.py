"""Central configuration. Every value can be overridden with an environment variable."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path(os.getenv("IRP_DATA_DIR", ROOT / "data"))
    output_dir: Path = Path(os.getenv("IRP_OUTPUT_DIR", ROOT / "output"))
    # approvals
    approval_token_ttl_s: int = _int("IRP_APPROVAL_TTL_SECONDS", 15 * 60)
    # orchestration
    max_plan_revisions: int = _int("IRP_MAX_PLAN_REVISIONS", 2)
    max_tasks_per_incident: int = _int("IRP_MAX_TASKS", 25)
    # retrieval
    low_confidence_score: float = _float("IRP_LOW_CONFIDENCE_SCORE", 0.12)
    ambiguous_margin: float = _float("IRP_AMBIGUOUS_MARGIN", 0.03)
    # input limits
    max_alert_bytes: int = _int("IRP_MAX_ALERT_BYTES", 64 * 1024)
    max_request_bytes: int = _int("IRP_MAX_REQUEST_BYTES", 256 * 1024)
    # web
    max_sessions: int = _int("IRP_MAX_SESSIONS", 200)


SETTINGS = Settings()
