"""Shared data structures passed between agents."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
PHASE_ORDER = {"preserve": 0, "contain": 1, "eradicate": 2, "recover": 3}


def severity_rank(level: str) -> int:
    return SEVERITY_LEVELS.index(level) if level in SEVERITY_LEVELS else -1


@dataclass
class IncidentRecord:
    """Structured incident produced by the Alert Parser Agent."""
    incident_id: str
    source: str
    title: str
    description: str
    vendor_severity: str | None
    status_signal: str                      # "confirmed" | "blocked" | "unknown"
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)          # all IPs seen
    external_ips: list[str] = field(default_factory=list)  # non-RFC1918 IPs (attacker side)
    internal_ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    email_senders: list[str] = field(default_factory=list)
    cloud_keys: list[str] = field(default_factory=list)
    cloud_accounts: list[str] = field(default_factory=list)
    # LLM enrichment (advisory, validated); empty in deterministic mode
    summary: str | None = None
    llm_signal: dict | None = None
    llm_added: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Citation:
    doc_id: str
    title: str
    section: str
    retrieval_score: float

    def __str__(self) -> str:
        return f"{self.doc_id} §{self.section} ({self.title})"


@dataclass
class ContainmentStep:
    step_id: str
    order: int
    phase: str
    action: str
    target: str
    target_type: str
    description: str
    destructive: bool
    citation: Citation
    status: str = "planned"   # planned | approved | executed | blocked | pending_approval | rejected
    approved_by: str | None = None
    result: str | None = None
    rationale: str | None = None   # LLM explanation of why this step fits this incident

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["citation"] = asdict(self.citation)
        return d
