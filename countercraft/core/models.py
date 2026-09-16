"""
Core data models shared by every audit module.

Keeping these in one place means the reporting engine never needs to know
anything about *how* a finding was produced -- only that it conforms to
this shape. Modules are free to add extra context via `Finding.metadata`.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import platform
import socket
import uuid
from typing import Any, Optional

from countercraft.config import SEVERITY_WEIGHTS


class Severity(enum.IntEnum):
    """Ordered so findings can be sorted worst-first with a plain sort()."""

    INFO = 0
    WARNING = 1
    CRITICAL = 2

    @property
    def label(self) -> str:
        return f"[{self.name}]"


@dataclasses.dataclass(slots=True)
class Finding:
    """A single, atomic audit observation."""

    module: str
    title: str
    severity: Severity
    description: str
    remediation: Optional[str] = None
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
    finding_id: str = dataclasses.field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "module": self.module,
            "title": self.title,
            "severity": self.severity.name,
            "description": self.description,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }


@dataclasses.dataclass(slots=True)
class ModuleResult:
    """
    What every BaseAuditor.run() must return.

    `skipped` + `skip_reason` let a module decline to run (e.g. missing
    root, missing dependency) without that looking like a crash.
    """

    module: str
    findings: list[Finding] = dataclasses.field(default_factory=list)
    skipped: bool = False
    skip_reason: Optional[str] = None
    error: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 3),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclasses.dataclass(slots=True)
class AuditReport:
    """Top-level container produced by the reporting/scoring engine."""

    results: list[ModuleResult] = dataclasses.field(default_factory=list)
    generated_at: str = dataclasses.field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat()
    )
    hostname: str = dataclasses.field(default_factory=socket.gethostname)
    os_info: str = dataclasses.field(
        default_factory=lambda: f"{platform.system()} {platform.release()} ({platform.version()})"
    )

    @property
    def all_findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    def counts(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.name] += 1
        return counts

    def risk_score(self) -> int:
        """
        Simple weighted score, 0 = clean. Not a substitute for reading the
        findings -- it exists purely to give a one-glance CLI headline and
        a stable number to diff between runs / CI gates.
        """
        return sum(SEVERITY_WEIGHTS[f.severity.name] for f in self.all_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "risk_score": self.risk_score(),
            "severity_counts": self.counts(),
            "modules": [r.to_dict() for r in self.results],
        }
