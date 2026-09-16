"""
Abstract base every audit module implements. Keeping the contract this
small is deliberate: modules should be droppable-in and the CLI/engine
should never need module-specific branching.
"""

from __future__ import annotations

import abc
import time

from anchorroot.core.models import Finding, ModuleResult, Severity


class BaseAuditor(abc.ABC):
    #: Short, stable identifier used in reports and CLI selection (e.g. "tpm").
    name: str = "unnamed"

    #: Human-readable description shown in `anchorroot list`.
    description: str = ""

    #: If True, `run()` will not be called at all without elevated privileges;
    #: the engine records a `skipped` ModuleResult instead. Auditors that can
    #: do *partial* work without root should set this False and self-degrade.
    requires_root: bool = False

    def __init__(self) -> None:
        self._findings: list[Finding] = []

    # -- helpers available to subclasses -----------------------------------

    def add_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        remediation: str | None = None,
        **metadata,
    ) -> None:
        self._findings.append(
            Finding(
                module=self.name,
                title=title,
                severity=severity,
                description=description,
                remediation=remediation,
                metadata=metadata,
            )
        )

    # -- contract -------------------------------------------------------

    @abc.abstractmethod
    def audit(self) -> None:
        """
        Subclasses implement their checks here, calling `self.add_finding`
        for each observation. Raising is fine -- the engine wraps this and
        records the exception as a ModuleResult error rather than crashing
        the whole run.
        """
        raise NotImplementedError

    def run(self) -> ModuleResult:
        """Engine entry point. Do not override -- implement `audit()` instead."""
        from anchorroot.core.utils import is_elevated  # local import avoids a cycle

        if self.requires_root and not is_elevated():
            return ModuleResult(
                module=self.name,
                skipped=True,
                skip_reason="requires elevated/root privileges",
            )

        start = time.monotonic()
        self._findings = []
        try:
            self.audit()
        except Exception as exc:  # noqa: BLE001 - isolate module failures
            return ModuleResult(
                module=self.name,
                error=f"{type(exc).__name__}: {exc}",
                duration_seconds=time.monotonic() - start,
            )
        return ModuleResult(
            module=self.name,
            findings=self._findings,
            duration_seconds=time.monotonic() - start,
        )
