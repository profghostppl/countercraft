"""
State Baseline & Differential Engine.

Captures a point-in-time snapshot of security-relevant host state --
TPM PCR values, installed root CAs, loaded kernel modules, and EFI boot
manager variables -- and compares a later snapshot against it, producing
high-visibility findings for anything that changed.

This is distinct from (and complements) the per-check baselines already
built into `TpmAuditor` and `FirmwareIntegrityChecker`: those are each
scoped to one specific artifact. This engine gives one combined "has
anything about this host's trust chain moved since I last looked"
snapshot, driven by the `anchorroot baseline save` / `anchorroot audit
--diff` CLI subcommands.

Every collector here degrades to an empty result (never raises) when its
data source is unavailable -- no TPM, no efivarfs, running unprivileged,
whatever -- and `diff_snapshots` only compares a category when BOTH sides
have data for it, so a collection failure never masquerades as "everything
in the baseline was removed" (the same false-positive class the
persistence module had to be hardened against).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Optional

from anchorroot.config import DEFAULT_BASELINE_PATH
from anchorroot.core.models import Finding, Severity
from anchorroot.core.utils import is_linux, is_mock_mode, is_windows, run_command

SNAPSHOT_SCHEMA_VERSION = 1

_MODULE_NAME = "baseline_diff"

# EFI_GLOBAL_VARIABLE_GUID -- owns BootOrder/BootCurrent/Boot####.
_BOOT_GUID_SUFFIX = "-8be4df61-93ca-11d2-aa0d-00e098032b8c"
_BOOT_ENTRY_RE = re.compile(r"^Boot([0-9A-Fa-f]{4})" + re.escape(_BOOT_GUID_SUFFIX) + r"$")


class SnapshotError(Exception):
    """Raised for a baseline file that can't be loaded/parsed -- caught by the CLI for a clean error message."""


@dataclasses.dataclass
class Snapshot:
    schema_version: int = SNAPSHOT_SCHEMA_VERSION
    generated_at: str = dataclasses.field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat()
    )
    tpm_pcrs: dict[str, str] = dataclasses.field(default_factory=dict)
    root_cas: dict[str, str] = dataclasses.field(default_factory=dict)  # fingerprint -> subject
    kernel_modules: list[str] = dataclasses.field(default_factory=list)
    efi_boot_variables: dict[str, str] = dataclasses.field(default_factory=dict)  # name -> sha256(payload)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Snapshot":
        # Tolerant loader: a baseline from an older/newer Anchorroot
        # version should still load, just with whatever categories it
        # happens to carry.
        return cls(
            schema_version=int(data.get("schema_version", SNAPSHOT_SCHEMA_VERSION)),
            generated_at=str(data.get("generated_at", "")),
            tpm_pcrs=dict(data.get("tpm_pcrs") or {}),
            root_cas=dict(data.get("root_cas") or {}),
            kernel_modules=list(data.get("kernel_modules") or []),
            efi_boot_variables=dict(data.get("efi_boot_variables") or {}),
        )


# -- collection ------------------------------------------------------------


def collect_snapshot() -> Snapshot:
    """Gather current host state into a Snapshot. Every field degrades to empty on failure, never raises."""
    return Snapshot(
        tpm_pcrs=_collect_tpm_pcrs(),
        root_cas=_collect_root_cas(),
        kernel_modules=_collect_kernel_modules(),
        efi_boot_variables=_collect_efi_boot_variables(),
    )


def _collect_tpm_pcrs() -> dict[str, str]:
    from anchorroot.modules.tpm_auditor import TpmAuditor

    try:
        pcrs = TpmAuditor.read_current_pcrs()
    except RuntimeError:
        return {}
    return {str(k): v for k, v in pcrs.items()}


def _collect_root_cas() -> dict[str, str]:
    from anchorroot.modules.ca_auditor import CaAuditor

    certs = CaAuditor().enumerate_root_cas()
    if not certs:
        return {}
    # Keyed by fingerprint (the true identity) rather than subject, since
    # subjects are not guaranteed unique across a trust store.
    return {fingerprint: subject for subject, fingerprint in certs if fingerprint}


def _collect_kernel_modules() -> list[str]:
    from anchorroot.modules.persistence import PersistenceAuditor

    return PersistenceAuditor.list_loaded_kernel_module_names()


def _collect_efi_boot_variables() -> dict[str, str]:
    if is_mock_mode():
        from anchorroot.mocks import MOCK_EFI_BOOT_VARIABLES

        return dict(MOCK_EFI_BOOT_VARIABLES)
    if is_linux():
        return _collect_efi_boot_variables_linux()
    if is_windows():
        return _collect_efi_boot_variables_windows()
    return {}


def _collect_efi_boot_variables_linux() -> dict[str, str]:
    efivars_dir = Path("/sys/firmware/efi/efivars")
    if not efivars_dir.is_dir():
        return {}
    result: dict[str, str] = {}
    for name in ("BootOrder", "BootCurrent"):
        var_path = efivars_dir / f"{name}{_BOOT_GUID_SUFFIX}"
        try:
            data = var_path.read_bytes()[4:]
        except OSError:
            continue
        result[name] = hashlib.sha256(data).hexdigest()
    try:
        entries = list(efivars_dir.glob(f"Boot????{_BOOT_GUID_SUFFIX}"))
    except OSError:
        entries = []
    for entry in entries:
        match = _BOOT_ENTRY_RE.match(entry.name)
        if not match:
            continue
        try:
            data = entry.read_bytes()[4:]
        except OSError:
            continue
        result[f"Boot{match.group(1)}"] = hashlib.sha256(data).hexdigest()
    return result


def _collect_efi_boot_variables_windows() -> dict[str, str]:
    # `bcdedit /enum firmware` is the practical, documented way to list
    # firmware boot manager entries on Windows; UEFI_LOAD_OPTION structures
    # aren't otherwise exposed to a script without a compiled helper. Each
    # "identifier { ... }" block is hashed as a whole (coarse fingerprint --
    # any change to a boot entry's identifier, description, or path shows
    # up as a hash change) rather than modeled field-by-field.
    result_cmd = run_command(["bcdedit", "/enum", "firmware"], timeout=15.0)
    if not result_cmd.ok:
        return {}
    entries: dict[str, str] = {}
    current_id: Optional[str] = None
    current_lines: list[str] = []

    def flush() -> None:
        if current_id:
            entries[current_id] = hashlib.sha256("\n".join(current_lines).encode("utf-8", "ignore")).hexdigest()

    for line in result_cmd.stdout.splitlines():
        stripped = line.strip()
        match = re.match(r"^identifier\s+(\{[^}]+\}|\S+)", stripped, re.IGNORECASE)
        if match:
            flush()
            current_id = match.group(1)
            current_lines = [stripped]
            continue
        if current_id and stripped:
            current_lines.append(stripped)
    flush()
    return entries


# -- persistence -------------------------------------------------------


def save_snapshot(path: Path) -> Snapshot:
    snapshot = collect_snapshot()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return snapshot


def load_snapshot(path: Path) -> Snapshot:
    if not path.is_file():
        raise SnapshotError(f"Baseline not found: {path}. Create one with 'anchorroot baseline save {path}' first.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"Could not read baseline {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SnapshotError(f"Baseline {path} does not contain a JSON object.")
    return Snapshot.from_dict(data)


# -- diffing -------------------------------------------------------------


def _finding(title: str, severity: Severity, description: str, remediation: Optional[str] = None, **metadata) -> Finding:
    return Finding(
        module=_MODULE_NAME,
        title=f"[BASELINE DRIFT] {title}",
        severity=severity,
        description=description,
        remediation=remediation,
        metadata=metadata,
    )


def diff_snapshots(baseline: Snapshot, current: Snapshot) -> list[Finding]:
    """
    Compare two snapshots and return high-visibility findings for
    anything that changed. Each category is only compared when both
    snapshots actually have data for it -- an empty side (TPM absent,
    unprivileged, non-UEFI) is skipped with an INFO note rather than
    treated as "everything was removed".
    """
    findings: list[Finding] = []

    findings.extend(_diff_tpm_pcrs(baseline, current))
    findings.extend(_diff_root_cas(baseline, current))
    findings.extend(_diff_kernel_modules(baseline, current))
    findings.extend(_diff_efi_boot_variables(baseline, current))

    if not findings:
        findings.append(
            _finding(
                "No drift detected",
                Severity.INFO,
                "TPM PCRs, root CA store, loaded kernel modules, and EFI "
                "boot variables all match the baseline snapshot (for "
                "every category both this run and the baseline had data to compare).",
            )
        )
    return findings


def _diff_tpm_pcrs(baseline: Snapshot, current: Snapshot) -> list[Finding]:
    if not baseline.tpm_pcrs or not current.tpm_pcrs:
        if baseline.tpm_pcrs or current.tpm_pcrs:
            return [
                _finding(
                    "TPM PCR comparison skipped",
                    Severity.INFO,
                    "TPM PCR values were available in only one of the "
                    "baseline/current snapshots (TPM absent, tpm2-tools "
                    "missing, or mock/real mode mismatch) -- skipping comparison.",
                )
            ]
        return []

    findings = []
    for idx, base_val in sorted(baseline.tpm_pcrs.items()):
        cur_val = current.tpm_pcrs.get(idx)
        if cur_val is None:
            continue
        if cur_val.lower() != base_val.lower():
            findings.append(
                _finding(
                    "TPM PCR changed",
                    Severity.CRITICAL,
                    f"PCR {idx} changed from baseline ({base_val} -> "
                    f"{cur_val}) -- any change in this chain without a "
                    "known, intentional firmware/boot update is a strong "
                    "tamper signal.",
                    remediation="Correlate with any known firmware update "
                    "or Secure Boot policy change; if none occurred, "
                    "investigate immediately.",
                    pcr_index=idx,
                    baseline_value=base_val,
                    current_value=cur_val,
                )
            )
    return findings


def _diff_root_cas(baseline: Snapshot, current: Snapshot) -> list[Finding]:
    if not baseline.root_cas or not current.root_cas:
        if baseline.root_cas or current.root_cas:
            return [
                _finding(
                    "Root CA comparison skipped",
                    Severity.INFO,
                    "Root CA store enumeration returned no data in one of "
                    "the baseline/current snapshots -- skipping comparison "
                    "to avoid flagging every baseline CA as removed.",
                )
            ]
        return []

    findings = []
    added = current.root_cas.keys() - baseline.root_cas.keys()
    removed = baseline.root_cas.keys() - current.root_cas.keys()
    for fingerprint in sorted(added):
        findings.append(
            _finding(
                "Root CA added",
                Severity.WARNING,
                f"New root CA since baseline: '{current.root_cas[fingerprint]}' "
                f"(sha256={fingerprint}). Verify this was an intentional install.",
                remediation="If unexpected, remove the certificate and "
                "investigate what installed it.",
                fingerprint=fingerprint,
                subject=current.root_cas[fingerprint],
            )
        )
    for fingerprint in sorted(removed):
        findings.append(
            _finding(
                "Root CA removed",
                Severity.WARNING,
                f"Root CA present in the baseline is no longer installed: "
                f"'{baseline.root_cas[fingerprint]}' (sha256={fingerprint}).",
                fingerprint=fingerprint,
                subject=baseline.root_cas[fingerprint],
            )
        )
    return findings


def _diff_kernel_modules(baseline: Snapshot, current: Snapshot) -> list[Finding]:
    if not baseline.kernel_modules or not current.kernel_modules:
        if baseline.kernel_modules or current.kernel_modules:
            return [
                _finding(
                    "Kernel module comparison skipped",
                    Severity.INFO,
                    "Kernel module enumeration returned no data in one of "
                    "the baseline/current snapshots -- skipping comparison.",
                )
            ]
        return []

    findings = []
    base_set, cur_set = set(baseline.kernel_modules), set(current.kernel_modules)
    added = sorted(cur_set - base_set)
    removed = sorted(base_set - cur_set)
    for name in added:
        findings.append(
            _finding(
                "New kernel module loaded",
                Severity.WARNING,
                f"Kernel module/driver '{name}' is loaded but was not "
                "present in the baseline snapshot.",
                remediation="Confirm this corresponds to an expected "
                "hardware or driver change; investigate if not.",
                module_name=name,
            )
        )
    if removed:
        findings.append(
            _finding(
                "Kernel modules no longer loaded",
                Severity.INFO,
                f"{len(removed)} module(s) from the baseline are no longer "
                f"loaded: {', '.join(removed[:10])}"
                + (f" (+{len(removed) - 10} more)" if len(removed) > 10 else ""),
                removed=removed,
            )
        )
    return findings


def _diff_efi_boot_variables(baseline: Snapshot, current: Snapshot) -> list[Finding]:
    if not baseline.efi_boot_variables or not current.efi_boot_variables:
        if baseline.efi_boot_variables or current.efi_boot_variables:
            return [
                _finding(
                    "EFI boot variable comparison skipped",
                    Severity.INFO,
                    "EFI boot manager variables were readable in only one "
                    "of the baseline/current snapshots (non-UEFI system, "
                    "efivarfs not mounted, or bcdedit failed) -- skipping comparison.",
                )
            ]
        return []

    findings = []
    for name, cur_hash in sorted(current.efi_boot_variables.items()):
        base_hash = baseline.efi_boot_variables.get(name)
        if base_hash is None:
            findings.append(
                _finding(
                    "EFI boot variable added",
                    Severity.CRITICAL,
                    f"EFI boot variable '{name}' was not present in the "
                    "baseline. New boot manager entries are a common "
                    "bootkit persistence technique.",
                    remediation="Enumerate current boot entries "
                    "(efibootmgr / bcdedit /enum firmware) and verify "
                    "every entry is expected; remove unrecognized ones.",
                    variable=name,
                )
            )
        elif base_hash != cur_hash:
            findings.append(
                _finding(
                    "EFI boot variable modified",
                    Severity.CRITICAL,
                    f"EFI boot variable '{name}' changed since the "
                    "baseline -- verify this corresponds to an intentional "
                    "boot configuration change.",
                    remediation="Enumerate current boot entries and "
                    "confirm the change was expected (e.g. an OS update "
                    "modifying its own boot entry).",
                    variable=name,
                    baseline_hash=base_hash,
                    current_hash=cur_hash,
                )
            )
    for name in sorted(baseline.efi_boot_variables.keys() - current.efi_boot_variables.keys()):
        findings.append(
            _finding(
                "EFI boot variable removed",
                Severity.WARNING,
                f"EFI boot variable '{name}' present in the baseline is no longer present.",
                variable=name,
            )
        )
    return findings
