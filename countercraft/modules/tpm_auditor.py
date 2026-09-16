"""
Advanced Module: TPM 2.0 PCR Integrity & Baseline Validator.

Reads Platform Configuration Register (PCR) values from a TPM 2.0 via
`tpm2-tools` (`tpm2_pcrread`), which -- unlike most TPM tooling -- works
the same way on Linux (via `/dev/tpmrm0`) and Windows (via the TBS
service), so it is used as the single cross-platform backend here rather
than maintaining two divergent code paths.

Focuses on the PCRs most relevant to firmware/boot integrity:
  PCR 0 - CRTM, BIOS/UEFI code, Option ROMs
  PCR 2 - UEFI drivers and execution code (third-party option ROM code)
  PCR 4 - Boot manager code and boot attempts
  PCR 7 - Secure Boot state: PK, KEK, db, dbx policy measurements

Supports saving a "known good" baseline snapshot and flagging drift
against it on subsequent runs -- the actual point of measured boot: a
PCR 7 change with no corresponding intentional Secure Boot policy update
is a strong bootkit/firmware-tamper signal, even if Secure Boot itself
still reports "enabled".
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from countercraft.core.base import BaseAuditor
from countercraft.core.models import Severity
from countercraft.core.utils import which, run_command

PCRS_OF_INTEREST: dict[int, str] = {
    0: "CRTM / BIOS-UEFI code / Option ROMs",
    2: "UEFI drivers and execution code",
    4: "Boot manager code and boot attempts",
    7: "Secure Boot state (PK, KEK, db, dbx)",
}

_PCR_LINE_RE = re.compile(r"^\s*(\d+)\s*:\s*(0x[0-9A-Fa-f]+)\s*$")


class TpmAuditor(BaseAuditor):
    name = "tpm"
    description = "TPM 2.0 presence, PCR readout, and baseline drift detection."
    requires_root = False  # tpm2-tools typically works for the 'tss'/'tpm' group; degrades otherwise

    def __init__(
        self,
        baseline_path: Optional[Path] = None,
        bank: str = "sha256",
    ) -> None:
        super().__init__()
        self.baseline_path = baseline_path
        self.bank = bank

    def audit(self) -> None:
        tpm2_pcrread = which("tpm2_pcrread")
        if not tpm2_pcrread:
            self._audit_presence_only()
            self.add_finding(
                "tpm2-tools not available",
                Severity.INFO,
                "tpm2_pcrread was not found on PATH. PCR integrity cannot "
                "be evaluated without it.",
                remediation="Install tpm2-tools (apt/dnf package "
                "'tpm2-tools', or the Windows build which talks to TBS).",
            )
            return

        result = run_command([tpm2_pcrread, self.bank], timeout=20.0)
        if not result.ok:
            self._audit_presence_only()
            self.add_finding(
                "PCR read failed",
                Severity.WARNING,
                f"tpm2_pcrread exited with an error: {result.stderr.strip() or result.stdout.strip()}",
                remediation="Confirm a TPM 2.0 device is present and "
                "accessible (permissions on /dev/tpmrm0, or TBS service "
                "running on Windows).",
            )
            return

        pcrs = self._parse_pcrread(result.stdout)
        if not pcrs:
            self.add_finding(
                "Could not parse PCR output",
                Severity.WARNING,
                "tpm2_pcrread returned data in an unrecognized format.",
                raw_output=result.stdout[-1000:],
            )
            return

        for index, label in PCRS_OF_INTEREST.items():
            value = pcrs.get(index)
            if value is None:
                self.add_finding(
                    f"PCR {index} unreadable",
                    Severity.WARNING,
                    f"PCR {index} ({label}) was not present in tpm2_pcrread output.",
                )
            else:
                self.add_finding(
                    f"PCR {index} read",
                    Severity.INFO,
                    f"PCR {index} ({label}) = {value}",
                    pcr_index=index,
                    pcr_value=value,
                )

        self._compare_baseline(pcrs)

    def _audit_presence_only(self) -> None:
        """Best-effort presence check when tpm2-tools is unavailable."""
        from countercraft.core.utils import is_linux, is_windows, run_powershell

        if is_linux():
            if Path("/dev/tpmrm0").exists() or Path("/dev/tpm0").exists():
                self.add_finding(
                    "TPM device node present",
                    Severity.INFO,
                    "A TPM device node exists, but PCR values could not be "
                    "read without tpm2-tools.",
                )
            else:
                self.add_finding(
                    "No TPM device detected",
                    Severity.WARNING,
                    "No /dev/tpm0 or /dev/tpmrm0 found. Either no TPM is "
                    "present, or it is disabled in firmware -- both "
                    "eliminate measured-boot integrity guarantees.",
                    remediation="Enable the TPM (fTPM/PTT or discrete) in "
                    "UEFI firmware settings if hardware supports it.",
                )
        elif is_windows():
            result = run_powershell("Get-Tpm | ConvertTo-Json -Compress")
            if not result.ok or not result.stdout.strip():
                self.add_finding(
                    "TPM status unknown",
                    Severity.WARNING,
                    "Get-Tpm did not return usable output.",
                )
                return
            try:
                info = json.loads(result.stdout)
            except json.JSONDecodeError:
                return
            if not isinstance(info, dict):
                # Get-Tpm can exit 0 while writing a plain error string to
                # stdout instead of an object (e.g. "Administrator
                # privilege is required to execute this command."), which
                # ConvertTo-Json then happily serializes as a JSON string.
                self.add_finding(
                    "TPM status unknown",
                    Severity.WARNING,
                    f"Get-Tpm did not return structured data: {str(info)[:200]}",
                    remediation="Re-run elevated (Administrator) so Get-Tpm can query TPM state.",
                )
                return
            present = info.get("TpmPresent")
            ready = info.get("TpmReady")
            if not present:
                self.add_finding(
                    "No TPM detected",
                    Severity.WARNING,
                    "Get-Tpm reports TpmPresent=False. Measured boot "
                    "integrity guarantees are unavailable.",
                    remediation="Enable fTPM/PTT (or install a discrete "
                    "TPM) in UEFI firmware settings.",
                )
            else:
                self.add_finding(
                    "TPM present",
                    Severity.INFO if ready else Severity.WARNING,
                    f"Get-Tpm reports TpmPresent={present}, TpmReady={ready}.",
                )

    @staticmethod
    def _parse_pcrread(output: str) -> dict[int, str]:
        pcrs: dict[int, str] = {}
        for line in output.splitlines():
            match = _PCR_LINE_RE.match(line)
            if match:
                pcrs[int(match.group(1))] = match.group(2).lower()
        return pcrs

    def _compare_baseline(self, pcrs: dict[int, str]) -> None:
        if not self.baseline_path:
            self.add_finding(
                "No TPM baseline configured",
                Severity.INFO,
                "Run with --tpm-baseline <path> to enable PCR drift "
                "detection across boots. Use --save-tpm-baseline to "
                "create one from this reading.",
            )
            return
        if not self.baseline_path.is_file():
            self.add_finding(
                "TPM baseline file not found",
                Severity.WARNING,
                f"{self.baseline_path} does not exist yet.",
            )
            return
        try:
            baseline_raw = json.loads(self.baseline_path.read_text())
            baseline = {int(k): v for k, v in baseline_raw.items()}
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            self.add_finding(
                "Could not load TPM baseline",
                Severity.WARNING,
                f"Failed to parse {self.baseline_path}: {exc}",
            )
            return

        drifted = []
        for index, label in PCRS_OF_INTEREST.items():
            base_val = baseline.get(index)
            cur_val = pcrs.get(index)
            if base_val is None or cur_val is None:
                continue
            if base_val.lower() != cur_val.lower():
                drifted.append(index)
                self.add_finding(
                    f"PCR {index} drift detected",
                    Severity.CRITICAL,
                    f"PCR {index} ({label}) changed from baseline "
                    f"{base_val} to {cur_val}. Any measurement in this "
                    "chain changing without an intentional firmware/boot "
                    "configuration update is a strong tamper signal.",
                    remediation="Correlate with any known firmware update, "
                    "Secure Boot key rotation, or boot order change. If "
                    "none occurred, treat as a suspected integrity "
                    "compromise and investigate offline.",
                    pcr_index=index,
                    baseline_value=base_val,
                    current_value=cur_val,
                )
        if not drifted:
            self.add_finding(
                "PCRs match baseline",
                Severity.INFO,
                f"All {len(PCRS_OF_INTEREST)} monitored PCRs match the "
                "recorded baseline.",
            )

    @staticmethod
    def save_baseline(pcrs: dict[int, str], out_path: Path) -> None:
        """Used by `countercraft audit --save-tpm-baseline` to persist a known-good snapshot."""
        out_path.write_text(json.dumps({str(k): v for k, v in pcrs.items()}, indent=2))

    @staticmethod
    def read_current_pcrs(bank: str = "sha256") -> dict[int, str]:
        """Standalone read used by the CLI's --save-tpm-baseline path."""
        tpm2_pcrread = which("tpm2_pcrread")
        if not tpm2_pcrread:
            raise RuntimeError("tpm2_pcrread not found on PATH")
        result = run_command([tpm2_pcrread, bank], timeout=20.0)
        if not result.ok:
            raise RuntimeError(f"tpm2_pcrread failed: {result.stderr or result.stdout}")
        return TpmAuditor._parse_pcrread(result.stdout)
