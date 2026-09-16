"""
Module 1: Platform & BIOS Configuration Auditor.

Primary path: shell out to CHIPSEC (`chipsec_main`), which requires its own
kernel driver and elevated privileges, to evaluate platform register
protections (SPI flash write protection / BIOS Write Protect + SMM lock
bits) directly from hardware.

Fallback path (CHIPSEC absent, driver not loaded, or not elevated): native
OS commands for Secure Boot status only. Register-level SPI/SMM checks have
no safe OS-native equivalent, so when CHIPSEC is unavailable those checks
are reported as INFO/"not evaluated" rather than guessed at.
"""

from __future__ import annotations

import re

from anchorroot.core.base import BaseAuditor
from anchorroot.core.models import Severity
from anchorroot.core.utils import is_elevated, is_linux, is_mock_mode, is_windows, run_command, run_powershell, which


class UefiPlatformAuditor(BaseAuditor):
    name = "uefi_platform"
    description = "SPI/BIOS write protection, SMM lock bits, and Secure Boot state."
    # Individually gated per-check below rather than blanket-skipped, since
    # Secure Boot status can be read without elevation on both OSes.
    requires_root = False

    def audit(self) -> None:
        self._audit_secure_boot()
        self._audit_chipsec_registers()

    # -- Secure Boot -----------------------------------------------------

    def _audit_secure_boot(self) -> None:
        if is_windows():
            self._secure_boot_windows()
        elif is_linux():
            self._secure_boot_linux()
        else:
            self.add_finding(
                "Secure Boot check unsupported",
                Severity.INFO,
                "Secure Boot verification is only implemented for Windows and Linux.",
            )

    def _secure_boot_windows(self) -> None:
        result = run_powershell("Confirm-SecureBootUEFI")
        if not result.ok:
            # Confirm-SecureBootUEFI throws on legacy BIOS (non-UEFI) systems.
            self.add_finding(
                "Secure Boot state unknown",
                Severity.WARNING,
                "Confirm-SecureBootUEFI failed -- system may be legacy BIOS "
                "(no UEFI Secure Boot support) or the query requires elevation.",
                remediation="Re-run elevated (Administrator) and confirm the "
                "firmware is in UEFI mode, not Legacy/CSM.",
                stderr=result.stderr.strip(),
            )
            return

        enabled = "true" in result.stdout.strip().lower()
        if enabled:
            self.add_finding(
                "Secure Boot enabled",
                Severity.INFO,
                "UEFI Secure Boot is active.",
            )
        else:
            self.add_finding(
                "Secure Boot disabled",
                Severity.CRITICAL,
                "UEFI Secure Boot is disabled, allowing unsigned bootloaders "
                "and OS kernels to execute -- a common firmware/bootkit "
                "persistence vector.",
                remediation="Enable Secure Boot in UEFI firmware settings.",
            )

        self._secure_boot_keys_windows()

    def _secure_boot_keys_windows(self) -> None:
        for key_name, severity_if_missing in (
            ("PK", Severity.WARNING),
            ("KEK", Severity.WARNING),
            ("db", Severity.WARNING),
            ("dbx", Severity.INFO),
        ):
            result = run_powershell(f"(Get-SecureBootUEFI -Name {key_name}).bytes.Length")
            if result.ok and result.stdout.strip().isdigit() and int(result.stdout.strip()) > 0:
                self.add_finding(
                    f"Secure Boot key present: {key_name}",
                    Severity.INFO,
                    f"{key_name} variable is populated ({result.stdout.strip()} bytes).",
                )
            else:
                label = {
                    "PK": "Platform Key (PK)",
                    "KEK": "Key Exchange Key (KEK)",
                    "db": "signature database (db)",
                    "dbx": "forbidden signature database (dbx)",
                }[key_name]
                self.add_finding(
                    f"Secure Boot key missing or unreadable: {key_name}",
                    severity_if_missing,
                    f"Could not read the {label} UEFI variable. If Secure Boot "
                    "is enabled this is unexpected and worth investigating; "
                    "an empty dbx specifically means no firmware/bootloader "
                    "revocations have ever been applied.",
                )

    def _secure_boot_linux(self) -> None:
        if which("mokutil"):
            result = run_command(["mokutil", "--sb-state"])
            if result.ok:
                state = result.stdout.strip().lower()
                if "enabled" in state:
                    self.add_finding(
                        "Secure Boot enabled",
                        Severity.INFO,
                        f"mokutil reports: {result.stdout.strip()}",
                    )
                else:
                    self.add_finding(
                        "Secure Boot disabled",
                        Severity.CRITICAL,
                        f"mokutil reports: {result.stdout.strip()}. Unsigned "
                        "bootloaders/kernels can execute.",
                        remediation="Enable Secure Boot in UEFI firmware settings.",
                    )
                self._secure_boot_keys_linux()
                return

        # Fallback with no external tools: read the efivars directly.
        sb_var = self._read_efivar("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
        if sb_var is None:
            self.add_finding(
                "Secure Boot state unknown",
                Severity.WARNING,
                "Neither mokutil nor a readable SecureBoot EFI variable was "
                "found. System may be legacy BIOS or efivarfs is not mounted.",
                remediation="Install mokutil, or verify /sys/firmware/efi/efivars is mounted.",
            )
            return
        enabled = sb_var[-1:] == b"\x01"
        self.add_finding(
            "Secure Boot enabled" if enabled else "Secure Boot disabled",
            Severity.INFO if enabled else Severity.CRITICAL,
            f"Read directly from efivarfs: SecureBoot={'1' if enabled else '0'}.",
        )
        self._secure_boot_keys_linux()

    def _secure_boot_keys_linux(self) -> None:
        # PK and KEK live under EFI_GLOBAL_VARIABLE_GUID; db and dbx live
        # under the separate EFI_IMAGE_SECURITY_DATABASE_GUID. Using the
        # wrong GUID silently fails to find the variable, so this matters.
        global_guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
        sig_db_guid = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
        for key_name, guid, severity_if_missing in (
            ("PK", global_guid, Severity.WARNING),
            ("KEK", global_guid, Severity.WARNING),
            ("db", sig_db_guid, Severity.WARNING),
            ("dbx", sig_db_guid, Severity.INFO),
        ):
            data = self._read_efivar(f"{key_name}-{guid}")
            if data:
                self.add_finding(
                    f"Secure Boot key present: {key_name}",
                    Severity.INFO,
                    f"{key_name} variable is populated ({len(data)} bytes).",
                )
            else:
                self.add_finding(
                    f"Secure Boot key missing or unreadable: {key_name}",
                    severity_if_missing,
                    f"Could not read the {key_name} EFI variable.",
                )

    @staticmethod
    def _read_efivar(var_name: str) -> bytes | None:
        if is_mock_mode():
            from anchorroot.mocks import mock_efivar

            raw = mock_efivar(var_name)
            return raw[4:] if raw else None
        path = f"/sys/firmware/efi/efivars/{var_name}"
        try:
            with open(path, "rb") as fh:
                # First 4 bytes are EFI variable attributes, not payload.
                return fh.read()[4:]
        except OSError:
            return None

    # -- CHIPSEC register-level checks -----------------------------------

    def _audit_chipsec_registers(self) -> None:
        chipsec_bin = which("chipsec_main") or which("chipsec_main.py")
        if not chipsec_bin:
            self.add_finding(
                "CHIPSEC not available",
                Severity.INFO,
                "chipsec_main was not found on PATH. SPI flash write "
                "protection and SMM lock bit register state were NOT "
                "evaluated -- these require CHIPSEC's kernel driver.",
                remediation="Install CHIPSEC (pip install chipsec) and its "
                "kernel driver, then re-run this module elevated.",
            )
            return
        if not is_elevated():
            self.add_finding(
                "CHIPSEC checks skipped",
                Severity.WARNING,
                "CHIPSEC is installed but this process is not elevated. "
                "Register-level SPI/SMM checks require raw MSR/PCI access.",
                remediation="Re-run as root/Administrator.",
            )
            return

        self._run_chipsec_module(
            chipsec_bin,
            "common.bios_wp",
            finding_title="SPI flash write protection (BIOS_WP)",
            failure_description=(
                "BIOS region of SPI flash is NOT write-protected. Malware "
                "with sufficient local privilege could flash a modified "
                "firmware image, surviving OS reinstalls."
            ),
            failure_remediation=(
                "Enable BIOS Write Protect (set BIOSWE=0, BLE=1, SMM_BWP=1) "
                "in firmware; update firmware/vendor tooling if the option "
                "is missing."
            ),
        )
        self._run_chipsec_module(
            chipsec_bin,
            "common.smm",
            finding_title="SMM lock bit (SMM_BWP / D_LCK)",
            failure_description=(
                "System Management Mode configuration is not locked. An "
                "attacker able to write to flash could persist code that "
                "executes in SMM, invisible to the OS and most EDR."
            ),
            failure_remediation=(
                "Ensure firmware locks SMRAM (D_LCK) and SMM BIOS write "
                "protection at boot; check for a pending firmware update."
            ),
        )
        self._run_chipsec_module(
            chipsec_bin,
            "common.spi_lock",
            finding_title="SPI flash controller lock",
            failure_description=(
                "SPI flash controller access controls (e.g. FLOCKDN) are "
                "not locked, leaving flash descriptor regions modifiable."
            ),
            failure_remediation="Update firmware; verify vendor has locked FLOCKDN at boot.",
        )

    def _run_chipsec_module(
        self,
        chipsec_bin: str,
        module: str,
        *,
        finding_title: str,
        failure_description: str,
        failure_remediation: str,
    ) -> None:
        result = run_command([chipsec_bin, "-m", module], timeout=90.0)
        output = result.stdout + result.stderr

        if result.timed_out:
            self.add_finding(
                f"{finding_title}: check timed out",
                Severity.WARNING,
                f"chipsec_main -m {module} did not complete within the timeout.",
            )
            return
        if result.returncode == 127:
            self.add_finding(
                f"{finding_title}: CHIPSEC unavailable",
                Severity.INFO,
                "chipsec_main disappeared between PATH lookup and execution.",
            )
            return

        # CHIPSEC's CLI prints lines like "[+] PASSED: ..." / "[-] FAILED: ...".
        if re.search(r"\bFAILED\b", output):
            self.add_finding(
                finding_title,
                Severity.CRITICAL,
                failure_description,
                remediation=failure_remediation,
                chipsec_module=module,
                raw_output=output[-2000:],
            )
        elif re.search(r"\bPASSED\b", output):
            self.add_finding(
                finding_title,
                Severity.INFO,
                "CHIPSEC reports this protection is correctly configured.",
                chipsec_module=module,
            )
        elif re.search(r"\bWARNING\b", output):
            self.add_finding(
                finding_title,
                Severity.WARNING,
                "CHIPSEC could not conclusively verify this protection "
                "(unsupported platform or partial register access).",
                chipsec_module=module,
                raw_output=output[-2000:],
            )
        else:
            self.add_finding(
                f"{finding_title}: inconclusive",
                Severity.WARNING,
                "CHIPSEC ran but produced unrecognized output; manual "
                "review of the raw output is recommended.",
                chipsec_module=module,
                raw_output=output[-2000:],
            )
