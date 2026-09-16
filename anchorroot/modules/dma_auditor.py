"""
Advanced Module: IOMMU & Kernel DMA Attack Surface Inspector.

Checks whether the platform is actually enforcing IOMMU-based DMA
remediation (Intel VT-d / AMD-Vi) rather than just supporting it in
silicon -- the distinction that matters for Thunderbolt/USB4/PCIe
DMA attacks (e.g. Thunderclap-style implants).

Linux: cross-checks three independent signals so a single misleading
source doesn't produce a false pass/fail:
  - /proc/cmdline for an explicit iommu enablement flag
  - dmesg / kernel ring buffer for "DMAR: IOMMU enabled" (Intel) or
    "AMD-Vi: ... enabled" (AMD)
  - /sys/kernel/iommu_groups/ actually being populated

Windows: shells out to `msinfo32 /report`, the documented, supported way
to read the same "Kernel DMA Protection" status shown in System
Information -- deliberately avoided poking undocumented registry keys.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from anchorroot.core.base import BaseAuditor
from anchorroot.core.models import Severity
from anchorroot.core.utils import is_linux, is_windows, run_command


class DmaAuditor(BaseAuditor):
    name = "dma"
    description = "IOMMU (VT-d/AMD-Vi) enforcement and Kernel DMA Protection status."
    requires_root = False  # dmesg may need root on some distros; degrades to other signals

    def audit(self) -> None:
        if is_linux():
            self._audit_linux()
        elif is_windows():
            self._audit_windows()
        else:
            self.add_finding(
                "IOMMU check unsupported",
                Severity.INFO,
                "DMA protection verification is only implemented for Linux and Windows.",
            )

    # -- Linux ---------------------------------------------------------------

    def _audit_linux(self) -> None:
        cmdline_enabled = self._check_cmdline()
        dmesg_enabled = self._check_dmesg()
        groups_populated = self._check_iommu_groups()
        self._check_external_bus_dma(groups_populated)

        # dmesg is the strongest positive signal (it reflects what the kernel
        # actually did at boot, not just what was requested); iommu_groups
        # existing is corroborating evidence. Cmdline alone only shows intent.
        if dmesg_enabled is True or groups_populated is True:
            self.add_finding(
                "IOMMU translation active",
                Severity.INFO,
                "Kernel reports IOMMU (VT-d/AMD-Vi) is enabled and DMA "
                "remapping is active.",
                cmdline_requests_iommu=cmdline_enabled,
                dmesg_confirms=dmesg_enabled,
                iommu_groups_populated=groups_populated,
            )
        elif cmdline_enabled is False and dmesg_enabled is False:
            self.add_finding(
                "IOMMU not enabled",
                Severity.CRITICAL,
                "No evidence the IOMMU is enabled: kernel cmdline does not "
                "request it and dmesg shows no DMAR/AMD-Vi activation. "
                "External buses (Thunderbolt/USB4/PCIe) are exposed to "
                "unrestricted DMA from attached peripherals.",
                remediation="Add `intel_iommu=on` (Intel) or `amd_iommu=on` "
                "(AMD) to kernel boot parameters, or verify VT-d/AMD-Vi is "
                "enabled in UEFI firmware settings.",
                cmdline_requests_iommu=cmdline_enabled,
                dmesg_confirms=dmesg_enabled,
            )
        else:
            self.add_finding(
                "IOMMU state inconclusive",
                Severity.WARNING,
                "Could not conclusively confirm IOMMU enforcement from "
                "available signals (dmesg may be permission-restricted).",
                remediation="Re-run elevated, or manually check "
                "`dmesg | grep -Ei 'DMAR|AMD-Vi'` and "
                "`ls /sys/kernel/iommu_groups/`.",
                cmdline_requests_iommu=cmdline_enabled,
                dmesg_confirms=dmesg_enabled,
                iommu_groups_populated=groups_populated,
            )

    @staticmethod
    def _check_cmdline() -> bool | None:
        try:
            cmdline = Path("/proc/cmdline").read_text()
        except OSError:
            return None
        return bool(re.search(r"\b(intel_iommu=on|amd_iommu=on|iommu=pt|iommu=force)\b", cmdline))

    @staticmethod
    def _check_dmesg() -> bool | None:
        result = run_command(["dmesg"], timeout=10.0)
        if not result.ok:
            # Many distros restrict dmesg to root (kernel.dmesg_restrict=1);
            # try the persistent kernel log as a fallback.
            result = run_command(["journalctl", "-k", "--no-pager"], timeout=10.0)
            if not result.ok:
                return None
        text = result.stdout
        if re.search(r"DMAR:\s*IOMMU enabled", text, re.IGNORECASE):
            return True
        if re.search(r"AMD-Vi.*(enabled|IOMMU performance counters)", text, re.IGNORECASE):
            return True
        if re.search(r"DMAR:|AMD-Vi:", text):
            return False  # subsystem logged but did not report enablement
        return None  # no relevant lines at all -- inconclusive, not "off"

    @staticmethod
    def _check_iommu_groups() -> bool | None:
        path = Path("/sys/kernel/iommu_groups")
        if not path.is_dir():
            return False
        try:
            return any(path.iterdir())
        except OSError:
            return None

    def _check_external_bus_dma(self, groups_populated: bool | None) -> None:
        lspci = run_command(["lspci"], timeout=10.0)
        if not lspci.ok:
            return
        thunderbolt_lines = [
            line for line in lspci.stdout.splitlines()
            if re.search(r"thunderbolt|usb4", line, re.IGNORECASE)
        ]
        if not thunderbolt_lines:
            return

        if groups_populated:
            self.add_finding(
                "External DMA-capable bus present, IOMMU active",
                Severity.INFO,
                f"Thunderbolt/USB4 controller detected "
                f"({thunderbolt_lines[0].strip()}); IOMMU grouping is in "
                "effect so attached devices are DMA-isolated.",
            )
        else:
            self.add_finding(
                "External DMA-capable bus present without confirmed IOMMU",
                Severity.CRITICAL,
                f"Thunderbolt/USB4 controller detected "
                f"({thunderbolt_lines[0].strip()}) but IOMMU enforcement "
                "could not be confirmed. This bus can grant plugged-in "
                "devices direct memory access.",
                remediation="Enable IOMMU (see above) and/or restrict "
                "Thunderbolt security level to 'User Authorization' or "
                "higher (bolt / Settings > Thunderbolt).",
            )

    # -- Windows ---------------------------------------------------------------

    def _audit_windows(self) -> None:
        status = self._read_kernel_dma_protection()
        if status is None:
            self.add_finding(
                "Kernel DMA Protection status unknown",
                Severity.WARNING,
                "Could not read Kernel DMA Protection status via "
                "`msinfo32 /report`.",
                remediation="Manually check System Information "
                "(msinfo32.exe) -> System Summary -> Kernel DMA Protection.",
            )
        elif status:
            self.add_finding(
                "Kernel DMA Protection enabled",
                Severity.INFO,
                "System Information reports Kernel DMA Protection is On. "
                "External PCIe-based peripherals (Thunderbolt/USB4) are "
                "restricted to IOMMU-isolated DMA remapping.",
            )
        else:
            self.add_finding(
                "Kernel DMA Protection disabled",
                Severity.CRITICAL,
                "System Information reports Kernel DMA Protection is Off. "
                "This typically means the CPU/firmware lack the required "
                "support, or it was explicitly disabled -- attached "
                "Thunderbolt/USB4 peripherals can perform unrestricted DMA.",
                remediation="Confirm VT-d/AMD-Vi is enabled in UEFI "
                "firmware; Kernel DMA Protection requires firmware-level "
                "IOMMU support to be present at boot and cannot be "
                "toggled purely in the OS.",
            )

        self._check_thunderbolt_pnp()

    @staticmethod
    def _read_kernel_dma_protection() -> bool | None:
        with tempfile.TemporaryDirectory(prefix="anchorroot_dma_") as tmp:
            report_path = Path(tmp) / "sysreport.txt"
            result = run_command(
                ["msinfo32", "/report", str(report_path)], timeout=90.0
            )
            if not report_path.is_file():
                return None
            try:
                text = report_path.read_text(errors="ignore", encoding="utf-16")
            except (OSError, UnicodeError):
                try:
                    text = report_path.read_text(errors="ignore")
                except OSError:
                    return None

        return DmaAuditor._parse_kernel_dma_protection_text(text)

    @staticmethod
    def _parse_kernel_dma_protection_text(text: str) -> bool | None:
        """Pure parsing logic, split out from I/O for direct unit testing."""
        match = re.search(r"Kernel DMA Protection\s+(.+)", text)
        if not match:
            return None
        value = match.group(1).strip().lower()
        if value.startswith("on"):
            return True
        if value.startswith("off"):
            return False
        return None

    def _check_thunderbolt_pnp(self) -> None:
        from anchorroot.core.utils import run_powershell

        result = run_powershell(
            "Get-PnpDevice | Where-Object { $_.FriendlyName -match "
            "'Thunderbolt|USB4' } | Select-Object -First 1 FriendlyName | "
            "ConvertTo-Json -Compress"
        )
        if result.ok and result.stdout.strip():
            self.add_finding(
                "External DMA-capable bus present",
                Severity.INFO,
                "A Thunderbolt/USB4 controller was detected; ensure "
                "Kernel DMA Protection (above) is enabled and Thunderbolt "
                "security is set to at least User Authorization in the "
                "vendor control panel.",
            )
