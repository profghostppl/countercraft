"""
Advanced Module: Coprocessor & Out-of-Band Management Auditor.

Audits the independent CPU coprocessor (Intel Management Engine / AMD
Platform Security Processor) that runs regardless of OS state, plus
Intel AMT out-of-band management provisioning.

Deliberately conservative about what it claims: reading the actual
HAP/AltMeDisable bit or ME operating mode requires either a vendor tool
(Intel's MEInfo / the coreboot project's `intelmetool`, which reads PCI
config space and needs root + /dev/mem access) or vendor-signed HECI
commands. Where those aren't available, this module reports presence
and HECI/driver accessibility -- which is itself meaningful, since a
missing MEI device node combined with a firmware-level "Intel ME
disabled" note (HAP bit) is a stronger security posture than a fully
enabled, provisioned ME -- and says plainly what it could not verify
rather than guessing.

The AMT out-of-band port probe (TCP 16992/16993) is the one check here
that's fully self-contained: AMT listens on those ports at the NIC level
independent of OS firewall state when provisioned, so a successful
connect is a hard, unambiguous signal.
"""

from __future__ import annotations

import socket

from countercraft.core.base import BaseAuditor
from countercraft.core.models import Severity
from countercraft.core.utils import is_linux, is_mock_mode, is_windows, run_command, run_powershell, which

_AMT_PORTS = {16992: "AMT (unencrypted HTTP)", 16993: "AMT (TLS/HTTPS)"}


class MeAuditor(BaseAuditor):
    name = "me"
    description = "Intel ME / AMD PSP presence and Intel AMT out-of-band exposure."
    requires_root = False  # HECI presence checks are unprivileged; degrades for deep ME state

    def audit(self) -> None:
        vendor = self._detect_vendor()
        if vendor == "intel":
            self._audit_intel_me()
        elif vendor == "amd":
            self._audit_amd_psp()
        else:
            self.add_finding(
                "CPU vendor undetermined",
                Severity.INFO,
                "Could not determine CPU vendor to select ME vs. PSP checks.",
            )
        self._probe_amt_ports()

    # -- vendor detection -----------------------------------------------

    @staticmethod
    def _detect_vendor() -> str | None:
        if is_linux():
            try:
                cpuinfo = open("/proc/cpuinfo").read().lower()
            except OSError:
                cpuinfo = ""
            if "genuineintel" in cpuinfo:
                return "intel"
            if "authenticamd" in cpuinfo:
                return "amd"
        elif is_windows():
            result = run_powershell(
                "(Get-CimInstance Win32_Processor).Manufacturer"
            )
            manufacturer = result.stdout.strip().lower()
            if "intel" in manufacturer:
                return "intel"
            if "amd" in manufacturer:
                return "amd"
        return None

    # -- Intel ME ---------------------------------------------------------

    def _audit_intel_me(self) -> None:
        if is_linux():
            self._intel_me_linux()
        elif is_windows():
            self._intel_me_windows()

    def _intel_me_linux(self) -> None:
        from pathlib import Path

        mei_nodes = [p for p in ("/dev/mei0", "/dev/mei") if Path(p).exists()]
        if mei_nodes:
            self.add_finding(
                "Intel ME HECI interface present",
                Severity.INFO,
                f"Host-to-ME interface node found ({mei_nodes[0]}); the ME "
                "is active and accepting host commands.",
            )
        else:
            self.add_finding(
                "Intel ME HECI interface not present",
                Severity.INFO,
                "No /dev/mei0 device node found. This means either the ME "
                "is disabled (e.g. HAP bit set) or the mei_me kernel "
                "module is not loaded -- these are not distinguishable "
                "from userspace without a vendor tool.",
            )

        intelmetool = which("intelmetool")
        if intelmetool:
            result = run_command([intelmetool, "-m"], timeout=20.0)
            self._parse_intelmetool(result.stdout + result.stderr)
        else:
            self.add_finding(
                "ME operating mode not evaluated",
                Severity.INFO,
                "intelmetool not found on PATH. HAP/AltMeDisable bit state "
                "and ME operating mode (Normal/Recovery/Manufacturing) "
                "were NOT verified.",
                remediation="Install intelmetool (from the coreboot "
                "project) and re-run elevated for HAP bit verification, "
                "or check with Intel's MEInfo/MEManuf tools.",
            )

    def _parse_intelmetool(self, output: str) -> None:
        lower = output.lower()
        if "hap" in lower and ("set" in lower or "disabled" in lower):
            self.add_finding(
                "Intel ME disabled via HAP bit",
                Severity.INFO,
                "intelmetool reports the High Assurance Platform (HAP) "
                "bit is set -- ME is running in a minimal, largely "
                "disabled state.",
                raw_output=output[-1500:],
            )
        elif "manufacturing mode" in lower:
            self.add_finding(
                "Intel ME left in Manufacturing Mode",
                Severity.CRITICAL,
                "ME reports Manufacturing Mode is still active. This mode "
                "exposes extensive low-level configuration and debugging "
                "access and must be closed before deployment.",
                remediation="Contact the OEM for guidance on closing "
                "Manufacturing Mode, or reflash with a firmware image "
                "that has it disabled.",
                raw_output=output[-1500:],
            )
        elif "recovery" in lower:
            self.add_finding(
                "Intel ME in Recovery mode",
                Severity.WARNING,
                "ME reports it is running in Recovery mode rather than "
                "Normal operation.",
                raw_output=output[-1500:],
            )
        else:
            self.add_finding(
                "Intel ME mode: Normal (assumed)",
                Severity.INFO,
                "intelmetool ran without reporting HAP/Recovery/"
                "Manufacturing indicators; ME appears to be in its "
                "default Normal operating mode.",
                raw_output=output[-1500:],
            )

    def _intel_me_windows(self) -> None:
        result = run_powershell(
            "Get-PnpDevice | Where-Object { $_.FriendlyName -match "
            "'Management Engine' } | Select-Object FriendlyName,Status | "
            "ConvertTo-Json -Compress"
        )
        if result.ok and result.stdout.strip():
            self.add_finding(
                "Intel ME device present",
                Severity.INFO,
                f"MEI device found: {result.stdout.strip()}",
            )
        else:
            self.add_finding(
                "Intel ME device not found",
                Severity.INFO,
                "No Intel Management Engine Interface device was found "
                "via PnP enumeration; ME may be disabled or the driver "
                "is not installed.",
            )
        self.add_finding(
            "ME operating mode not evaluated",
            Severity.INFO,
            "HAP bit / ME operating mode (Normal/Recovery/Manufacturing) "
            "verification requires Intel's MEInfo tool (part of the "
            "Intel CSME System Tools kit), which is not invoked "
            "automatically here.",
            remediation="Run Intel's MEInfo.exe (from Intel CSME System "
            "Tools) elevated for authoritative ME mode/version data.",
        )
        lms = run_powershell(
            "Get-Service -Name LMS -ErrorAction SilentlyContinue | "
            "Select-Object Status | ConvertTo-Json -Compress"
        )
        if lms.ok and lms.stdout.strip():
            self.add_finding(
                "Intel LMS (AMT) service present",
                Severity.INFO,
                "The Intel Local Management Service is installed, "
                "indicating AMT/vPro support is present on this platform.",
                raw_output=lms.stdout.strip(),
            )

    # -- AMD PSP ---------------------------------------------------------

    def _audit_amd_psp(self) -> None:
        if is_linux():
            self._amd_psp_linux()
        else:
            self.add_finding(
                "AMD PSP not evaluated",
                Severity.INFO,
                "AMD Platform Security Processor state inspection is only "
                "implemented for Linux in this build (via kernel "
                "`ccp`/`sp5100_tco` driver presence and dmesg).",
            )

    def _amd_psp_linux(self) -> None:
        from pathlib import Path

        result = run_command(["lsmod"], timeout=10.0)
        has_ccp = result.ok and any(line.startswith("ccp ") for line in result.stdout.splitlines())
        if has_ccp:
            self.add_finding(
                "AMD PSP driver loaded",
                Severity.INFO,
                "The `ccp` kernel module (AMD Cryptographic Coprocessor / "
                "PSP interface) is loaded, confirming the PSP is active "
                "and accessible from the host OS.",
            )
        else:
            self.add_finding(
                "AMD PSP driver not loaded",
                Severity.INFO,
                "No `ccp` kernel module loaded. The PSP may still be "
                "active at the firmware level (it manages Secure Boot "
                "attestation regardless of OS driver state) -- this only "
                "reflects host-OS-visible PSP interface availability.",
            )
        sysfs = Path("/sys/bus/platform/drivers/amd_hsti")
        if sysfs.exists():
            self.add_finding(
                "AMD HSTI interface present",
                Severity.INFO,
                "Hardware Security Test Interface sysfs node found "
                f"({sysfs}); platform security fuse state can be queried "
                "through it for deeper HSTI-based verification.",
            )

    # -- Intel AMT out-of-band port probe -------------------------------

    def _probe_amt_ports(self) -> None:
        if is_mock_mode():
            # Deterministic demo data instead of a real (harmless, but
            # environment-dependent) loopback connect attempt -- shows the
            # CRITICAL path without relying on anything actually listening.
            open_ports = [(16992, _AMT_PORTS[16992])]
        else:
            open_ports = []
            for port, label in _AMT_PORTS.items():
                if self._tcp_connect("127.0.0.1", port) or self._tcp_connect(self._local_ip(), port):
                    open_ports.append((port, label))

        if open_ports:
            details = ", ".join(f"{p}/tcp ({label})" for p, label in open_ports)
            self.add_finding(
                "Intel AMT out-of-band management port listening",
                Severity.CRITICAL,
                f"Detected an open connection to {details}. This indicates "
                "AMT is provisioned and actively listening for out-of-band "
                "management, which operates independently of the host OS "
                "and its firewall -- anyone with network access and valid "
                "(or default/weak) AMT credentials can control this "
                "machine below the OS.",
                remediation="If AMT/vPro management is not intentionally "
                "in use, unprovision it (Intel MEBx / ACUConfig) or "
                "restrict network access to these ports at the switch/"
                "firewall level. Rotate AMT admin credentials if unsure "
                "of provisioning history.",
                open_ports=[p for p, _ in open_ports],
            )
        else:
            self.add_finding(
                "No AMT out-of-band ports detected listening",
                Severity.INFO,
                "TCP 16992/16993 did not respond -- AMT is either not "
                "present, not provisioned, or not listening on this "
                "interface. Note this probe only checks the local host's "
                "own address(es); AMT may still be reachable on other "
                "network segments if it has a dedicated NIC path.",
            )

    @staticmethod
    def _tcp_connect(host: str, port: int, timeout: float = 0.75) -> bool:
        if not host:
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def _local_ip() -> str | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return None
