"""
Offline mock providers for --mock / --dry-run mode.

A single registry of canned responses for the external tools and OS
interfaces Anchorroot's modules read from: subprocess commands
(tpm2-tools, CHIPSEC, intelmetool, mokutil, driverquery, lsmod, dmesg,
lspci, openssl, osquery, various PowerShell cmdlets, bcdedit, msinfo32)
and the raw EFI variable reads used for Secure Boot keys and dbx.

Consulted from exactly two places, both gated on
`anchorroot.core.utils.is_mock_mode()`:
  - `anchorroot.core.utils.which` / `run_command` (all subprocess-based checks)
  - `uefi_platform._read_efivar` / `ca_auditor._read_dbx_raw` /
    `core.diff` (the handful of direct efivarfs file reads, which don't
    go through run_command at all)

This means every module runs unmodified in mock mode -- it just observes
"the tool is installed" and "here is its output" without knowing the data
is synthetic. The fixtures are deliberately a *mix* of clean and flagged
results (a disabled Secure Boot key, an unsigned kernel module, a
listening AMT port, a Superfish-style CA) so a --mock run exercises and
demonstrates the full severity range, not just the all-clear path.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from anchorroot.core.utils import CommandResult

# -- binaries mock mode pretends are installed -----------------------------

MOCK_AVAILABLE_BINARIES = frozenset(
    {
        "chipsec_main",
        "chipsec_main.py",
        "mokutil",
        "UEFIExtract",
        "binwalk",
        "osqueryi",
        "tpm2_pcrread",
        "intelmetool",
        "openssl",
        "lsmod",
        "modinfo",
        "dmesg",
        "lspci",
        "driverquery",
        "crontab",
        "bcdedit",
        "msinfo32",
    }
)


def mock_which(binary: str) -> str | None:
    return f"/mock/bin/{binary}" if binary in MOCK_AVAILABLE_BINARIES else None


# -- fixture data -----------------------------------------------------------

_MOCK_SHA256_PCR = {
    0: "0x1c2f8b1e2b0d5a7c9f3e6a4d8b1c7e2f5a9d3c6b8e1f4a7d2c5b9e3f6a1d4c7b",
    1: "0x2d3a9c2f3c1e6b8d0a4f7c5e9b2d6a1f4c7e0b3d6a9f2c5e8b1d4a7f0c3e6b9d",
    2: "0x3e4b0d3a4d2f7c9e1b5a8d6f0c3e7b2a5d9f4c7e1b0d3a6f9c2e5b8d1a4f7c0e",
    4: "0x4f5c1e4b5e3a8d0f2c6b9e7a1d4f8c3b6e0a5d9c2f7b1e4a8d3c6e0b9f2a5c8d",
    7: "0x5a6d2f5c6f4b9e1a3d7c0f8b2e5a9d4c7f1b6e0d3a8c2f5b9e4a1d6f0c3b7e2a",
}

MOCK_TPM_PCRREAD_OUTPUT = "sha256:\n" + "\n".join(
    f"  {idx} : {val}" for idx, val in sorted(_MOCK_SHA256_PCR.items())
) + "\n"

_MOCK_CHIPSEC_RESULTS = {
    "common.bios_wp": "[+] PASSED: BIOS Region Write Protection is enabled (BIOSWE=0, BLE=1, SMM_BWP=1)\n",
    "common.smm": "[-] FAILED: SMM_BWP is not set; SMRAM is not fully locked down\n",
    "common.spi_lock": "[+] PASSED: SPI Flash Controller access (FLOCKDN) is locked\n",
}

_MOCK_LSMOD = (
    "Module                  Size  Used by\n"
    "nvidia              12681216  12\n"
    "usb_storage            94208  0\n"
    "coreboot_backdoor       16384  1\n"  # deliberately odd name to demo the unsigned-module WARNING path
)

_MOCK_DRIVERQUERY_CSV = (
    '"Module Name","Display Name","Driver Type","Link Date","Path"\r\n'
    '"ampa","AMD PSP Driver","Kernel","1/1/2024","\\??\\C:\\Windows\\system32\\ampa.sys"\r\n'
    '"acmeoem","Acme OEM Helper","Kernel","1/1/2024","C:\\ProgramData\\AcmeOem\\acmeoem.sys"\r\n'
)

_MOCK_LSPCI = (
    "00:14.0 USB controller: Intel Corporation Alder Lake-P Thunderbolt 4 USB Controller\n"
    "00:1c.0 PCI bridge: Intel Corporation Device 51bc\n"
)

_MOCK_DMESG = "DMAR: IOMMU enabled\nDMAR: Intel(R) Virtualization Technology for Directed I/O\n"

_MOCK_INTELMETOOL = (
    "ME: FW Partition Table      : OK\n"
    "ME: FW status flags: mfg mode: NO, boot options present: NO\n"
    "ME: HAP is set: ME is disabled\n"
)

# CN=<subject> pairs mimicking `openssl x509 -noout -subject/-fingerprint`,
# consumed in the same call order ca_dbx_auditor iterates certificate files.
_MOCK_OPENSSL_SUBJECTS = [
    "subject=CN = DigiCert Global Root CA, O = DigiCert Inc, C = US",
    "subject=CN = ISRG Root X1, O = Internet Security Research Group, C = US",
    "subject=CN = Superfish, Inc., O = Superfish, Inc.",
]
_MOCK_OPENSSL_FINGERPRINTS = [
    "sha256 Fingerprint=A8:98:5D:3A:65:E5:E5:C4:B2:D7:D6:6D:40:C6:DD:2F:B1:9C:54:36:D6:6D:1D:C3:AF:2E:14:1D:68:C6:9F:02",
    "sha256 Fingerprint=96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6",
    "sha256 Fingerprint=DE:AD:BE:EF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB",
]

_openssl_call_index = {"subject": 0, "fingerprint": 0}


def _mock_openssl(args: list[str]) -> CommandResult:
    joined = " ".join(args)
    if "-subject" in joined:
        i = _openssl_call_index["subject"] % len(_MOCK_OPENSSL_SUBJECTS)
        _openssl_call_index["subject"] += 1
        return CommandResult(args=args, returncode=0, stdout=_MOCK_OPENSSL_SUBJECTS[i] + "\n", stderr="")
    if "-fingerprint" in joined:
        i = _openssl_call_index["fingerprint"] % len(_MOCK_OPENSSL_FINGERPRINTS)
        _openssl_call_index["fingerprint"] += 1
        return CommandResult(args=args, returncode=0, stdout=_MOCK_OPENSSL_FINGERPRINTS[i] + "\n", stderr="")
    return CommandResult(args=args, returncode=0, stdout="", stderr="")


_MOCK_BCDEDIT_FIRMWARE = (
    "Firmware Boot Manager\n"
    "----------------------\n"
    "identifier              {fwbootmgr}\n"
    "displayorder            {a11c1234-0000-0000-0000-000000000001}\n"
    "timeout                 1\n"
    "\n"
    "Firmware Application (101fffff)\n"
    "--------------------------------\n"
    "identifier              {a11c1234-0000-0000-0000-000000000001}\n"
    "description             Windows Boot Manager\n"
    "\n"
    "Firmware Application (101fffff)\n"
    "--------------------------------\n"
    "identifier              {a11c1234-0000-0000-0000-000000000002}\n"
    "description             UEFI: Built-in EFI Shell\n"
)


def _mock_msinfo32(args: list[str]) -> CommandResult:
    """
    msinfo32's real output goes to the /report FILE argument, not stdout --
    special-cased so DmaAuditor's file-based read works unmodified.
    """
    report_path = None
    for i, a in enumerate(args):
        if a == "/report" and i + 1 < len(args):
            report_path = args[i + 1]
            break
    if report_path:
        try:
            from pathlib import Path

            Path(report_path).write_text(
                "Kernel DMA Protection\tOn\n", encoding="utf-16"
            )
        except OSError:
            pass
    return CommandResult(args=args, returncode=0, stdout="", stderr="")


# -- subprocess-argv-matched fixtures ---------------------------------------

_CMD_FIXTURES: list[tuple[re.Pattern, CommandResult | None]] = []


def _cmd(pattern: str, stdout: str = "", returncode: int = 0) -> None:
    _CMD_FIXTURES.append((re.compile(pattern), CommandResult(args=[], returncode=returncode, stdout=stdout, stderr="")))


_cmd(r"chipsec_main(\.py)?\s.*common\.bios_wp", _MOCK_CHIPSEC_RESULTS["common.bios_wp"])
_cmd(r"chipsec_main(\.py)?\s.*common\.smm\b", _MOCK_CHIPSEC_RESULTS["common.smm"])
_cmd(r"chipsec_main(\.py)?\s.*common\.spi_lock", _MOCK_CHIPSEC_RESULTS["common.spi_lock"])
_cmd(r"\btpm2_pcrread\b", MOCK_TPM_PCRREAD_OUTPUT)
_cmd(r"\bmokutil\b.*--sb-state", "SecureBoot enabled\n")
_cmd(r"\bintelmetool\b", _MOCK_INTELMETOOL)
_cmd(r"\blsmod\b", _MOCK_LSMOD)
_cmd(r"\bmodinfo\b.*coreboot_backdoor", "")  # unsigned, by design (demo finding)
_cmd(r"\bmodinfo\b", "signer: Mock Signing Authority\n")
_cmd(r"\bdmesg\b", _MOCK_DMESG)
_cmd(r"\blspci\b", _MOCK_LSPCI)
_cmd(r"\bdriverquery\b.*\bcsv\b", _MOCK_DRIVERQUERY_CSV)
_cmd(r"\bcrontab\b\s+-l", "0 3 * * * /usr/bin/logrotate --state /var/lib/logrotate/status\n")
_cmd(r"\bbcdedit\b.*firmware", _MOCK_BCDEDIT_FIRMWARE)
_cmd(r"\bosqueryi\b", "[]")

# -- PowerShell script fixtures ---------------------------------------------

_PS_FIXTURES: list[tuple[re.Pattern, CommandResult]] = []


def _ps(pattern: str, stdout: str = "", returncode: int = 0) -> None:
    _PS_FIXTURES.append((re.compile(pattern), CommandResult(args=[], returncode=returncode, stdout=stdout, stderr="")))


_ps(r"Confirm-SecureBootUEFI", "True\n")
_ps(r"Get-SecureBootUEFI -Name PK", "2696\n")
_ps(r"Get-SecureBootUEFI -Name KEK", "3326\n")
_ps(r"Get-SecureBootUEFI -Name db\b", "9032\n")
_ps(r"Get-SecureBootUEFI -Name dbx", "0\n")  # deliberately empty (demo finding)
_ps(r"\(Get-SecureBootUEFI -Name dbx\)\.bytes", "")
_ps(r"Get-Tpm\b", '{"TpmPresent":true,"TpmReady":true}')
_ps(r"Win32_StartupCommand", "[]")
_ps(r"Get-ScheduledTask\b", "[]")
_ps(r"Get-PnpDevice.*Thunderbolt\|USB4", '{"FriendlyName":"Intel Thunderbolt 4 USB Controller"}')
_ps(r"Get-PnpDevice.*Management Engine", '{"FriendlyName":"Intel(R) Management Engine Interface","Status":"OK"}')
_ps(r"Win32_Processor", "GenuineIntel\n")
_ps(
    r"Cert:\\LocalMachine\\Root",
    '[{"Subject":"CN=DigiCert Global Root CA, O=DigiCert Inc, C=US","Thumbprint":"A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436D66D1DC3AF2E141D68C69F02"},'
    '{"Subject":"CN=Superfish, Inc., O=Superfish, Inc.","Thumbprint":"DEADBEEF00112233445566778899AABBCCDDEEFF0011223344556677889AABB"}]',
)
_ps(r"Get-Service -Name LMS", '{"Status":"Running"}')
_ps(r"msinfo32", "")  # msinfo32 is invoked directly, not via powershell, but keep a harmless fallback


# -- dispatch -----------------------------------------------------------

def mock_command(args: list[str]) -> CommandResult:
    """
    Resolve a subprocess invocation to canned output. Always returns a
    CommandResult (never None / falls through to a real subprocess call)
    -- mock mode must be an absolute guarantee, not a best-effort one.
    """
    if not args:
        return CommandResult(args=args, returncode=0, stdout="", stderr="")

    exe = args[0].lower()
    if "powershell" in exe:
        script = args[-1] if len(args) > 1 else ""
        return mock_powershell(script)

    if exe.endswith("openssl") or exe == "openssl":
        return _mock_openssl(args)

    if exe.endswith("msinfo32") or exe == "msinfo32":
        return _mock_msinfo32(args)

    joined = " ".join(args)
    for pattern, result in _CMD_FIXTURES:
        if pattern.search(joined):
            return CommandResult(args=args, returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)

    # No fixture matched (an unmocked command called mid-development, or a
    # module invoking something new) -- return an empty success rather
    # than ever falling through to a real subprocess call.
    return CommandResult(args=args, returncode=0, stdout="", stderr="")


def mock_powershell(script: str) -> CommandResult:
    for pattern, result in _PS_FIXTURES:
        if pattern.search(script):
            return CommandResult(args=[], returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    return CommandResult(args=[], returncode=0, stdout="", stderr="")


# -- EFI variable fixtures (direct efivarfs-style reads, not subprocess) ---

_EFI_CERT_SHA256_GUID = struct.pack(
    "<IHH8s", 0xC1C41626, 0x504C, 0x4092, bytes([0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28])
)


def _build_signature_list(hashes: list[bytes]) -> bytes:
    sig_size = 16 + 32
    entries = b"".join((b"\x00" * 16) + h for h in hashes)
    list_size = struct.calcsize("<16sIII") + len(entries)
    header = struct.pack("<16sIII", _EFI_CERT_SHA256_GUID, list_size, 0, sig_size)
    return header + entries


def _mock_hash(label: str) -> bytes:
    import hashlib

    return hashlib.sha256(label.encode()).digest()


_MOCK_ATTR_PREFIX = b"\x06\x00\x00\x00"  # NV|BS|RT, a typical Secure Boot variable attribute set

MOCK_EFIVARS: dict[str, bytes] = {
    "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c": _MOCK_ATTR_PREFIX + b"\x01",
    "PK-8be4df61-93ca-11d2-aa0d-00e098032b8c": _MOCK_ATTR_PREFIX + b"\x01" * 32,
    "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c": _MOCK_ATTR_PREFIX + b"\x02" * 64,
    "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f": _MOCK_ATTR_PREFIX + b"\x03" * 128,
    "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f": _MOCK_ATTR_PREFIX
    + _build_signature_list([_mock_hash("revoked-bootloader-1"), _mock_hash("revoked-bootloader-2")]),
}


def mock_efivar(var_name: str) -> bytes | None:
    return MOCK_EFIVARS.get(var_name)


# -- EFI boot manager variable fixtures, for engine.diff -------------------

MOCK_EFI_BOOT_VARIABLES: dict[str, str] = {
    "BootOrder": _mock_hash("BootOrder-0000-0001").hex(),
    "BootCurrent": _mock_hash("BootCurrent-0000").hex(),
    "Boot0000": _mock_hash("Windows Boot Manager").hex(),
    "Boot0001": _mock_hash("UEFI: Built-in EFI Shell").hex(),
}

# -- kernel module list fixture, for engine.diff -----------------------

MOCK_KERNEL_MODULES: list[str] = ["nvidia", "usb_storage", "coreboot_backdoor"]

# -- root CA fixture, for engine.diff (fingerprint -> subject) -------------

MOCK_ROOT_CAS: dict[str, str] = {
    _MOCK_OPENSSL_FINGERPRINTS[0].split("=", 1)[1].replace(":", "").lower(): "CN=DigiCert Global Root CA",
    _MOCK_OPENSSL_FINGERPRINTS[1].split("=", 1)[1].replace(":", "").lower(): "CN=ISRG Root X1",
    _MOCK_OPENSSL_FINGERPRINTS[2].split("=", 1)[1].replace(":", "").lower(): "CN=Superfish, Inc.",
}
