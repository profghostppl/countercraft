"""
Advanced Module: Root CA Store & UEFI Revocation (dbx) Inspector.

Two independent trust-store checks:

1. System Root CA Store Scrutiny -- enumerates installed root CAs and
   flags known OEM-adware CA names (Superfish/Komodia, eDellRoot,
   PrivDog-style local MITM proxies) by name-pattern denylist, plus
   optionally cross-references fingerprints against a locally supplied
   snapshot of the Mozilla Included CA list for a broader "not a
   recognized public root" signal.

   We do NOT ship a hardcoded copy of the Mozilla CA list in this repo --
   it changes over time and bundling a stale copy would itself become a
   source of false positives/negatives. Pass one in via
   `--mozilla-ca-list` (a JSON array of lowercase SHA-256 fingerprints,
   easily produced from Mozilla's published CCADB CSV) to enable that
   check; without it, this module still runs the denylist check, which
   needs no external data.

2. UEFI `dbx` (forbidden signature database) inspection -- reads the
   live EFI variable and reports how many revocation entries are
   present. Matching specific entries against named CVEs (e.g.
   BlackLotus/CVE-2023-24932, Baton Drop/CVE-2022-34301) requires the
   authoritative hash list from the relevant Microsoft/vendor security
   advisory; we accept that as an optional input rather than embedding
   specific hashes here, since embedding stale or wrong hashes would be
   actively misleading for a security tool.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Optional

from countercraft.core.base import BaseAuditor
from countercraft.core.models import Severity
from countercraft.core.utils import is_linux, is_mock_mode, is_windows, run_command, run_powershell

# Case-insensitive substring matches against CA "Subject" strings. Sourced
# from widely reported OEM-bundled MITM/adware CA incidents (Superfish/
# Komodia 2015, eDellRoot / DSDTestProvider 2015, PrivDog 2015). Extend as
# new incidents are publicly documented -- do not add unverified entries.
_KNOWN_BAD_CA_PATTERNS = (
    "superfish",
    "komodia",
    "edellroot",
    "dsdtestprovider",
    "privdog",
)

# EFI_CERT_SHA256_GUID = {0xc1c41626, 0x504c, 0x4092,
#   {0xac,0xa9,0x41,0xf9,0x36,0x93,0x43,0x28}}, identifying SHA-256 hash
# entries within an EFI_SIGNATURE_LIST (the dbx wire format). GUIDs in
# this on-disk format are little-endian for the first three fields.
_EFI_CERT_SHA256_GUID = struct.pack(
    "<IHH8s", 0xC1C41626, 0x504C, 0x4092, bytes([0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28])
)


class CaAuditor(BaseAuditor):
    name = "ca"
    description = "Root CA store scrutiny and UEFI dbx (revocation list) inspection."
    requires_root = False

    def __init__(
        self,
        mozilla_ca_fingerprints_path: Optional[Path] = None,
        expected_dbx_hashes_path: Optional[Path] = None,
    ) -> None:
        super().__init__()
        self.mozilla_ca_fingerprints_path = mozilla_ca_fingerprints_path
        self.expected_dbx_hashes_path = expected_dbx_hashes_path

    def audit(self) -> None:
        self._audit_ca_store()
        self._audit_dbx()

    # -- CA store ------------------------------------------------------

    def enumerate_root_cas(self) -> Optional[list[tuple[str, str]]]:
        """
        Public, side-effect-focused enumeration (subject, fingerprint)
        pairs -- used both by `_audit_ca_store` below and by
        `core.diff`'s snapshot collector, which wants the raw data
        without generating Findings for it.

        Deliberately tries the real per-OS path *first* even in mock
        mode: `_enumerate_ca_linux`/`_enumerate_ca_windows` already run
        unmodified against mocked command output (via
        `core.utils.run_command`), so they exercise the actual code under
        test rather than a separate, easily-drifting duplicate. The
        standalone `MOCK_ROOT_CAS` fixture is only a last-resort fallback
        for a platform with no real collector (e.g. macOS) running mock mode.
        """
        if is_linux():
            return self._enumerate_ca_linux()
        if is_windows():
            return self._enumerate_ca_windows()
        if is_mock_mode():
            from countercraft.mocks import MOCK_ROOT_CAS

            return [(subject, fingerprint) for fingerprint, subject in MOCK_ROOT_CAS.items()]
        return None

    def _audit_ca_store(self) -> None:
        certs = self.enumerate_root_cas()
        if certs is None and not (is_linux() or is_windows()):
            self.add_finding(
                "CA store check unsupported",
                Severity.INFO,
                "Root CA store enumeration is only implemented for Linux and Windows.",
            )
            return

        if certs is None:
            return  # enumeration helper already recorded its own finding

        self.add_finding(
            "Root CA store enumerated",
            Severity.INFO,
            f"Found {len(certs)} root CA(s) in the system trust store.",
        )

        known_fingerprints = self._load_mozilla_fingerprints()
        flagged_bad = 0
        flagged_unrecognized = 0
        for subject, fingerprint in certs:
            if self._is_known_bad_ca(subject):
                flagged_bad += 1
                self.add_finding(
                    "Known OEM-adware / MITM CA detected",
                    Severity.CRITICAL,
                    f"Installed root CA '{subject}' matches a known "
                    "adware/MITM certificate pattern (e.g. Superfish/"
                    "Komodia-style). Such CAs let their issuer transparently "
                    "intercept and re-sign TLS traffic for any site.",
                    remediation="Remove this certificate from the trust "
                    "store immediately and uninstall the software that "
                    "installed it; check for an associated local proxy "
                    "process.",
                    subject=subject,
                    fingerprint=fingerprint,
                )
                continue

            if known_fingerprints is not None and fingerprint.lower() not in known_fingerprints:
                flagged_unrecognized += 1
                self.add_finding(
                    "Root CA not in supplied Mozilla CA reference list",
                    Severity.WARNING,
                    f"'{subject}' (sha256={fingerprint}) was not found in "
                    "the supplied Mozilla-derived fingerprint list. This "
                    "is routinely true for legitimate OS/enterprise/"
                    "corporate-proxy CAs, so treat as a manual-review "
                    "prompt, not a verdict.",
                    subject=subject,
                    fingerprint=fingerprint,
                )

        if known_fingerprints is None:
            self.add_finding(
                "Mozilla CA cross-reference not performed",
                Severity.INFO,
                "No --mozilla-ca-list supplied; only the known-bad-name "
                "denylist check was run against the CA store.",
            )
        if flagged_bad == 0 and known_fingerprints is not None and flagged_unrecognized == 0:
            self.add_finding(
                "No unrecognized root CAs",
                Severity.INFO,
                "Every installed root CA matched the supplied Mozilla reference list.",
            )

    def _enumerate_ca_linux(self) -> Optional[list[tuple[str, str]]]:
        import hashlib
        import subprocess

        cert_dir = Path("/etc/ssl/certs")
        if not cert_dir.is_dir():
            self.add_finding(
                "CA store directory not found",
                Severity.WARNING,
                f"{cert_dir} does not exist on this system.",
            )
            return None

        results: list[tuple[str, str]] = []
        pem_files = sorted(cert_dir.glob("*.pem")) + sorted(cert_dir.glob("*.crt"))
        for pem in pem_files:
            if pem.is_symlink() and not pem.resolve().exists():
                continue
            subject_result = run_command(
                ["openssl", "x509", "-noout", "-subject", "-nameopt", "utf8", "-in", str(pem)],
                timeout=5.0,
            )
            fingerprint_result = run_command(
                ["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", str(pem)],
                timeout=5.0,
            )
            if not subject_result.ok or not fingerprint_result.ok:
                continue
            subject = subject_result.stdout.strip().removeprefix("subject=").strip()
            fp_raw = fingerprint_result.stdout.strip().split("=", 1)[-1]
            fingerprint = fp_raw.replace(":", "").lower()
            results.append((subject, fingerprint))

        if not results and not (cert_dir / "ca-certificates.crt").exists():
            self.add_finding(
                "openssl not usable for CA enumeration",
                Severity.WARNING,
                "Could not enumerate any certificates via openssl CLI; is "
                "openssl installed?",
            )
            return None
        return results

    def _enumerate_ca_windows(self) -> Optional[list[tuple[str, str]]]:
        result = run_powershell(
            "Get-ChildItem Cert:\\LocalMachine\\Root | "
            "Select-Object Subject,Thumbprint | ConvertTo-Json -Compress"
        )
        if not result.ok or not result.stdout.strip():
            self.add_finding(
                "Could not enumerate Windows root CA store",
                Severity.WARNING,
                f"Get-ChildItem Cert:\\LocalMachine\\Root failed: "
                f"{result.stderr.strip()}",
            )
            return None
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        # PowerShell can exit 0 while stdout holds a plain string (an error
        # message ConvertTo-Json happily serialized) rather than an object
        # or array -- guard against treating that string as a row.
        rows = data if isinstance(data, list) else [data]
        results = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            subject = row.get("Subject", "")
            thumbprint = (row.get("Thumbprint") or "").lower()
            if subject:
                results.append((subject, thumbprint))
        if not results and rows and not isinstance(rows[0], dict):
            self.add_finding(
                "Unexpected output enumerating Windows root CA store",
                Severity.WARNING,
                f"Get-ChildItem did not return structured data: {str(rows[0])[:200]}",
            )
            return None
        return results

    @staticmethod
    def _is_known_bad_ca(subject: str) -> bool:
        subject_lower = subject.lower()
        return any(pattern in subject_lower for pattern in _KNOWN_BAD_CA_PATTERNS)

    def _load_mozilla_fingerprints(self) -> Optional[set[str]]:
        if not self.mozilla_ca_fingerprints_path:
            return None
        if not self.mozilla_ca_fingerprints_path.is_file():
            self.add_finding(
                "Mozilla CA reference file not found",
                Severity.WARNING,
                f"{self.mozilla_ca_fingerprints_path} does not exist.",
            )
            return None
        try:
            data = json.loads(self.mozilla_ca_fingerprints_path.read_text())
            return {str(fp).lower().replace(":", "") for fp in data}
        except (json.JSONDecodeError, OSError) as exc:
            self.add_finding(
                "Could not parse Mozilla CA reference file",
                Severity.WARNING,
                f"Failed to parse {self.mozilla_ca_fingerprints_path}: {exc}",
            )
            return None

    # -- dbx -------------------------------------------------------------

    def _audit_dbx(self) -> None:
        raw = self._read_dbx_raw()
        if raw is None:
            self.add_finding(
                "Could not read dbx",
                Severity.WARNING,
                "Unable to read the UEFI dbx (forbidden signature database) "
                "variable. System may be legacy BIOS, efivarfs may not be "
                "mounted (Linux), or this process lacks the required access.",
                remediation="On Linux, verify /sys/firmware/efi/efivars is "
                "mounted and readable. On Windows, this requires an "
                "elevated process with SeSystemEnvironmentPrivilege.",
            )
            return

        sha256_hashes = self._parse_signature_list_sha256(raw)
        self.add_finding(
            "dbx read",
            Severity.INFO,
            f"UEFI dbx contains {len(sha256_hashes)} SHA-256 revocation "
            f"entries across {len(raw)} bytes of signature list data.",
        )

        if not sha256_hashes:
            self.add_finding(
                "dbx has no SHA-256 revocation entries",
                Severity.WARNING,
                "No SHA-256 hash entries were found in dbx. An essentially "
                "empty dbx means firmware/bootloader revocations "
                "(including known-vulnerable signed bootloaders) have "
                "likely never been applied via a Secure Boot update.",
                remediation="Apply the latest Secure Boot dbx update for "
                "your platform (via Windows Update / fwupd / vendor tool).",
            )

        expected = self._load_expected_dbx_hashes()
        if expected is None:
            self.add_finding(
                "Specific CVE coverage not evaluated",
                Severity.INFO,
                "No --expected-dbx-hashes supplied, so dbx contents were "
                "not checked for specific known-vulnerable-bootloader "
                "revocations (e.g. BlackLotus/CVE-2023-24932, Baton "
                "Drop/CVE-2022-34301). Supply the authoritative hash list "
                "from the relevant security advisory to enable this check.",
            )
            return

        missing = expected - sha256_hashes
        if missing:
            self.add_finding(
                "dbx missing expected revocation entries",
                Severity.CRITICAL,
                f"{len(missing)} of {len(expected)} expected revocation "
                "hash(es) are absent from the current dbx -- this system "
                "has not received one or more known bootloader "
                "revocations you configured as required.",
                remediation="Apply the missing Secure Boot dbx update.",
                missing_count=len(missing),
                missing_sample=sorted(missing)[:10],
            )
        else:
            self.add_finding(
                "All expected dbx revocations present",
                Severity.INFO,
                f"All {len(expected)} expected revocation hash(es) were "
                "found in the current dbx.",
            )

    def _load_expected_dbx_hashes(self) -> Optional[set[str]]:
        if not self.expected_dbx_hashes_path:
            return None
        if not self.expected_dbx_hashes_path.is_file():
            self.add_finding(
                "Expected dbx hash file not found",
                Severity.WARNING,
                f"{self.expected_dbx_hashes_path} does not exist.",
            )
            return None
        try:
            data = json.loads(self.expected_dbx_hashes_path.read_text())
            return {str(h).lower() for h in data}
        except (json.JSONDecodeError, OSError) as exc:
            self.add_finding(
                "Could not parse expected dbx hash file",
                Severity.WARNING,
                f"Failed to parse {self.expected_dbx_hashes_path}: {exc}",
            )
            return None

    @staticmethod
    def _read_dbx_raw() -> Optional[bytes]:
        if is_mock_mode():
            from countercraft.mocks import mock_efivar

            raw = mock_efivar("dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f")
            return raw[4:] if raw else None
        if is_linux():
            path = Path(
                "/sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
            )
            try:
                # First 4 bytes are the EFI variable attributes, not payload.
                return path.read_bytes()[4:]
            except OSError:
                return None
        if is_windows():
            # Reading raw EFI variable bytes from PowerShell without a
            # compiled helper is unreliable across versions; report the
            # variable's presence/size via the documented cmdlet instead
            # of fabricating a parse of inaccessible data.
            result = run_powershell(
                "(Get-SecureBootUEFI -Name dbx).bytes"
            )
            if not result.ok or not result.stdout.strip():
                return None
            # Get-SecureBootUEFI prints byte values newline/space separated
            # when piped through PowerShell's default formatter.
            try:
                byte_vals = [int(tok) for tok in result.stdout.split()]
                return bytes(byte_vals)
            except ValueError:
                return None
        return None

    @staticmethod
    def _parse_signature_list_sha256(data: bytes) -> set[str]:
        """
        Minimal EFI_SIGNATURE_LIST walker, extracting only
        EFI_CERT_SHA256_GUID entries (the overwhelming majority of dbx
        content). Malformed/unrecognized lists are skipped rather than
        raising, since this is inherently best-effort parsing of a
        firmware-controlled binary blob.
        """
        hashes: set[str] = set()
        offset = 0
        header_fmt = "<16sIII"
        header_size = struct.calcsize(header_fmt)

        while offset + header_size <= len(data):
            sig_type, list_size, header_size_field, sig_size = struct.unpack_from(
                header_fmt, data, offset
            )
            if list_size < header_size or list_size == 0:
                break  # malformed; stop rather than loop forever
            if sig_type == _EFI_CERT_SHA256_GUID and sig_size >= 48:  # 16 owner GUID + 32 hash
                entries_start = offset + header_size + header_size_field
                entries_end = offset + list_size
                pos = entries_start
                while pos + sig_size <= entries_end:
                    hash_bytes = data[pos + 16 : pos + sig_size]  # skip owner GUID
                    hashes.add(hash_bytes.hex())
                    pos += sig_size
            offset += list_size

        return hashes
