"""
Shared pytest fixtures for the Anchorroot test suite: automatic
mock-mode reset between tests, and canned TPM / dmesg / EFI-variable
payloads that individual auditor tests can build on instead of
hand-rolling the same synthetic data.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Callable

import pytest

import anchorroot.core.utils as core_utils

# EFI_CERT_SHA256_GUID (little-endian per the on-disk EFI_SIGNATURE_LIST
# format) -- see anchorroot/modules/ca_auditor.py for the authoritative
# derivation and usage.
_EFI_CERT_SHA256_GUID = struct.pack(
    "<IHH8s", 0xC1C41626, 0x504C, 0x4092, bytes([0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28])
)


@pytest.fixture(autouse=True)
def _reset_mock_mode():
    """
    Global mock-mode toggle affects every module's behavior, so it must
    never leak from one test into the next regardless of pass/fail.
    Autouse means every test in the suite gets this for free.
    """
    core_utils.set_mock_mode(False)
    yield
    core_utils.set_mock_mode(False)


@pytest.fixture
def tpm_pcrread_output() -> str:
    """Sample `tpm2_pcrread sha256` output covering the PCRs Anchorroot cares about."""
    return (
        "sha256:\n"
        "  0 : 0x1111111111111111111111111111111111111111111111111111111111111111\n"
        "  1 : 0x2222222222222222222222222222222222222222222222222222222222222222\n"
        "  2 : 0x3333333333333333333333333333333333333333333333333333333333333333\n"
        "  4 : 0x4444444444444444444444444444444444444444444444444444444444444444\n"
        "  7 : 0x7777777777777777777777777777777777777777777777777777777777777777\n"
    )


@pytest.fixture
def dmesg_iommu_enabled() -> str:
    """Sample dmesg output confirming Intel VT-d IOMMU translation is active."""
    return "DMAR: IOMMU enabled\nDMAR: Intel(R) Virtualization Technology for Directed I/O\n"


@pytest.fixture
def dmesg_iommu_absent() -> str:
    """Sample dmesg output with no IOMMU-related lines at all (inconclusive, not "off")."""
    return "Linux version 6.5.0\n"


@pytest.fixture
def efivar_sha256_sig_list() -> Callable[[list[bytes]], bytes]:
    """
    Factory building a synthetic EFI_SIGNATURE_LIST (the dbx wire format)
    containing the given SHA-256 digests. Use like:

        def test_x(efivar_sha256_sig_list):
            h = hashlib.sha256(b"revoked-bootloader").digest()
            data = efivar_sha256_sig_list([h])
    """

    def _build(hashes: list[bytes]) -> bytes:
        sig_size = 16 + 32  # owner GUID + sha256 digest
        entries = b"".join((b"\x00" * 16) + h for h in hashes)
        list_size = struct.calcsize("<16sIII") + len(entries)
        header = struct.pack("<16sIII", _EFI_CERT_SHA256_GUID, list_size, 0, sig_size)
        return header + entries

    return _build


@pytest.fixture
def sample_dbx_hash() -> Callable[[str], bytes]:
    """Deterministic 32-byte "hash" for a named fixture bootloader, for use with efivar_sha256_sig_list."""

    def _hash(label: str) -> bytes:
        return hashlib.sha256(label.encode()).digest()

    return _hash
