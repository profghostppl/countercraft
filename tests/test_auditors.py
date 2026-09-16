"""
Cross-cutting tests over every registered auditor: the contract each one
must satisfy (BaseAuditor subclass, a stable non-default name, a clean run
under --mock with no raised error), plus a few tests exercising the shared
TPM / dmesg / EFI-variable fixtures from conftest.py directly against the
modules that consume that kind of data. Auditor-specific parsing/behavior
tests live in their own test_<module>.py files -- this file is about the
auditors as a set.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

import anchorroot.core.utils as core_utils
from anchorroot.core.base import BaseAuditor
from anchorroot.core.utils import CommandResult
from anchorroot.modules import (
    CaAuditor,
    DmaAuditor,
    FirmwareIntegrityChecker,
    MeAuditor,
    NetworkAuditor,
    PersistenceAuditor,
    TpmAuditor,
    UefiPlatformAuditor,
)

# NetworkAuditor is deliberately excluded here: it needs a short explicit
# capture duration (its default is 30s), so it gets its own test below
# rather than joining the generic parametrized sweep.
ALL_AUDITOR_CLASSES = [
    UefiPlatformAuditor,
    FirmwareIntegrityChecker,
    PersistenceAuditor,
    TpmAuditor,
    DmaAuditor,
    MeAuditor,
    CaAuditor,
]


@pytest.mark.parametrize("auditor_cls", ALL_AUDITOR_CLASSES)
def test_every_auditor_subclasses_base_auditor(auditor_cls):
    assert issubclass(auditor_cls, BaseAuditor)


@pytest.mark.parametrize("auditor_cls", ALL_AUDITOR_CLASSES)
def test_every_auditor_has_a_stable_lowercase_name(auditor_cls):
    name = auditor_cls().name
    assert name and name != "unnamed"
    assert name == name.lower()
    assert " " not in name


@pytest.mark.parametrize("auditor_cls", ALL_AUDITOR_CLASSES)
def test_every_auditor_runs_cleanly_in_mock_mode(auditor_cls):
    # Deliberately does NOT assert `result.findings` is non-empty: a
    # genuinely clean result (e.g. PersistenceAuditor's mocked osquery
    # backend returning empty rows for every query) is a valid outcome,
    # not a failure -- this test only checks the run didn't error/skip.
    core_utils.set_mock_mode(True)
    result = auditor_cls().run()
    assert result.error is None, f"{auditor_cls.__name__} raised: {result.error}"
    assert not result.skipped, f"{auditor_cls.__name__} was skipped: {result.skip_reason}"


def test_network_auditor_runs_cleanly_in_mock_mode():
    core_utils.set_mock_mode(True)
    result = NetworkAuditor(duration_seconds=0.1).run()
    assert result.error is None
    assert not result.skipped


def test_module_names_are_unique_across_all_auditors():
    names = [cls().name for cls in [*ALL_AUDITOR_CLASSES, NetworkAuditor]]
    assert len(names) == len(set(names)), f"duplicate auditor names: {names}"


# -- fixture-driven checks against specific auditors ------------------------


def test_tpm_auditor_parses_conftest_pcrread_fixture(tpm_pcrread_output):
    pcrs = TpmAuditor._parse_pcrread(tpm_pcrread_output)
    assert pcrs[0].startswith("0x1111")
    assert pcrs[7].startswith("0x7777")


def test_dma_auditor_detects_iommu_enabled_from_conftest_dmesg_fixture(dmesg_iommu_enabled):
    with patch(
        "anchorroot.modules.dma_auditor.run_command",
        return_value=CommandResult(args=[], returncode=0, stdout=dmesg_iommu_enabled, stderr=""),
    ):
        assert DmaAuditor._check_dmesg() is True


def test_dma_auditor_inconclusive_from_conftest_dmesg_absent_fixture(dmesg_iommu_absent):
    with patch(
        "anchorroot.modules.dma_auditor.run_command",
        return_value=CommandResult(args=[], returncode=0, stdout=dmesg_iommu_absent, stderr=""),
    ):
        assert DmaAuditor._check_dmesg() is None


def test_ca_auditor_parses_efivar_sig_list_fixture(efivar_sha256_sig_list, sample_dbx_hash):
    h1 = sample_dbx_hash("revoked-bootloader-1")
    h2 = sample_dbx_hash("revoked-bootloader-2")
    data = efivar_sha256_sig_list([h1, h2])

    hashes = CaAuditor._parse_signature_list_sha256(data)

    assert hashes == {h1.hex(), h2.hex()}
