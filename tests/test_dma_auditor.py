from unittest.mock import patch

from countercraft.core.utils import CommandResult
from countercraft.modules.dma_auditor import DmaAuditor


def _cmd_result(stdout: str = "", returncode: int = 0) -> CommandResult:
    return CommandResult(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_check_dmesg_detects_intel_vtd_enabled():
    with patch("countercraft.modules.dma_auditor.run_command", return_value=_cmd_result("DMAR: IOMMU enabled\n")):
        assert DmaAuditor._check_dmesg() is True


def test_check_dmesg_detects_amd_vi_enabled():
    output = "AMD-Vi: IOMMU performance counters supported\nAMD-Vi: Interrupt remapping enabled\n"
    with patch("countercraft.modules.dma_auditor.run_command", return_value=_cmd_result(output)):
        assert DmaAuditor._check_dmesg() is True


def test_check_dmesg_subsystem_present_but_not_confirmed_enabled():
    with patch("countercraft.modules.dma_auditor.run_command", return_value=_cmd_result("DMAR: table not found\n")):
        assert DmaAuditor._check_dmesg() is False


def test_check_dmesg_no_relevant_lines_is_inconclusive():
    with patch("countercraft.modules.dma_auditor.run_command", return_value=_cmd_result("Linux version 6.5.0\n")):
        assert DmaAuditor._check_dmesg() is None


def test_check_dmesg_falls_back_to_journalctl_on_permission_denied():
    responses = [_cmd_result("", returncode=1), _cmd_result("DMAR: IOMMU enabled\n")]
    with patch("countercraft.modules.dma_auditor.run_command", side_effect=responses):
        assert DmaAuditor._check_dmesg() is True


def test_check_dmesg_returns_none_when_both_sources_fail():
    responses = [_cmd_result("", returncode=1), _cmd_result("", returncode=1)]
    with patch("countercraft.modules.dma_auditor.run_command", side_effect=responses):
        assert DmaAuditor._check_dmesg() is None


def test_parse_kernel_dma_protection_on():
    text = "Kernel DMA Protection\tOn\nOther Field\tSomething\n"
    assert DmaAuditor._parse_kernel_dma_protection_text(text) is True


def test_parse_kernel_dma_protection_off():
    text = "Kernel DMA Protection\tOff\n"
    assert DmaAuditor._parse_kernel_dma_protection_text(text) is False


def test_parse_kernel_dma_protection_missing_field():
    assert DmaAuditor._parse_kernel_dma_protection_text("some unrelated report text") is None


def test_parse_kernel_dma_protection_unrecognized_value():
    assert DmaAuditor._parse_kernel_dma_protection_text("Kernel DMA Protection\tUnknown\n") is None
