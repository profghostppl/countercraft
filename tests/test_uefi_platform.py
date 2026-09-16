from unittest.mock import patch

from anchorroot.core.utils import CommandResult
from anchorroot.modules.uefi_platform import UefiPlatformAuditor


def _cmd_result(stdout: str = "", returncode: int = 0) -> CommandResult:
    return CommandResult(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_run_chipsec_module_flags_failed_as_critical():
    auditor = UefiPlatformAuditor()
    output = "[x][ =======================================================\n[-] FAILED: BIOS region write protection is NOT configured\n"
    with patch("anchorroot.modules.uefi_platform.run_command", return_value=_cmd_result(output)):
        auditor._run_chipsec_module(
            "chipsec_main",
            "common.bios_wp",
            finding_title="SPI flash write protection (BIOS_WP)",
            failure_description="desc",
            failure_remediation="fix it",
        )
    assert auditor._findings[0].severity.name == "CRITICAL"
    assert auditor._findings[0].title == "SPI flash write protection (BIOS_WP)"


def test_run_chipsec_module_reports_info_on_pass():
    auditor = UefiPlatformAuditor()
    output = "[+] PASSED: BIOS region write protection is configured correctly\n"
    with patch("anchorroot.modules.uefi_platform.run_command", return_value=_cmd_result(output)):
        auditor._run_chipsec_module(
            "chipsec_main",
            "common.bios_wp",
            finding_title="SPI flash write protection (BIOS_WP)",
            failure_description="desc",
            failure_remediation="fix it",
        )
    assert auditor._findings[0].severity.name == "INFO"


def test_run_chipsec_module_warns_on_ambiguous_output():
    auditor = UefiPlatformAuditor()
    with patch("anchorroot.modules.uefi_platform.run_command", return_value=_cmd_result("some unrelated chipsec banner\n")):
        auditor._run_chipsec_module(
            "chipsec_main",
            "common.bios_wp",
            finding_title="SPI flash write protection (BIOS_WP)",
            failure_description="desc",
            failure_remediation="fix it",
        )
    assert auditor._findings[0].severity.name == "WARNING"
    assert "inconclusive" in auditor._findings[0].title


def test_run_chipsec_module_handles_timeout():
    auditor = UefiPlatformAuditor()
    timed_out = CommandResult(args=[], returncode=-1, stdout="", stderr="timed out", timed_out=True)
    with patch("anchorroot.modules.uefi_platform.run_command", return_value=timed_out):
        auditor._run_chipsec_module(
            "chipsec_main",
            "common.smm",
            finding_title="SMM lock bit",
            failure_description="desc",
            failure_remediation="fix it",
        )
    assert "timed out" in auditor._findings[0].title
