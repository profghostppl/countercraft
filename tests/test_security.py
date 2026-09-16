from unittest.mock import patch

from anchorroot.core.utils import CommandResult
from anchorroot.utils.security import (
    describe_elevation_required,
    describe_missing_binary,
    elevation_required_result,
    run_privileged,
    sanitize_output,
)


def test_sanitize_output_strips_ansi_csi_sequences():
    text = "\x1b[31mRED TEXT\x1b[0m normal"
    assert sanitize_output(text) == "RED TEXT normal"


def test_sanitize_output_strips_osc_sequences():
    text = "before\x1b]0;window title\x07after"
    assert sanitize_output(text) == "beforeafter"


def test_sanitize_output_strips_control_chars_but_keeps_tab_and_newline():
    text = "line1\tcol\nline2\x00\x07\x1f"
    assert sanitize_output(text) == "line1\tcol\nline2"


def test_sanitize_output_strips_carriage_return_overwrite_trick():
    text = "REAL MESSAGE\rSPOOFED MESSAGE"
    result = sanitize_output(text)
    assert "\r" not in result
    assert result == "REAL MESSAGESPOOFED MESSAGE"


def test_sanitize_output_truncates_oversized_output():
    text = "A" * 1000
    result = sanitize_output(text, max_len=100)
    assert len(result) <= 100 + len("\n...[output truncated]")
    assert result.endswith("[output truncated]")


def test_sanitize_output_empty_string_is_noop():
    assert sanitize_output("") == ""


def test_sanitize_output_clean_text_is_unchanged():
    text = "Module Name  Size  Used by\nnvidia  12345  10\n"
    assert sanitize_output(text) == text


def test_describe_missing_binary_includes_package_hints():
    msg = describe_missing_binary("tpm2_pcrread")
    assert "not found on PATH" in msg
    assert "tpm2-tools" in msg


def test_describe_missing_binary_unknown_binary_still_returns_generic_message():
    msg = describe_missing_binary("totally_unknown_tool")
    assert "not found on PATH" in msg


def test_describe_elevation_required_windows_message():
    with patch("anchorroot.utils.security.is_windows", return_value=True), patch(
        "anchorroot.utils.security.is_macos", return_value=False
    ), patch("anchorroot.utils.security.is_linux", return_value=False):
        msg = describe_elevation_required("SPI flash write-protection register read")
    assert "Administrator" in msg
    assert "SPI flash write-protection register read" in msg


def test_describe_elevation_required_linux_message():
    with patch("anchorroot.utils.security.is_windows", return_value=False), patch(
        "anchorroot.utils.security.is_macos", return_value=False
    ), patch("anchorroot.utils.security.is_linux", return_value=True):
        msg = describe_elevation_required("kernel module signature check")
    assert "sudo" in msg


def test_elevation_required_result_shape():
    result = elevation_required_result("SMM lock bit read")
    assert isinstance(result, CommandResult)
    assert result.returncode == 126
    assert not result.ok
    assert "SMM lock bit read" in result.stderr


def test_run_privileged_skips_execution_when_not_elevated():
    with patch("anchorroot.utils.security.is_elevated", return_value=False), patch(
        "anchorroot.utils.security.run_command"
    ) as mock_run:
        result = run_privileged(["chipsec_main", "-m", "common.bios_wp"], context="BIOS write-protect check")
    mock_run.assert_not_called()
    assert result.returncode == 126
    assert "BIOS write-protect check" in result.stderr


def test_run_privileged_delegates_when_elevated():
    canned = CommandResult(args=[], returncode=0, stdout="ok", stderr="")
    with patch("anchorroot.utils.security.is_elevated", return_value=True), patch(
        "anchorroot.utils.security.run_command", return_value=canned
    ) as mock_run:
        result = run_privileged(["chipsec_main", "-m", "common.bios_wp"], context="BIOS write-protect check")
    mock_run.assert_called_once()
    assert result is canned
