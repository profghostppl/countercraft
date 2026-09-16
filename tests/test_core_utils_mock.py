import sys
from unittest.mock import patch

import anchorroot.core.utils as core_utils

# Mock-mode reset between tests is handled by the autouse fixture in
# tests/conftest.py -- no per-file teardown needed here.


def test_mock_mode_toggle_defaults_off():
    assert core_utils.is_mock_mode() is False


def test_mock_mode_toggle_round_trip():
    core_utils.set_mock_mode(True)
    assert core_utils.is_mock_mode() is True
    core_utils.set_mock_mode(False)
    assert core_utils.is_mock_mode() is False


def test_is_elevated_always_true_in_mock_mode():
    core_utils.set_mock_mode(True)
    assert core_utils.is_elevated() is True


def test_which_ignores_real_path_in_mock_mode():
    core_utils.set_mock_mode(True)
    # A binary certain not to be a registered mock fixture.
    assert core_utils.which("definitely_not_a_real_or_mocked_tool") is None
    assert core_utils.which("tpm2_pcrread") is not None


def test_run_command_never_touches_real_subprocess_in_mock_mode():
    core_utils.set_mock_mode(True)
    with patch("subprocess.run") as mock_run:
        result = core_utils.run_command(["tpm2_pcrread", "sha256"])
    mock_run.assert_not_called()
    assert result.ok


def test_run_command_uses_real_subprocess_when_mock_mode_off():
    core_utils.set_mock_mode(False)
    result = core_utils.run_command([sys.executable, "-c", "print('hello')"], timeout=10.0)
    assert result.ok
    assert "hello" in result.stdout


def test_run_command_sanitizes_real_output():
    core_utils.set_mock_mode(False)
    result = core_utils.run_command(
        [sys.executable, "-c", "print('\\x1b[31mred\\x1b[0m text')"], timeout=10.0
    )
    assert "\x1b" not in result.stdout
    assert "red text" in result.stdout
