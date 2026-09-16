from unittest.mock import patch

from countercraft.modules.persistence import PersistenceAuditor


def test_extract_executable_strips_quotes_and_arguments():
    cmd = '"C:\\Program Files\\Vendor\\tool.exe" --flag value'
    assert PersistenceAuditor._extract_executable(cmd) == "C:\\Program Files\\Vendor\\tool.exe"


def test_extract_executable_handles_unquoted_command():
    assert PersistenceAuditor._extract_executable("/usr/bin/foo --bar") == "/usr/bin/foo"


def test_extract_executable_unquoted_path_with_spaces_uses_extension_heuristic():
    # No quotes, path contains a space, target need not exist on disk
    # (e.g. an orphaned scheduled task whose binary was uninstalled).
    cmd = r"C:\Program Files\P508\P508PowerAgent.exe -service"
    assert PersistenceAuditor._extract_executable(cmd) == r"C:\Program Files\P508\P508PowerAgent.exe"


def test_extract_executable_unquoted_path_with_spaces_and_no_args():
    cmd = r"C:\Program Files\Vendor App\tool.exe"
    assert PersistenceAuditor._extract_executable(cmd) == cmd


def test_normalize_windows_path_strips_nt_device_prefix():
    assert (
        PersistenceAuditor._normalize_windows_path(r"\??\C:\Windows\system32\drivers\AsIO3.sys")
        == r"C:\Windows\system32\drivers\AsIO3.sys"
    )


def test_classify_path_allows_nt_prefixed_system32_driver():
    with patch("countercraft.modules.persistence.is_windows", return_value=True):
        result = PersistenceAuditor._classify_path(r"\??\C:\Windows\system32\drivers\AsIO3.sys")
    assert result is None


def test_classify_path_resolves_bare_name_via_path():
    with patch("countercraft.modules.persistence.is_windows", return_value=True), patch(
        "countercraft.modules.persistence.which", return_value=r"C:\Windows\System32\sc.exe"
    ):
        result = PersistenceAuditor._classify_path("sc.exe")
    assert result is None


def test_classify_path_bare_name_unresolvable_still_flagged():
    with patch("countercraft.modules.persistence.is_windows", return_value=True), patch(
        "countercraft.modules.persistence.which", return_value=None
    ):
        result = PersistenceAuditor._classify_path("totally_unknown_binary.exe")
    assert result is not None


def test_classify_path_flags_windows_temp_as_critical():
    with patch("countercraft.modules.persistence.is_windows", return_value=True):
        result = PersistenceAuditor._classify_path(r"C:\Users\alice\AppData\Local\Temp\svc.exe")
    assert result is not None
    severity, _ = result
    assert severity.name == "CRITICAL"


def test_classify_path_allows_windows_program_files():
    with patch("countercraft.modules.persistence.is_windows", return_value=True):
        result = PersistenceAuditor._classify_path(r"C:\Program Files\Vendor\app.exe")
    assert result is None


def test_classify_path_flags_windows_non_standard_dir_as_warning():
    with patch("countercraft.modules.persistence.is_windows", return_value=True):
        result = PersistenceAuditor._classify_path(r"C:\ProgramData\WeirdOem\util.exe")
    assert result is not None
    severity, _ = result
    assert severity.name == "WARNING"


def test_classify_path_flags_linux_tmp_as_critical():
    with patch("countercraft.modules.persistence.is_windows", return_value=False):
        result = PersistenceAuditor._classify_path("/tmp/.hidden/backdoor")
    assert result is not None
    severity, _ = result
    assert severity.name == "CRITICAL"


def test_classify_path_allows_linux_standard_bin():
    with patch("countercraft.modules.persistence.is_windows", return_value=False):
        result = PersistenceAuditor._classify_path("/usr/bin/systemd-resolved")
    assert result is None


def test_classify_path_flags_linux_home_dir_as_warning():
    with patch("countercraft.modules.persistence.is_windows", return_value=False):
        result = PersistenceAuditor._classify_path("/home/alice/.local/bin/script.sh")
    assert result is not None
    severity, _ = result
    assert severity.name == "WARNING"


def test_evaluate_paths_adds_finding_for_suspicious_location():
    auditor = PersistenceAuditor()
    with patch("countercraft.modules.persistence.is_windows", return_value=False):
        auditor._evaluate_paths([("cron-job", "/tmp/miner")], context="cron entry", require_path=False)
    assert len(auditor._findings) == 1
    assert auditor._findings[0].severity.name == "CRITICAL"
    assert auditor._findings[0].metadata["path"] == "/tmp/miner"


def test_evaluate_paths_no_finding_for_standard_location():
    auditor = PersistenceAuditor()
    with patch("countercraft.modules.persistence.is_windows", return_value=False):
        auditor._evaluate_paths([("cron-job", "/usr/bin/logrotate")], context="cron entry", require_path=False)
    assert auditor._findings == []
