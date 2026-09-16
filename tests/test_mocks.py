from anchorroot.mocks import (
    MOCK_AVAILABLE_BINARIES,
    mock_command,
    mock_efivar,
    mock_powershell,
    mock_which,
)


def test_mock_which_returns_path_for_known_binary():
    assert mock_which("tpm2_pcrread") is not None
    assert "tpm2_pcrread" in mock_which("tpm2_pcrread")


def test_mock_which_returns_none_for_unknown_binary():
    assert mock_which("totally_unknown_tool") is None


def test_mock_which_covers_every_advertised_binary():
    for binary in MOCK_AVAILABLE_BINARIES:
        assert mock_which(binary) is not None


def test_mock_command_never_returns_none():
    # mock mode must be an absolute guarantee -- every call gets a
    # CommandResult, never a signal to fall through to a real subprocess.
    assert mock_command([]) is not None
    assert mock_command(["some_never_registered_binary", "--flag"]) is not None


def test_mock_command_tpm2_pcrread_contains_pcrs_of_interest():
    result = mock_command(["/mock/bin/tpm2_pcrread", "sha256"])
    assert result.ok
    for pcr in ("0", "2", "4", "7"):
        assert f"  {pcr} : 0x" in result.stdout


def test_mock_command_chipsec_smm_reports_failure():
    result = mock_command(["/mock/bin/chipsec_main", "-m", "common.smm"])
    assert "FAILED" in result.stdout


def test_mock_command_chipsec_bios_wp_reports_pass():
    result = mock_command(["/mock/bin/chipsec_main", "-m", "common.bios_wp"])
    assert "PASSED" in result.stdout


def test_mock_command_lsmod_includes_demo_module():
    result = mock_command(["/mock/bin/lsmod"])
    assert "coreboot_backdoor" in result.stdout


def test_mock_command_modinfo_unsigned_for_demo_module():
    result = mock_command(["/mock/bin/modinfo", "-F", "signer", "coreboot_backdoor"])
    assert result.stdout.strip() == ""


def test_mock_command_modinfo_signed_for_other_modules():
    result = mock_command(["/mock/bin/modinfo", "-F", "signer", "nvidia"])
    assert result.stdout.strip() != ""


def test_mock_command_driverquery_csv_parses_as_csv():
    import csv
    import io

    result = mock_command(["driverquery", "/fo", "csv"])
    rows = list(csv.DictReader(io.StringIO(result.stdout)))
    assert any(row.get("Module Name") == "ampa" for row in rows)


def test_mock_command_msinfo32_writes_report_file(tmp_path):
    report_path = tmp_path / "report.txt"
    result = mock_command(["msinfo32", "/report", str(report_path)])
    assert result.ok
    assert report_path.is_file()
    content = report_path.read_text(encoding="utf-16")
    assert "Kernel DMA Protection" in content
    assert "On" in content


def test_mock_command_openssl_subject_cycles_through_fixtures():
    seen = set()
    for _ in range(3):
        result = mock_command(["openssl", "x509", "-noout", "-subject", "-in", "cert.pem"])
        seen.add(result.stdout.strip())
    assert len(seen) >= 2  # at least two distinct subjects across calls


def test_mock_powershell_confirm_secure_boot():
    result = mock_powershell("Confirm-SecureBootUEFI")
    assert result.stdout.strip() == "True"


def test_mock_powershell_get_tpm_is_valid_json_object():
    import json

    result = mock_powershell("Get-Tpm | ConvertTo-Json -Compress")
    data = json.loads(result.stdout)
    assert data["TpmPresent"] is True


def test_mock_powershell_cert_store_includes_superfish():
    result = mock_powershell("Get-ChildItem Cert:\\LocalMachine\\Root | ConvertTo-Json -Compress")
    assert "Superfish" in result.stdout


def test_mock_powershell_unmatched_script_returns_empty_success():
    result = mock_powershell("Some-Cmdlet-Nobody-Mocked")
    assert result.ok
    assert result.stdout == ""


def test_mock_command_dispatches_powershell_args_through_mock_powershell():
    result = mock_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", "Confirm-SecureBootUEFI"])
    assert result.stdout.strip() == "True"


def test_mock_efivar_known_variable():
    raw = mock_efivar("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    assert raw is not None
    assert len(raw) > 4  # attribute prefix + payload


def test_mock_efivar_unknown_variable_returns_none():
    assert mock_efivar("NotARealVariable-00000000-0000-0000-0000-000000000000") is None
