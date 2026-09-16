import json

from countercraft.cli import _normalize_argv, main

# Mock-mode reset between tests is handled by the autouse fixture in
# tests/conftest.py -- no per-file teardown needed here.

# -- argv normalization ---------------------------------------------------


def test_normalize_argv_empty_defaults_to_audit():
    assert _normalize_argv([]) == ["audit"]


def test_normalize_argv_bare_flags_get_audit_prefix():
    assert _normalize_argv(["--all"]) == ["audit", "--all"]
    assert _normalize_argv(["--audit-uefi", "--mock"]) == ["audit", "--audit-uefi", "--mock"]


def test_normalize_argv_explicit_audit_subcommand_untouched():
    assert _normalize_argv(["audit", "--all"]) == ["audit", "--all"]


def test_normalize_argv_baseline_subcommand_untouched():
    assert _normalize_argv(["baseline", "save", "x.json"]) == ["baseline", "save", "x.json"]


def test_normalize_argv_help_untouched():
    assert _normalize_argv(["--help"]) == ["--help"]
    assert _normalize_argv(["-h"]) == ["-h"]


# -- end-to-end mock runs ---------------------------------------------------


def test_mock_audit_run_exits_zero_and_writes_report(tmp_path):
    out = tmp_path / "report.json"
    code = main(["--mock", "--audit-tpm", "--no-table", "--output", str(out)])
    assert code == 0
    assert out.is_file()
    data = json.loads(out.read_text())
    assert data["modules"][0]["module"] == "tpm"
    assert data["modules"][0]["error"] is None


def test_mock_audit_fail_on_critical_exits_nonzero(tmp_path):
    out = tmp_path / "report.json"
    code = main(["--mock", "--audit-me", "--no-table", "--output", str(out), "--fail-on", "critical"])
    # me_auditor's mock AMT probe deterministically reports a listening
    # port as CRITICAL -- see countercraft/modules/me_auditor.py.
    assert code == 1


def test_baseline_save_then_diff_round_trip_no_drift(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    save_code = main(["baseline", "save", str(baseline_path), "--mock"])
    assert save_code == 0
    assert baseline_path.is_file()

    out = tmp_path / "report.json"
    audit_code = main(
        ["--mock", "--audit-tpm", "--no-table", "--output", str(out), "--diff", str(baseline_path)]
    )
    assert audit_code == 0
    data = json.loads(out.read_text())
    diff_module = next(m for m in data["modules"] if m["module"] == "baseline_diff")
    assert diff_module["findings"][0]["title"] == "[BASELINE DRIFT] No drift detected"


def test_audit_diff_missing_baseline_exits_2(tmp_path):
    missing = tmp_path / "nope.json"
    code = main(["--mock", "--audit-tpm", "--no-table", "--diff", str(missing)])
    assert code == 2


def test_audit_diff_detects_drift(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    main(["baseline", "save", str(baseline_path), "--mock"])

    # Perturb one PCR to simulate real drift between the two runs.
    data = json.loads(baseline_path.read_text())
    data["tpm_pcrs"]["7"] = "0x" + "00" * 32
    baseline_path.write_text(json.dumps(data))

    out = tmp_path / "report.json"
    code = main(["--mock", "--audit-tpm", "--no-table", "--output", str(out), "--diff", str(baseline_path)])
    assert code == 0
    report = json.loads(out.read_text())
    diff_module = next(m for m in report["modules"] if m["module"] == "baseline_diff")
    titles = [f["title"] for f in diff_module["findings"]]
    assert "[BASELINE DRIFT] TPM PCR changed" in titles
