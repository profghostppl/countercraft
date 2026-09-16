import json

from countercraft.modules.tpm_auditor import PCRS_OF_INTEREST, TpmAuditor

SAMPLE_PCRREAD_OUTPUT = """
sha256:
  0 : 0x1111111111111111111111111111111111111111111111111111111111111111
  1 : 0x2222222222222222222222222222222222222222222222222222222222222222
  2 : 0x3333333333333333333333333333333333333333333333333333333333333333
  4 : 0x4444444444444444444444444444444444444444444444444444444444444444
  7 : 0x7777777777777777777777777777777777777777777777777777777777777777
"""


def test_parse_pcrread_extracts_all_pcrs_of_interest():
    pcrs = TpmAuditor._parse_pcrread(SAMPLE_PCRREAD_OUTPUT)
    assert set(PCRS_OF_INTEREST) <= set(pcrs)
    assert pcrs[0].startswith("0x1111")
    assert pcrs[7].startswith("0x7777")


def test_parse_pcrread_returns_empty_dict_for_garbage_output():
    assert TpmAuditor._parse_pcrread("not a pcr dump\nrandom text") == {}


def test_parse_pcrread_ignores_blank_and_header_lines():
    pcrs = TpmAuditor._parse_pcrread("sha256:\n\n  0 : 0xabc\n")
    assert pcrs == {0: "0xabc"}


def test_compare_baseline_flags_drifted_pcr_only(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps({"0": "0xaaaa", "2": "0xbbbb", "4": "0xcccc", "7": "0xdddd"})
    )
    auditor = TpmAuditor(baseline_path=baseline_path)

    current = {0: "0xaaaa", 2: "0xbbbb", 4: "0xcccc", 7: "0xEEEE"}
    auditor._compare_baseline(current)

    drift_titles = [f.title for f in auditor._findings if "drift" in f.title]
    assert drift_titles == ["PCR 7 drift detected"]

    drift_finding = next(f for f in auditor._findings if f.title == "PCR 7 drift detected")
    assert drift_finding.severity.name == "CRITICAL"
    assert drift_finding.metadata["baseline_value"] == "0xdddd"
    assert drift_finding.metadata["current_value"] == "0xEEEE"


def test_compare_baseline_all_match_reports_clean(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    values = {"0": "0xaaaa", "2": "0xbbbb", "4": "0xcccc", "7": "0xdddd"}
    baseline_path.write_text(json.dumps(values))
    auditor = TpmAuditor(baseline_path=baseline_path)

    current = {int(k): v for k, v in values.items()}
    auditor._compare_baseline(current)

    assert any(f.title == "PCRs match baseline" for f in auditor._findings)
    assert not any("drift" in f.title for f in auditor._findings)


def test_compare_baseline_missing_file_warns(tmp_path):
    auditor = TpmAuditor(baseline_path=tmp_path / "does_not_exist.json")
    auditor._compare_baseline({0: "0xaaaa"})
    assert auditor._findings[0].severity.name == "WARNING"
    assert "not found" in auditor._findings[0].title.lower()


def test_no_baseline_configured_is_informational():
    auditor = TpmAuditor(baseline_path=None)
    auditor._compare_baseline({0: "0xaaaa"})
    assert auditor._findings[0].severity.name == "INFO"
