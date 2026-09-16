import json

from countercraft.core.diff import Snapshot, diff_snapshots, load_snapshot, save_snapshot, SnapshotError
import pytest


def _snapshot(**overrides) -> Snapshot:
    base = dict(
        tpm_pcrs={"0": "0xaaaa", "7": "0xbbbb"},
        root_cas={"fp1": "CN=Digicert", "fp2": "CN=ISRG"},
        kernel_modules=["nvidia", "usb_storage"],
        efi_boot_variables={"BootOrder": "hash1", "Boot0000": "hash2"},
    )
    base.update(overrides)
    return Snapshot(**base)


# -- Snapshot serialization --------------------------------------------------


def test_snapshot_to_dict_from_dict_round_trip():
    snap = _snapshot()
    restored = Snapshot.from_dict(snap.to_dict())
    assert restored.tpm_pcrs == snap.tpm_pcrs
    assert restored.root_cas == snap.root_cas
    assert restored.kernel_modules == snap.kernel_modules
    assert restored.efi_boot_variables == snap.efi_boot_variables


def test_snapshot_from_dict_tolerates_missing_keys():
    restored = Snapshot.from_dict({"schema_version": 1})
    assert restored.tpm_pcrs == {}
    assert restored.root_cas == {}
    assert restored.kernel_modules == []
    assert restored.efi_boot_variables == {}


def test_save_and_load_snapshot_round_trip(tmp_path, monkeypatch):
    path = tmp_path / "baseline.json"
    monkeypatch.setattr("countercraft.core.diff.collect_snapshot", lambda: _snapshot())
    saved = save_snapshot(path)
    loaded = load_snapshot(path)
    assert loaded.tpm_pcrs == saved.tpm_pcrs
    assert loaded.root_cas == saved.root_cas


def test_load_snapshot_missing_file_raises_snapshot_error(tmp_path):
    with pytest.raises(SnapshotError, match="not found"):
        load_snapshot(tmp_path / "nope.json")


def test_load_snapshot_malformed_json_raises_snapshot_error(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not valid json")
    with pytest.raises(SnapshotError):
        load_snapshot(path)


def test_load_snapshot_non_object_json_raises_snapshot_error(tmp_path):
    path = tmp_path / "list.json"
    path.write_text(json.dumps([1, 2, 3]))
    with pytest.raises(SnapshotError):
        load_snapshot(path)


# -- diff_snapshots: no drift -------------------------------------------


def test_diff_identical_snapshots_reports_no_drift():
    snap = _snapshot()
    findings = diff_snapshots(snap, snap)
    assert len(findings) == 1
    assert findings[0].title == "[BASELINE DRIFT] No drift detected"
    assert findings[0].severity.name == "INFO"


# -- diff_snapshots: PCR drift -------------------------------------------


def test_diff_pcr_change_is_critical():
    baseline = _snapshot(tpm_pcrs={"0": "0xaaaa", "7": "0xbbbb"})
    current = _snapshot(tpm_pcrs={"0": "0xaaaa", "7": "0xCCCC"})
    findings = diff_snapshots(baseline, current)
    pcr_findings = [f for f in findings if "PCR" in f.title]
    assert len(pcr_findings) == 1
    assert pcr_findings[0].severity.name == "CRITICAL"
    assert pcr_findings[0].metadata["pcr_index"] == "7"


def test_diff_pcr_case_insensitive_match_not_flagged():
    baseline = _snapshot(tpm_pcrs={"0": "0xAAAA"})
    current = _snapshot(tpm_pcrs={"0": "0xaaaa"})
    findings = diff_snapshots(baseline, current)
    assert not any("PCR" in f.title for f in findings)


def test_diff_pcr_skipped_when_current_empty_no_false_flood():
    baseline = _snapshot(tpm_pcrs={"0": "0xaaaa", "7": "0xbbbb"})
    current = _snapshot(tpm_pcrs={})
    findings = diff_snapshots(baseline, current)
    assert not any(f.severity.name == "CRITICAL" for f in findings)
    assert any("comparison skipped" in f.title.lower() for f in findings)


# -- diff_snapshots: root CAs ---------------------------------------------


def test_diff_root_ca_added_and_removed():
    baseline = _snapshot(root_cas={"fp1": "CN=Digicert"})
    current = _snapshot(root_cas={"fp1": "CN=Digicert", "fp2": "CN=Superfish"})
    findings = diff_snapshots(baseline, current)
    added = [f for f in findings if f.title == "[BASELINE DRIFT] Root CA added"]
    assert len(added) == 1
    assert added[0].severity.name == "WARNING"
    assert added[0].metadata["subject"] == "CN=Superfish"


def test_diff_root_ca_removed():
    baseline = _snapshot(root_cas={"fp1": "CN=Digicert", "fp2": "CN=Old"})
    current = _snapshot(root_cas={"fp1": "CN=Digicert"})
    findings = diff_snapshots(baseline, current)
    removed = [f for f in findings if f.title == "[BASELINE DRIFT] Root CA removed"]
    assert len(removed) == 1
    assert removed[0].metadata["fingerprint"] == "fp2"


# -- diff_snapshots: kernel modules ----------------------------------------


def test_diff_new_kernel_module_is_warning():
    baseline = _snapshot(kernel_modules=["nvidia"])
    current = _snapshot(kernel_modules=["nvidia", "sketchy_driver"])
    findings = diff_snapshots(baseline, current)
    added = [f for f in findings if f.title == "[BASELINE DRIFT] New kernel module loaded"]
    assert len(added) == 1
    assert added[0].severity.name == "WARNING"
    assert added[0].metadata["module_name"] == "sketchy_driver"


def test_diff_removed_kernel_module_is_info_not_critical():
    baseline = _snapshot(kernel_modules=["nvidia", "usb_storage"])
    current = _snapshot(kernel_modules=["nvidia"])
    findings = diff_snapshots(baseline, current)
    removed = [f for f in findings if "no longer loaded" in f.title]
    assert len(removed) == 1
    assert removed[0].severity.name == "INFO"


# -- diff_snapshots: EFI boot variables -------------------------------------


def test_diff_efi_boot_variable_modified_is_critical():
    baseline = _snapshot(efi_boot_variables={"BootOrder": "hash1"})
    current = _snapshot(efi_boot_variables={"BootOrder": "hash2"})
    findings = diff_snapshots(baseline, current)
    changed = [f for f in findings if f.title == "[BASELINE DRIFT] EFI boot variable modified"]
    assert len(changed) == 1
    assert changed[0].severity.name == "CRITICAL"


def test_diff_efi_boot_variable_added_is_critical():
    baseline = _snapshot(efi_boot_variables={"BootOrder": "hash1"})
    current = _snapshot(efi_boot_variables={"BootOrder": "hash1", "Boot0099": "hash_new"})
    findings = diff_snapshots(baseline, current)
    added = [f for f in findings if f.title == "[BASELINE DRIFT] EFI boot variable added"]
    assert len(added) == 1
    assert added[0].severity.name == "CRITICAL"
    assert added[0].metadata["variable"] == "Boot0099"


def test_diff_efi_boot_variable_removed_is_warning():
    baseline = _snapshot(efi_boot_variables={"BootOrder": "hash1", "Boot0000": "hash2"})
    current = _snapshot(efi_boot_variables={"BootOrder": "hash1"})
    findings = diff_snapshots(baseline, current)
    removed = [f for f in findings if f.title == "[BASELINE DRIFT] EFI boot variable removed"]
    assert len(removed) == 1
    assert removed[0].severity.name == "WARNING"


def test_diff_efi_boot_skipped_when_baseline_empty_no_false_flood():
    baseline = _snapshot(efi_boot_variables={})
    current = _snapshot(efi_boot_variables={"BootOrder": "hash1", "Boot0000": "hash2"})
    findings = diff_snapshots(baseline, current)
    assert not any(f.severity.name == "CRITICAL" for f in findings)
    assert any("comparison skipped" in f.title.lower() for f in findings)
