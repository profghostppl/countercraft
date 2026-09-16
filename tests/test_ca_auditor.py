import hashlib
import struct

from countercraft.modules.ca_auditor import CaAuditor

_EFI_CERT_SHA256_GUID = struct.pack(
    "<IHH8s", 0xC1C41626, 0x504C, 0x4092, bytes([0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28])
)
_OTHER_GUID = b"\x11" * 16
_HEADER_FMT = "<16sIII"


def _build_signature_list(hashes: list[bytes], sig_type: bytes = _EFI_CERT_SHA256_GUID) -> bytes:
    sig_size = 16 + 32  # owner GUID + sha256 digest
    entries = b"".join((b"\x00" * 16) + h for h in hashes)
    header_size_field = 0
    list_size = struct.calcsize(_HEADER_FMT) + header_size_field + len(entries)
    header = struct.pack(_HEADER_FMT, sig_type, list_size, header_size_field, sig_size)
    return header + entries


def test_parse_signature_list_extracts_sha256_hashes():
    h1 = hashlib.sha256(b"bootloader-a").digest()
    h2 = hashlib.sha256(b"bootloader-b").digest()
    data = _build_signature_list([h1, h2])

    result = CaAuditor._parse_signature_list_sha256(data)

    assert result == {h1.hex(), h2.hex()}


def test_parse_signature_list_ignores_non_sha256_signature_types():
    h1 = hashlib.sha256(b"x509-cert-placeholder").digest()
    data = _build_signature_list([h1], sig_type=_OTHER_GUID)

    assert CaAuditor._parse_signature_list_sha256(data) == set()


def test_parse_signature_list_handles_multiple_concatenated_lists():
    h1 = hashlib.sha256(b"first").digest()
    h2 = hashlib.sha256(b"second").digest()
    data = _build_signature_list([h1]) + _build_signature_list([h2])

    assert CaAuditor._parse_signature_list_sha256(data) == {h1.hex(), h2.hex()}


def test_parse_signature_list_stops_on_malformed_zero_size_entry():
    # list_size == 0 must not spin forever -- this is the regression this
    # test guards against.
    data = struct.pack(_HEADER_FMT, _EFI_CERT_SHA256_GUID, 0, 0, 48) + b"\x00" * 100
    assert CaAuditor._parse_signature_list_sha256(data) == set()


def test_parse_signature_list_empty_input():
    assert CaAuditor._parse_signature_list_sha256(b"") == set()


def test_is_known_bad_ca_matches_superfish():
    assert CaAuditor._is_known_bad_ca("CN=Superfish, Inc., O=Superfish, Inc.")


def test_is_known_bad_ca_matches_edellroot_case_insensitive():
    assert CaAuditor._is_known_bad_ca("cn=eDellRoot")


def test_is_known_bad_ca_does_not_flag_legitimate_ca():
    assert not CaAuditor._is_known_bad_ca("CN=DigiCert Global Root CA, O=DigiCert Inc")


def test_load_mozilla_fingerprints_normalizes_case_and_colons(tmp_path):
    import json

    ref_path = tmp_path / "mozilla.json"
    ref_path.write_text(json.dumps(["AA:BB:CC", "ddeeff"]))
    auditor = CaAuditor(mozilla_ca_fingerprints_path=ref_path)

    fingerprints = auditor._load_mozilla_fingerprints()

    assert fingerprints == {"aabbcc", "ddeeff"}


def test_load_mozilla_fingerprints_missing_file_warns(tmp_path):
    auditor = CaAuditor(mozilla_ca_fingerprints_path=tmp_path / "missing.json")
    assert auditor._load_mozilla_fingerprints() is None
    assert auditor._findings[0].severity.name == "WARNING"
