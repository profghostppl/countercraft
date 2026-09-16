from unittest.mock import patch

from anchorroot.modules.me_auditor import MeAuditor


def test_parse_intelmetool_detects_hap_bit_set():
    auditor = MeAuditor()
    auditor._parse_intelmetool("ME: HAP is set: ME is disabled\n")
    assert auditor._findings[0].title == "Intel ME disabled via HAP bit"
    assert auditor._findings[0].severity.name == "INFO"


def test_parse_intelmetool_detects_manufacturing_mode_as_critical():
    auditor = MeAuditor()
    auditor._parse_intelmetool("ME: FW Partition Table      : OK\nManufacturing Mode  : YES\n")
    assert auditor._findings[0].title == "Intel ME left in Manufacturing Mode"
    assert auditor._findings[0].severity.name == "CRITICAL"


def test_parse_intelmetool_detects_recovery_mode_as_warning():
    auditor = MeAuditor()
    auditor._parse_intelmetool("ME: Current Operation Mode: Recovery Mode\n")
    assert auditor._findings[0].title == "Intel ME in Recovery mode"
    assert auditor._findings[0].severity.name == "WARNING"


def test_parse_intelmetool_defaults_to_normal_mode():
    auditor = MeAuditor()
    auditor._parse_intelmetool("ME: FW Partition Table      : OK\nME: FW status flags: ok\n")
    assert auditor._findings[0].title == "Intel ME mode: Normal (assumed)"
    assert auditor._findings[0].severity.name == "INFO"


def test_probe_amt_ports_flags_critical_when_port_open():
    auditor = MeAuditor()
    with patch.object(MeAuditor, "_tcp_connect", side_effect=lambda host, port, timeout=0.75: port == 16992):
        with patch.object(MeAuditor, "_local_ip", return_value="192.0.2.1"):
            auditor._probe_amt_ports()
    finding = auditor._findings[0]
    assert finding.title == "Intel AMT out-of-band management port listening"
    assert finding.severity.name == "CRITICAL"
    assert finding.metadata["open_ports"] == [16992]


def test_probe_amt_ports_reports_info_when_nothing_listening():
    auditor = MeAuditor()
    with patch.object(MeAuditor, "_tcp_connect", return_value=False):
        with patch.object(MeAuditor, "_local_ip", return_value="192.0.2.1"):
            auditor._probe_amt_ports()
    finding = auditor._findings[0]
    assert finding.title == "No AMT out-of-band ports detected listening"
    assert finding.severity.name == "INFO"
