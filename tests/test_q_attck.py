from qrecon.q_attck.loader import QuantumATTCKLoader
from qrecon.q_attck.mapper import FindingMapper
from qrecon.q_attck.models import Finding, Severity


def test_taxonomy_loads_without_error():
    loader = QuantumATTCKLoader()
    assert loader.tactics is not None
    assert loader.techniques is not None


def test_all_17_techniques_present():
    loader = QuantumATTCKLoader()
    assert len(loader.techniques) == 17


def test_all_7_tactics_present():
    loader = QuantumATTCKLoader()
    assert len(loader.tactics) == 7


def test_get_technique_by_id_returns_correct_technique():
    loader = QuantumATTCKLoader()
    technique = loader.get_technique("QTT004")
    assert technique is not None
    assert technique.name == "API key exposure via public repository"


def test_get_techniques_for_platform_ibm_returns_subset():
    loader = QuantumATTCKLoader()
    ibm_techniques = loader.get_techniques_for_platform("ibm-quantum")
    assert len(ibm_techniques) > 0
    # QTT007 is IBM specific, QTT004 is all platforms, both should be in ibm_techniques
    assert any(t.id == "QTT007" for t in ibm_techniques)
    assert any(t.id == "QTT004" for t in ibm_techniques)


def test_get_techniques_by_severity_critical_returns_5_techniques():
    loader = QuantumATTCKLoader()
    critical_techniques = loader.get_techniques_by_severity(Severity.CRITICAL)
    # The prompt explicitly listed QTT004, QTT006, QTT011, QTT016, QTT017
    assert len(critical_techniques) == 5
    critical_ids = [t.id for t in critical_techniques]
    assert "QTT004" in critical_ids
    assert "QTT006" in critical_ids
    assert "QTT011" in critical_ids
    assert "QTT016" in critical_ids
    assert "QTT017" in critical_ids


def test_finding_mapper_maps_idor_finding_to_QTT016():
    mapper = FindingMapper()
    finding = Finding(
        module="auth_probe.cross_tenant",
        title="IDOR on job modification",
        description="Able to cancel foreign job 12345 belonging to another user.",
        severity=Severity.CRITICAL,
        platform="ibm-quantum",
        raw_data={}
    )
    mapped = mapper.map_finding(finding)
    assert mapped is not None
    assert mapped.technique_id == "QTT016"


def test_finding_mapper_maps_credential_finding_to_QTT004():
    mapper = FindingMapper()
    finding = Finding(
        module="auth_probe.credential_leak",
        title="Exposed API Key",
        description="Found IBM Quantum token exposed in public repository.",
        severity=Severity.CRITICAL,
        platform="ibm-quantum",
        raw_data={}
    )
    mapped = mapper.map_finding(finding)
    assert mapped is not None
    assert mapped.technique_id == "QTT004"
