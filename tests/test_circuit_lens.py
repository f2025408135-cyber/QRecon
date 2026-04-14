from pathlib import Path

from qrecon.circuit_lens.parser import CircuitParser
from qrecon.circuit_lens.timing_oracle import TimingOracleDetector
from qrecon.circuit_lens.disclosure_heuristics import DisclosureHeuristicAnalyzer

FIXTURES_DIR = Path("tests/fixtures/sample_circuits")


def test_parser_correctly_parses_bell_circuit():
    parser = CircuitParser()
    parsed = parser.parse_file(str(FIXTURES_DIR / "benign_bell.qasm"))
    
    assert parsed.qubit_count == 2
    assert parsed.gate_count == 4  
    assert parsed.measurement_pattern == "all"


def test_parser_extracts_correct_gate_histogram():
    parser = CircuitParser()
    parsed = parser.parse_file(str(FIXTURES_DIR / "calibration_extractor.qasm"))
    
    assert parsed.qubit_count == 5
    assert parsed.gate_histogram.get("rx") == 5
    assert parsed.gate_histogram.get("ry") == 5
    assert parsed.gate_histogram.get("measure") == 5


def test_timing_oracle_detector_flags_identity_heavy_circuit():
    parser = CircuitParser()
    parsed = parser.parse_file(str(FIXTURES_DIR / "suspicious_timing_probe.qasm"))
    
    detector = TimingOracleDetector()
    result = detector.analyze(parsed)
    
    assert len(result.findings) >= 1
    
    padding_finding = next((f for f in result.findings if f.title == "Identity gate padding detected"), None)
    assert padding_finding is not None
    assert padding_finding.technique_id == "QTT003"


def test_timing_oracle_detector_does_not_flag_bell_circuit():
    parser = CircuitParser()
    parsed = parser.parse_file(str(FIXTURES_DIR / "benign_bell.qasm"))
    
    detector = TimingOracleDetector()
    result = detector.analyze(parsed)
    
    assert len(result.findings) == 0


def test_timing_oracle_detector_flags_calibration_extractor_circuit():
    parser = CircuitParser()
    parsed = parser.parse_file(str(FIXTURES_DIR / "calibration_extractor.qasm"))
    
    detector = TimingOracleDetector()
    result = detector.analyze(parsed)
    
    assert len(result.findings) >= 1
    variation_finding = next((f for f in result.findings if "parameter variation" in f.title), None)
    assert variation_finding is not None
    assert variation_finding.technique_id == "QTT002"


def test_disclosure_analyzer_flags_reset_measure_loop():
    qasm = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[1];
creg c[1];
reset q[0];
measure q[0] -> c[0];
reset q[0];
measure q[0] -> c[0];
reset q[0];
measure q[0] -> c[0];
"""
    parser = CircuitParser()
    parsed = parser.parse_string(qasm)
    
    analyzer = DisclosureHeuristicAnalyzer()
    result = analyzer.analyze(parsed)
    
    assert len(result.findings) >= 1
    loop_finding = next((f for f in result.findings if "Reset-and-measure" in f.title), None)
    assert loop_finding is not None
    assert loop_finding.technique_id == "QTT012"
    assert loop_finding.severity == "high"
