from typing import List
from qrecon.q_attck.models import Severity
from qrecon.circuit_lens.models import ParsedCircuit, CircuitFinding, TimingOracleAnalysisResult

class TimingOracleDetector:
    def analyze(self, parsed_circuit: ParsedCircuit) -> TimingOracleAnalysisResult:
        findings: List[CircuitFinding] = []
        
        id_gates = parsed_circuit.gate_histogram.get("id", 0) + parsed_circuit.gate_histogram.get("delay", 0)
        if parsed_circuit.gate_count > 0:
            id_ratio = id_gates / parsed_circuit.gate_count
            if id_ratio > 0.3:
                findings.append(CircuitFinding(
                    module="circuit_lens.timing_oracle",
                    title="Identity gate padding detected",
                    description="Circuit may be using id/nop gates to control execution time precisely for timing measurement purposes.",
                    severity=Severity.MEDIUM,
                    platform="all",
                    raw_data={"id_ratio": id_ratio, "id_gates": id_gates, "total_gates": parsed_circuit.gate_count},
                    technique_id="QTT003",
                    confidence=0.85,
                    rationale=f"High ratio of identity gates ({id_ratio:.2f}) indicates potential timing control padding."
                ))

        if parsed_circuit.qubit_count == 1 and parsed_circuit.measurement_pattern == "all" and parsed_circuit.gate_count < 5:
            findings.append(CircuitFinding(
                module="circuit_lens.timing_oracle",
                title="Minimal single-qubit probe circuit",
                description="Minimal circuit designed primarily to measure execution latency, not perform useful computation.",
                severity=Severity.LOW,
                platform="all",
                raw_data={"qubit_count": 1, "gate_count": parsed_circuit.gate_count},
                technique_id="QTT003",
                confidence=0.7,
                rationale="Circuit is too minimal for computation, likely used to check queue latency."
            ))

        param_gates = sum(parsed_circuit.gate_histogram.get(g, 0) for g in ["rx", "ry", "rz", "u1", "u2", "u3", "p"])
        if param_gates > 5 and parsed_circuit.qubit_count > 1:
             if parsed_circuit.measurement_pattern == "all":
                 findings.append(CircuitFinding(
                    module="circuit_lens.timing_oracle",
                    title="Potential systematic angle variation",
                    description="Circuit contains many parameterized gates with full measurement, potentially extracting calibration data.",
                    severity=Severity.MEDIUM,
                    platform="all",
                    raw_data={"param_gates": param_gates},
                    technique_id="QTT002",
                    confidence=0.6,
                    rationale="High volume of parameterized single qubit gates followed by measurement indicates characterization."
                ))

        if parsed_circuit.qubit_count >= 4 and parsed_circuit.measurement_pattern == "all":
            if "rx" in parsed_circuit.gate_histogram or "ry" in parsed_circuit.gate_histogram:
                findings.append(CircuitFinding(
                    module="circuit_lens.timing_oracle",
                    title="All-qubit measurement with parameter variation",
                    description="Possible calibration extraction or multi-qubit noise characterization.",
                    severity=Severity.MEDIUM,
                    platform="all",
                    raw_data={"qubit_count": parsed_circuit.qubit_count, "gate_histogram": parsed_circuit.gate_histogram},
                    technique_id="QTT002",
                    confidence=0.75,
                    rationale="Wide measurement pattern combined with rotation gates indicates full-device characterization attempt."
                ))

        return TimingOracleAnalysisResult(findings=findings)
