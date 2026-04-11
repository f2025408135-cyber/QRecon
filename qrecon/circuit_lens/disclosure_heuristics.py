from typing import List
from qrecon.q_attck.models import Severity
from qrecon.circuit_lens.models import ParsedCircuit, CircuitFinding, DisclosureAnalysisResult

class DisclosureHeuristicAnalyzer:
    def analyze(self, parsed_circuit: ParsedCircuit) -> DisclosureAnalysisResult:
        findings: List[CircuitFinding] = []
        
        if parsed_circuit.qubit_count > 0:
            ratio = parsed_circuit.depth / parsed_circuit.qubit_count
            if ratio > 50:
                findings.append(CircuitFinding(
                    module="circuit_lens.disclosure_heuristics",
                    title="Unusual depth-to-qubit ratio",
                    description="Circuit has very high depth relative to qubit count, potentially attempting to accumulate specific error information.",
                    severity=Severity.LOW,
                    platform="all",
                    raw_data={"depth": parsed_circuit.depth, "qubit_count": parsed_circuit.qubit_count, "ratio": ratio},
                    technique_id="QTT010",
                    confidence=0.6,
                    rationale=f"High depth/qubit ratio ({ratio:.2f}) is uncommon for standard algorithms of this width."
                ))

        has_barrier = "barrier" in parsed_circuit.gate_histogram
        if parsed_circuit.depth > 300 and not has_barrier:
            findings.append(CircuitFinding(
                module="circuit_lens.disclosure_heuristics",
                title="Barrier-free deep circuit",
                description="Deep circuit without optimization barriers may indicate resource exhaustion attempt.",
                severity=Severity.MEDIUM,
                platform="all",
                raw_data={"depth": parsed_circuit.depth},
                technique_id="QTT008",
                confidence=0.7,
                rationale="Circuit is very deep but lacks barriers, which may cause heavy transpilation load or target exhaustion."
            ))

        cx_count = parsed_circuit.gate_histogram.get("cx", 0) + parsed_circuit.gate_histogram.get("cz", 0)
        if cx_count > 0 and parsed_circuit.measurement_pattern == "all" and parsed_circuit.qubit_count > 2:
            if parsed_circuit.depth < 10 and cx_count >= parsed_circuit.qubit_count // 2:
                findings.append(CircuitFinding(
                    module="circuit_lens.disclosure_heuristics",
                    title="Potential cross-talk probe",
                    description="Dense two-qubit gates in shallow circuit with full measurement.",
                    severity=Severity.LOW,
                    platform="all",
                    raw_data={"cx_count": cx_count, "depth": parsed_circuit.depth},
                    technique_id="QTT009",
                    confidence=0.5,
                    rationale="Simultaneous two-qubit gates followed by measurement is the standard pattern for cross-talk characterization."
                ))

        reset_count = parsed_circuit.gate_histogram.get("reset", 0)
        measure_count = parsed_circuit.gate_histogram.get("measure", 0)
        
        other_gates = parsed_circuit.gate_count - reset_count - measure_count
        
        if reset_count > 0 and measure_count >= reset_count and other_gates < reset_count:
            findings.append(CircuitFinding(
                module="circuit_lens.disclosure_heuristics",
                title="Reset-and-measure loop pattern",
                description="Repeated reset+measure on same qubits without computation. May probe qubit reset fidelity.",
                severity=Severity.HIGH,
                platform="ibm-quantum",
                raw_data={"reset_count": reset_count, "measure_count": measure_count, "other_gates": other_gates},
                technique_id="QTT012",
                confidence=0.85,
                rationale="High ratio of resets and measurements compared to logical gates suggests probing of hardware reset fidelity."
            ))

        return DisclosureAnalysisResult(findings=findings)
