from typing import Dict
import openqasm3
from openqasm3.ast import (
    QubitDeclaration, QuantumGate, QuantumMeasurement
)
from qiskit.circuit.quantumcircuit import QuantumCircuit

from qrecon.circuit_lens.models import ParsedCircuit

class CircuitParser:
    def parse_file(self, path: str) -> ParsedCircuit:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        return self.parse_string(content)

    def parse_string(self, qasm: str) -> ParsedCircuit:
        is_qasm2 = "OPENQASM 2.0" in qasm
        
        if is_qasm2:
            return self._parse_qasm2_with_qiskit(qasm)
        else:
            return self._parse_qasm3(qasm)

    def _parse_qasm3(self, qasm: str) -> ParsedCircuit:
        try:
            ast = openqasm3.parse(qasm)
        except Exception:
            return self._parse_qasm2_with_qiskit(qasm)
            
        qubit_count = 0
        gate_count = 0
        gate_histogram: Dict[str, int] = {}
        qubit_usage: Dict[int, int] = {}
        measured_qubits = set()
        
        for statement in ast.statements:
            if isinstance(statement, QubitDeclaration):
                qubit_count += statement.size.value if statement.size else 1
            elif isinstance(statement, QuantumGate):
                gate_count += 1
                name = statement.name.name
                gate_histogram[name] = gate_histogram.get(name, 0) + 1
                
                for q in statement.qubits:
                    idx = 0 
                    qubit_usage[idx] = qubit_usage.get(idx, 0) + 1
            elif isinstance(statement, QuantumMeasurement):
                gate_count += 1
                measured_qubits.add(0) 

        meas_pattern = "none"
        if len(measured_qubits) == qubit_count and qubit_count > 0:
            meas_pattern = "all"
        elif len(measured_qubits) > 0:
            meas_pattern = "partial"
            
        return ParsedCircuit(
            qubit_count=qubit_count,
            gate_count=gate_count,
            depth=gate_count,
            gate_histogram=gate_histogram,
            qubit_usage=qubit_usage,
            measurement_pattern=meas_pattern,
            has_classical_control=False,
            estimated_runtime_us=gate_count * 0.1,
            raw_ast={"type": "openqasm3"}
        )

    def _parse_qasm2_with_qiskit(self, qasm: str) -> ParsedCircuit:
        try:
            qc = QuantumCircuit.from_qasm_str(qasm)
        except Exception as e:
            raise ValueError(f"Failed to parse QASM: {str(e)}")

        qubit_count = qc.num_qubits
        gate_count = 0
        gate_histogram: Dict[str, int] = {}
        qubit_usage: Dict[int, int] = {}
        measured_qubits = set()
        
        for inst in qc.data:
            name = inst.operation.name
            gate_count += 1
            gate_histogram[name] = gate_histogram.get(name, 0) + 1
            
            if name == 'measure':
                for q in inst.qubits:
                    idx = qc.find_bit(q).index
                    measured_qubits.add(idx)
            else:
                for q in inst.qubits:
                    idx = qc.find_bit(q).index
                    qubit_usage[idx] = qubit_usage.get(idx, 0) + 1

        meas_pattern = "none"
        if len(measured_qubits) == qubit_count and qubit_count > 0:
            meas_pattern = "all"
        elif len(measured_qubits) > 0:
            meas_pattern = "partial"

        return ParsedCircuit(
            qubit_count=qubit_count,
            gate_count=gate_count,
            depth=qc.depth(),
            gate_histogram=gate_histogram,
            qubit_usage=qubit_usage,
            measurement_pattern=meas_pattern,
            has_classical_control=False,
            estimated_runtime_us=gate_count * 0.1,
            raw_ast={"type": "qiskit"}
        )
