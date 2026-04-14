from typing import Dict, List, Any
from pydantic import BaseModel

from qrecon.q_attck.models import Finding

class ParsedCircuit(BaseModel):
    qubit_count: int
    gate_count: int
    depth: int
    gate_histogram: Dict[str, int]
    qubit_usage: Dict[int, int]
    measurement_pattern: str
    has_classical_control: bool
    estimated_runtime_us: float
    raw_ast: Dict[str, Any]


class CircuitFinding(Finding):
    confidence: float
    rationale: str
    technique_id: str


class CircuitAnalysisResult(BaseModel):
    circuit_name: str
    parsed_metrics: ParsedCircuit
    findings: List[CircuitFinding]

class TimingOracleAnalysisResult(BaseModel):
    findings: List[CircuitFinding]
    
class DisclosureAnalysisResult(BaseModel):
    findings: List[CircuitFinding]
