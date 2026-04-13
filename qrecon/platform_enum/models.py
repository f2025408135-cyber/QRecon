from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from qrecon.q_attck.models import Finding

def _now_utc():
    return datetime.now(timezone.utc)

class QubitCalibration(BaseModel):
    qubit_id: int
    t1_us: float
    t2_us: float
    readout_error: float
    gate_errors: Dict[str, float]

class BackendInfo(BaseModel):
    name: str
    provider: str
    num_qubits: int
    operational: bool
    is_simulator: bool
    basis_gates: List[str]
    max_shots: int
    coupling_map: Optional[List[List[int]]] = None
    calibration: Optional[Dict[str, QubitCalibration]] = None

class EnumerationError(BaseModel):
    module: str
    operation: str
    error_type: str
    message: str
    timestamp: datetime = Field(default_factory=_now_utc)

class AttackSurfaceMap(BaseModel):
    platform: str
    enumeration_timestamp: datetime
    backends: List[BackendInfo]
    account_info: Dict[str, Any]
    api_metadata: Dict[str, Any]
    rate_limit_info: Dict[str, Any]
    attack_surface_notes: List[str]
    errors: List[EnumerationError]
    raw_findings: List[Finding]

class IBMEnumerationResult(AttackSurfaceMap):
    enumeration_duration_seconds: float

class BraketEnumerationResult(AttackSurfaceMap):
    enumeration_duration_seconds: float
