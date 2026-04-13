from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Tactic(BaseModel):
    id: str
    name: str
    shortname: str
    description: str

class Technique(BaseModel):
    id: str
    tactic_id: str
    name: str
    description: str
    detection_hints: List[str]
    mitigation_hints: List[str]
    severity: Severity
    platforms: List[str]

def _now_utc():
    return datetime.now(timezone.utc)

class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    module: str
    title: str
    description: str
    severity: Severity
    platform: str
    raw_data: Dict[str, Any]
    timestamp: datetime = Field(default_factory=_now_utc)

class MappedFinding(BaseModel):
    finding: Finding
    tactic_id: str
    technique_id: str
    confidence: float
    mapping_rationale: str
