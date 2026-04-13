from typing import Dict, List, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field

def _now_utc():
    return datetime.now(timezone.utc)

class TestRequest(BaseModel):
    method: str
    endpoint_pattern: str
    headers_to_test: Dict[str, str] = Field(default_factory=dict)
    parameters_to_test: Dict[str, Any] = Field(default_factory=dict)

class Hypothesis(BaseModel):
    hypothesis_id: str
    title: str
    technique_hypothesis: str
    rationale: str
    test_request: TestRequest
    expected_vulnerable_response: str
    expected_secure_response: str
    confidence: float
    novelty: str

class HypothesisReport(BaseModel):
    platform: str
    generated_at: datetime = Field(default_factory=_now_utc)
    model_used: str
    hypothesis_count: int
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    generation_notes: str = ""
