import json
import pytest
from datetime import datetime, timezone

from qrecon.platform_enum.models import AttackSurfaceMap
from qrecon.qhypo.agent import QHypoAgent
from qrecon.qhypo.prompts import HYPOTHESIS_GENERATION_PROMPT_TEMPLATE

@pytest.fixture
def mock_attack_surface():
    return AttackSurfaceMap(
        platform="ibm-quantum",
        enumeration_timestamp=datetime.now(timezone.utc),
        backends=[],
        account_info={},
        api_metadata={},
        rate_limit_info={},
        attack_surface_notes=["Note 1"],
        errors=[],
        raw_findings=[]
    )

class MockToolUseBlock:
    def __init__(self, data):
        self.type = "tool_use"
        self.name = "submit_hypotheses"
        self.input = {"hypotheses": data}

class MockMessages:
    def __init__(self, mock_data):
        self._mock_data = mock_data
        
    def create(self, **kwargs):
        class Resp:
            content = [MockToolUseBlock(self._mock_data)]
        return Resp()

class MockAnthropicClient:
    def __init__(self, mock_data):
        self.messages = MockMessages(mock_data)

@pytest.fixture
def patch_anthropic_tools(monkeypatch):
    def _patch(mock_data):
        monkeypatch.setattr("qrecon.qhypo.agent.Anthropic", lambda api_key: MockAnthropicClient(mock_data))
    return _patch

def test_agent_parses_valid_hypothesis_tool_response(patch_anthropic_tools, mock_attack_surface):
    valid_data = [
      {
        "hypothesis_id": "H001",
        "title": "Test Title",
        "technique_hypothesis": "QTT001",
        "rationale": "Reason",
        "test_request": {
          "method": "GET",
          "endpoint_pattern": "/api/test",
          "headers_to_test": {},
          "parameters_to_test": {}
        },
        "expected_vulnerable_response": "200 OK",
        "expected_secure_response": "403 Forbidden",
        "confidence": 0.8,
        "novelty": "Very"
      }
    ]
    
    patch_anthropic_tools(valid_data)
    
    agent = QHypoAgent(anthropic_api_key="fake_key")
    report = agent.generate_hypotheses(mock_attack_surface, hypothesis_count=1)
    
    assert report.hypothesis_count == 1
    assert len(report.hypotheses) == 1
    assert report.hypotheses[0].hypothesis_id == "H001"

def test_agent_handles_api_error_gracefully(monkeypatch, mock_attack_surface):
    from anthropic import APIError
    
    class FailingMessages:
        def create(self, **kwargs):
             class MockReq:
                 pass
             raise APIError("Test API Error", request=MockReq(), body=None)
             
    class FailingClient:
        def __init__(self):
            self.messages = FailingMessages()
            
    monkeypatch.setattr("qrecon.qhypo.agent.Anthropic", lambda api_key: FailingClient())
    
    agent = QHypoAgent(anthropic_api_key="fake_key")
    report = agent.generate_hypotheses(mock_attack_surface)
    
    assert report.hypothesis_count == 0
    assert "API call failed" in report.generation_notes

def test_prompt_template_fills_all_variables():
    prompt = HYPOTHESIS_GENERATION_PROMPT_TEMPLATE.format(
        platform="ibm-quantum",
        timestamp="2026-04-11T12:00:00",
        backend_summary="1 backend",
        attack_surface_notes="notes",
        auth_probe_summary="auth",
        circuit_findings_summary="circ",
        existing_mappings="map",
        hypothesis_count=3
    )
    
    assert "PLATFORM: ibm-quantum" in prompt
    assert "Generate exactly 3 adversarial hypotheses" in prompt
