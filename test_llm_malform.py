from qrecon.qhypo.agent import QHypoAgent
from qrecon.platform_enum.models import AttackSurfaceMap
from datetime import datetime, timezone

def run():
    agent = QHypoAgent("fake", "claude-3-5-sonnet-20241022")
    # Simulate LLM returning entirely non-JSON syntax despite tool calling request
    class MockMessage:
        def __init__(self):
            class Block:
                type = "text"
                text = "Sorry, I can't do that."
            self.content = [Block()]

    class MockMessages:
        def create(self, **kwargs):
            return MockMessage()
            
    class MockClient:
        def __init__(self):
            self.messages = MockMessages()
            
    agent.client = MockClient()
    
    mock_surface = AttackSurfaceMap(
        platform="ibm-quantum",
        enumeration_timestamp=datetime.now(timezone.utc),
        backends=[], account_info={}, api_metadata={}, rate_limit_info={},
        attack_surface_notes=[], errors=[], raw_findings=[]
    )
    
    rep = agent.generate_hypotheses(mock_surface, hypothesis_count=1)
    print(f"Hypotheses Count: {rep.hypothesis_count}")
    print(f"Generation Notes: {rep.generation_notes}")

run()
