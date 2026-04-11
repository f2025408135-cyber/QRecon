import time
import httpx
from datetime import datetime
from typing import Dict, List, Any
from pydantic import BaseModel, Field

from qrecon.q_attck.models import Finding, Severity

class RateLimitProbingResult(BaseModel):
    platform: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    probes_executed: List[Dict[str, Any]] = []
    findings: List[Finding] = []


class RateLimitProber:
    def __init__(self, platform: str, credentials: Dict[str, str]):
        self.platform = platform
        self.credentials = credentials

    def probe(self) -> RateLimitProbingResult:
        result = RateLimitProbingResult(platform=self.platform)
        
        if self.platform == "ibm-quantum":
            token = self.credentials.get("ibm_token")
            if not token:
                return result
                
            base_url = "https://api.quantum-computing.ibm.com"
            headers = {"X-Access-Token": token}
            
            endpoint = f"{base_url}/v4/users/me"
            
            with httpx.Client(timeout=10.0) as client:
                probe_record = {"endpoint": endpoint, "results": []}
                throttled = False
                
                for i in range(10):
                    try:
                        resp = client.get(endpoint, headers=headers)
                        probe_record["results"].append({
                            "iteration": i,
                            "status": resp.status_code,
                            "headers": dict(resp.headers)
                        })
                        if resp.status_code in [429, 503]:
                            throttled = True
                    except Exception as e:
                         pass
                         
                result.probes_executed.append(probe_record)
                
                if not throttled:
                    finding = Finding(
                        module="auth_probe.rate_limits",
                        title="Absent Rate Limiting",
                        description="Burst of API requests did not trigger a 429 Too Many Requests response.",
                        severity=Severity.MEDIUM,
                        platform=self.platform,
                        raw_data={"endpoint": endpoint, "requests_sent": 10}
                    )
                    result.findings.append(finding)

        return result
