import httpx
from datetime import datetime, timezone
from typing import Dict, List, Any
from pydantic import BaseModel, Field

from qrecon.q_attck.models import Finding, Severity

def _now_utc():
    return datetime.now(timezone.utc)

class TokenScopeProbingResult(BaseModel):
    platform: str
    timestamp: datetime = Field(default_factory=_now_utc)
    tier_1_results: Dict[str, str] = {}
    tier_2_results: Dict[str, str] = {}
    findings: List[Finding] = []


class TokenScopeProber:
    def __init__(self, platform: str, credentials: Dict[str, str]):
        self.platform = platform
        self.credentials = credentials

    def probe(self) -> TokenScopeProbingResult:
        result = TokenScopeProbingResult(platform=self.platform)

        if self.platform == "ibm-quantum":
            token = self.credentials.get("ibm_token")
            if not token:
                return result

            base_url = "https://api.quantum-computing.ibm.com"
            headers = {"X-Access-Token": token}
            
            with httpx.Client(timeout=10.0) as client:
                try:
                    resp = client.get(f"{base_url}/v4/users/me", headers=headers)
                    result.tier_1_results["get_account"] = str(resp.status_code)
                except httpx.RequestError as e:
                    result.tier_1_results["get_account"] = "Error: Network failure"
                except Exception as e:
                    result.tier_1_results["get_account"] = "Error"
                    
                tier_2_endpoints = {
                    "network_admin": f"{base_url}/network",
                    "user_listing": f"{base_url}/v4/users",
                    "admin_config": f"{base_url}/admin/config"
                }

                for name, url in tier_2_endpoints.items():
                    try:
                        resp = client.get(url, headers=headers)
                        result.tier_2_results[name] = str(resp.status_code)
                        
                        if resp.status_code == 200:
                            finding = Finding(
                                module="auth_probe.token_scope",
                                title=f"Unexpected access to {name} endpoint",
                                description=f"Standard token successfully accessed elevated endpoint: {url}",
                                severity=Severity.HIGH,
                                platform=self.platform,
                                raw_data={"url": url, "status_code": resp.status_code}
                            )
                            result.findings.append(finding)
                    except httpx.RequestError as e:
                         result.tier_2_results[name] = "Error: Network failure"
                    except Exception as e:
                        result.tier_2_results[name] = "Error"

        return result
