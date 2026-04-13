import time
from datetime import datetime, timezone
from typing import Dict, List, Any
from pydantic import BaseModel, Field

try:
    from github import Github
    from github.GithubException import RateLimitExceededException, GithubException
    GITHUB_AVAILABLE = True
except ImportError:
    GITHUB_AVAILABLE = False

from qrecon.q_attck.models import Finding, Severity

def _now_utc():
    return datetime.now(timezone.utc)

class CredentialLeakScanResult(BaseModel):
    timestamp: datetime = Field(default_factory=_now_utc)
    queries_executed: int = 0
    disclaimer: str = "QRecon reports potential exposures for responsible disclosure purposes only. Do not use found credentials."
    findings: List[Finding] = []


class CredentialLeakScanner:
    def __init__(self, github_token: str):
        self.github_token = github_token

    def scan(self, search_depth: int = 100) -> CredentialLeakScanResult:
        result = CredentialLeakScanResult()
        
        if not GITHUB_AVAILABLE or not self.github_token:
            finding = Finding(
                module="auth_probe.credential_leak",
                title="Scanner initialization failed",
                description="PyGithub not available or token missing.",
                severity=Severity.LOW,
                platform="all",
                raw_data={}
            )
            result.findings.append(finding)
            return result

        g = Github(self.github_token)
        
        queries = [
            "\"QiskitRuntimeService token\" language:python",
            "\"IBMProvider token\" language:python",
            "\"IBMRuntimeService token\" language:python",
            "\"qiskitrc\" filename:qiskitrc",
            "\"ibm-quantum\" \"token\" filename:*.env"
        ]

        for query in queries:
            try:
                results = g.search_code(query)
                result.queries_executed += 1
                
                count = 0
                for file in results:
                    if count >= search_depth:
                        break
                        
                    if "test" not in file.name.lower():
                        finding = Finding(
                            module="auth_probe.credential_leak",
                            title="Exposed API Key on GitHub",
                            description=f"Potential IBM token found in {file.repository.full_name}/{file.path}",
                            severity=Severity.CRITICAL,
                            platform="ibm-quantum",
                            raw_data={
                                "repo": file.repository.html_url,
                                "path": file.path,
                                "query": query
                            }
                        )
                        result.findings.append(finding)
                        
                    count += 1
                    
                    time.sleep(1)
                    
            except RateLimitExceededException:
                break
            except GithubException as e:
                pass
            except Exception as e:
                pass

        return result
