import asyncio
import time
import httpx
from datetime import datetime, timezone
from typing import Dict, List, Any
from pydantic import BaseModel, Field

from qrecon.config import get_logger, IBM_API_BASE_URL
from qrecon.q_attck.models import Finding, Severity

logger = get_logger("rate_limit_prober")

def _now_utc():
    return datetime.now(timezone.utc)

class RateLimitProbingResult(BaseModel):
    platform: str
    timestamp: datetime = Field(default_factory=_now_utc)
    probes_executed: List[Dict[str, Any]] = []
    findings: List[Finding] = []

class RateLimitProber:
    def __init__(self, platform: str, credentials: Dict[str, str]):
        self.platform = platform
        self.credentials = credentials
        self.max_concurrent_requests = 20

    def probe(self) -> RateLimitProbingResult:
        result = RateLimitProbingResult(platform=self.platform)
        
        if self.platform == "ibm-quantum":
            token = self.credentials.get("ibm_token")
            if not token:
                logger.error("missing_ibm_token_for_rate_limits")
                return result
                
            base_url = IBM_API_BASE_URL
            headers = {"X-Access-Token": token}
            endpoint = f"{base_url}/v4/users/me"
            
            logger.info("initiating_async_rate_limit_probe", endpoint=endpoint, target_requests=self.max_concurrent_requests)
            
            try:
                # We use asyncio.run to execute the async event loop synchronously from the CLI scope
                probe_record = asyncio.run(self._fire_async_burst(endpoint, headers, self.max_concurrent_requests))
                result.probes_executed.append(probe_record)
                
                throttled = any(res["status"] in [429, 503] for res in probe_record["results"])
                
                if not throttled:
                    finding = Finding(
                        module="auth_probe.rate_limits",
                        title="Absent Rate Limiting",
                        description="Concurrent burst of API requests did not trigger a 429 Too Many Requests response.",
                        severity=Severity.MEDIUM,
                        platform=self.platform,
                        raw_data={"endpoint": endpoint, "requests_sent": self.max_concurrent_requests}
                    )
                    result.findings.append(finding)
                    logger.warning("absent_rate_limiting_detected", endpoint=endpoint)
                else:
                    logger.info("rate_limiting_successfully_triggered")
                    
            except Exception as e:
                logger.error("async_probe_failed", error=str(e))

        return result

    async def _fire_async_burst(self, endpoint: str, headers: Dict[str, str], count: int) -> Dict[str, Any]:
        probe_record = {"endpoint": endpoint, "results": []}
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            tasks = [self._fetch(client, endpoint, headers, i) for i in range(count)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for res in results:
                if isinstance(res, dict):
                    probe_record["results"].append(res)
                elif isinstance(res, Exception):
                    logger.debug("async_request_exception", error=str(res))
                    probe_record["results"].append({"status": "Network Error", "error": str(res)})
                    
        return probe_record

    async def _fetch(self, client: httpx.AsyncClient, endpoint: str, headers: Dict[str, str], iteration: int) -> Dict[str, Any]:
        try:
            resp = await client.get(endpoint, headers=headers)
            return {
                "iteration": iteration,
                "status": resp.status_code,
                "headers": dict(resp.headers)
            }
        except httpx.RequestError as e:
            return {"iteration": iteration, "status": "Network Error"}
