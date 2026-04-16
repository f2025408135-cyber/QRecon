import asyncio
import httpx
import time
from qrecon.auth_probe.rate_limits import RateLimitProber
import pytest
import respx

@respx.mock
def test_async_connection_pool_exhaustion():
    # Simulate a target that holds connections open indefinitely (Slowloris-style)
    # The default httpx.AsyncClient has limits on connection pools.
    
    def slow_response(request):
        time.sleep(2) # Blocking sleep to simulate terrible target
        return httpx.Response(200)

    respx.get("https://api.quantum-computing.ibm.com/v4/users/me").mock(side_effect=slow_response)

    prober = RateLimitProber("ibm-quantum", {"ibm_token": "valid_token"})
    prober.max_concurrent_requests = 200 # Overload the pool significantly

    start = time.time()
    result = prober.probe()
    end = time.time()

    print(f"Pool Exhaustion Simulation took: {end - start:.2f}s")
    
    # Check if requests successfully returned or errored out due to timeout/pool limits
    successes = sum(1 for r in result.probes_executed[0]["results"] if r.get("status") == 200)
    errors = sum(1 for r in result.probes_executed[0]["results"] if r.get("status") == "Network Error")
    print(f"Successes: {successes}, Errors (Timeouts/Pools): {errors}")

if __name__ == "__main__":
    test_async_connection_pool_exhaustion()
