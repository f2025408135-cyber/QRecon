import asyncio
import httpx
import time
from qrecon.auth_probe.rate_limits import RateLimitProber

def main():
    prober = RateLimitProber("ibm-quantum", {"ibm_token": "malformed_fake_token"})
    print("Testing against dummy token...")
    start = time.time()
    res = prober.probe()
    end = time.time()
    
    print(f"Time taken: {end - start:.2f}s")
    print(res.model_dump_json(indent=2))

if __name__ == "__main__":
    main()
