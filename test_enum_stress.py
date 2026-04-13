from qrecon.platform_enum.ibm import IBMQuantumEnumerator
from qrecon.platform_enum.braket import BraketEnumerator
import time

def main():
    print("Testing enumerator failure resilience...")
    
    ibm = IBMQuantumEnumerator("completely-fake-invalid-token")
    start = time.time()
    res = ibm.enumerate()
    end = time.time()
    print(f"IBM Enumerator resiliently failed in {end-start:.2f}s")
    print(f"Notes: {res.attack_surface_notes}")
    
    braket = BraketEnumerator("bad_key", "bad_secret", "us-east-1")
    start = time.time()
    res2 = braket.enumerate()
    end = time.time()
    print(f"Braket Enumerator resiliently failed in {end-start:.2f}s")
    print(f"Notes: {res2.attack_surface_notes}")
    print(f"Errors count: {len(res2.errors)}")

if __name__ == "__main__":
    main()
