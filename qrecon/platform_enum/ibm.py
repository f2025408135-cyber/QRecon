import time
import httpx
from datetime import datetime, timezone
from typing import Dict, List, Any

from qiskit_ibm_runtime import QiskitRuntimeService

from qrecon.config import IBM_API_BASE_URL, get_logger
from qrecon.platform_enum.models import (
    IBMEnumerationResult,
    BackendInfo,
    QubitCalibration,
    EnumerationError,
)

logger = get_logger("ibm_enumerator")

def _now_utc():
    return datetime.now(timezone.utc)

class IBMQuantumEnumerator:
    def __init__(self, ibm_token: str):
        self.ibm_token = ibm_token
        self.service = None
        self.api_base_url = IBM_API_BASE_URL
        
    def enumerate(self) -> IBMEnumerationResult:
        start_time = time.time()
        errors: List[EnumerationError] = []
        notes: List[str] = []
        backends: List[BackendInfo] = []
        account_info: Dict[str, Any] = {}
        api_metadata: Dict[str, Any] = {}
        rate_limit_info: Dict[str, Any] = {}
        
        try:
            self.service = QiskitRuntimeService(channel="ibm_quantum", token=self.ibm_token)
        except Exception as e:
            logger.error("ibm_authentication_failed", error=str(e))
            errors.append(
                EnumerationError(
                    module="ibm",
                    operation="authenticate",
                    error_type=type(e).__name__,
                    message=f"Failed to authenticate: {str(e)}"
                )
            )
            duration = time.time() - start_time
            return IBMEnumerationResult(
                platform="ibm-quantum",
                enumeration_timestamp=_now_utc(),
                backends=[],
                account_info={},
                api_metadata={},
                rate_limit_info={},
                attack_surface_notes=["Authentication failed. Enumeration aborted."],
                errors=errors,
                raw_findings=[],
                enumeration_duration_seconds=duration
            )

        try:
            for backend in self.service.backends():
                try:
                    conf = backend.configuration()
                    stat = backend.status()
                    
                    b_info = BackendInfo(
                        name=backend.name,
                        provider="ibm-quantum",
                        num_qubits=conf.n_qubits,
                        operational=stat.operational,
                        is_simulator=conf.simulator,
                        basis_gates=conf.basis_gates,
                        max_shots=conf.max_shots,
                        coupling_map=getattr(conf, "coupling_map", None)
                    )

                    if not b_info.is_simulator and b_info.operational:
                        try:
                            props = backend.properties()
                            if props:
                                cal_dict = {}
                                for q_idx, q_props in enumerate(props.qubits):
                                    q_data = {ndv.name: ndv.value for ndv in q_props}
                                    t1 = q_data.get("T1", 0) * 1e6 
                                    t2 = q_data.get("T2", 0) * 1e6
                                    readout_error = q_data.get("readout_error", 0)
                                    
                                    gate_errors = {}
                                    for gate in props.gates:
                                        if q_idx in gate.qubits:
                                            for p in gate.parameters:
                                                if p.name == "gate_error":
                                                    gate_errors[gate.gate] = p.value
                                                    
                                    cal_dict[str(q_idx)] = QubitCalibration(
                                        qubit_id=q_idx,
                                        t1_us=t1,
                                        t2_us=t2,
                                        readout_error=readout_error,
                                        gate_errors=gate_errors
                                    )
                                b_info.calibration = cal_dict
                                
                                if len(cal_dict) > 0:
                                    notes.append(f"Backend {b_info.name} exposes detailed calibration data.")
                        except Exception as e:
                            logger.warning("calibration_fetch_failed", backend=backend.name, error=str(e))
                            errors.append(
                                EnumerationError(
                                    module="ibm",
                                    operation=f"calibration_{backend.name}",
                                    error_type=type(e).__name__,
                                    message=f"Calibration data fetch failed: {str(e)}"
                                )
                            )

                    backends.append(b_info)
                except Exception as e:
                     logger.warning("backend_details_failed", backend=backend.name, error=str(e))
                     errors.append(
                        EnumerationError(
                            module="ibm",
                            operation=f"backend_details_{backend.name}",
                            error_type=type(e).__name__,
                            message=f"Backend detail fetch failed: {str(e)}"
                        )
                    )
        except Exception as e:
            logger.error("backend_listing_failed", error=str(e))
            errors.append(
                EnumerationError(
                    module="ibm",
                    operation="backend_list",
                    error_type=type(e).__name__,
                    message=f"Backend listing failed: {str(e)}"
                )
            )

        try:
            instances = getattr(self.service, "_account", None)
            if instances:
                 account_info["channel"] = instances.channel
                 account_info["instance"] = instances.instance
        except Exception as e:
             logger.debug("account_info_fetch_failed", error=str(e))

        try:
            with httpx.Client() as client:
                headers = {"X-Access-Token": self.ibm_token}
                resp = client.get(f"{self.api_base_url}/v4/users/me", headers=headers)
                api_metadata["status_code"] = resp.status_code
                api_metadata["headers"] = dict(resp.headers)
                
                for h, v in resp.headers.items():
                    if "ratelimit" in h.lower() or "retry-after" in h.lower():
                        rate_limit_info[h.lower()] = v
                
                if rate_limit_info:
                    notes.append("Rate limit headers detected in API response.")
                    
                if resp.status_code == 200:
                    account_info["user_details"] = resp.json()
        except Exception as e:
            logger.warning("api_probe_failed", error=str(e))
            errors.append(
                EnumerationError(
                    module="ibm",
                    operation="api_probe",
                    error_type=type(e).__name__,
                    message=f"Direct API probe failed: {str(e)}"
                )
            )

        try:
            jobs = self.service.jobs(limit=10)
            account_info["recent_jobs"] = [
                {
                    "job_id": j.job_id(),
                    "creation_date": str(j.creation_date),
                    "status": str(j.status()),
                    "backend": j.backend().name if j.backend() else "unknown"
                }
                for j in jobs
            ]
        except Exception as e:
            logger.warning("job_history_fetch_failed", error=str(e))
            errors.append(
                EnumerationError(
                    module="ibm",
                    operation="job_history",
                    error_type=type(e).__name__,
                    message=f"Job history fetch failed: {str(e)}"
                )
            )

        duration = time.time() - start_time
        logger.info("ibm_enumeration_complete", duration=duration, backends=len(backends))
        return IBMEnumerationResult(
            platform="ibm-quantum",
            enumeration_timestamp=_now_utc(),
            backends=backends,
            account_info=account_info,
            api_metadata=api_metadata,
            rate_limit_info=rate_limit_info,
            attack_surface_notes=notes,
            errors=errors,
            raw_findings=[],
            enumeration_duration_seconds=duration
        )
