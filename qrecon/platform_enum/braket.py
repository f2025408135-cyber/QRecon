import time
import json
from datetime import datetime, timezone
from typing import Dict, List, Any

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from qrecon.config import get_logger
from qrecon.platform_enum.models import (
    BraketEnumerationResult,
    BackendInfo,
    EnumerationError,
)
from qrecon.q_attck.models import Finding

logger = get_logger("braket_enumerator")

def _now_utc():
    return datetime.now(timezone.utc)

class BraketEnumerator:
    def __init__(self, aws_access_key_id: str, aws_secret_access_key: str, region: str = "us-east-1"):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.region = region
        self.client = None
        self.s3_client = None

    def enumerate(self) -> BraketEnumerationResult:
        start_time = time.time()
        errors: List[EnumerationError] = []
        notes: List[str] = []
        backends: List[BackendInfo] = []
        account_info: Dict[str, Any] = {}
        api_metadata: Dict[str, Any] = {}
        rate_limit_info: Dict[str, Any] = {}
        findings: List[Finding] = []

        if not BOTO3_AVAILABLE:
            duration = time.time() - start_time
            logger.error("boto3_not_installed")
            return BraketEnumerationResult(
                platform="amazon-braket",
                enumeration_timestamp=_now_utc(),
                backends=[],
                account_info={},
                api_metadata={},
                rate_limit_info={},
                attack_surface_notes=["boto3 not installed. Cannot enumerate Braket."],
                errors=[EnumerationError(
                    module="braket",
                    operation="init",
                    error_type="ImportError",
                    message="boto3 is required for Amazon Braket enumeration."
                )],
                raw_findings=[],
                enumeration_duration_seconds=duration
            )

        try:
            session = boto3.Session(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                region_name=self.region
            )
            self.client = session.client('braket')
            self.s3_client = session.client('s3')
        except Exception as e:
             logger.error("braket_session_creation_failed", error=str(e))
             duration = time.time() - start_time
             return BraketEnumerationResult(
                platform="amazon-braket",
                enumeration_timestamp=_now_utc(),
                backends=[],
                account_info={},
                api_metadata={},
                rate_limit_info={},
                attack_surface_notes=["Authentication failed."],
                errors=[EnumerationError(
                    module="braket",
                    operation="authenticate",
                    error_type=type(e).__name__,
                    message=f"Failed to create boto3 session: {str(e)}"
                )],
                raw_findings=[],
                enumeration_duration_seconds=duration
            )

        try:
            paginator = self.client.get_paginator('search_devices')
            page_iterator = paginator.paginate(filters=[])
            
            for page in page_iterator:
                for device in page.get('devices', []):
                    try:
                        device_details = self.client.get_device(deviceArn=device['deviceArn'])
                        capabilities_str = device_details.get('deviceCapabilities', '{}')
                        capabilities = json.loads(capabilities_str)
                        
                        num_qubits = 0
                        if 'paradigm' in capabilities and 'qubitCount' in capabilities['paradigm']:
                            num_qubits = capabilities['paradigm']['qubitCount']
                            
                        basis_gates = []
                        if 'action' in capabilities and 'braket.ir.jaqcd.program' in capabilities['action']:
                            basis_gates = capabilities['action']['braket.ir.jaqcd.program'].get('supportedOperations', [])

                        b_info = BackendInfo(
                            name=device.get('deviceName', 'Unknown'),
                            provider=device.get('providerName', 'Unknown'),
                            num_qubits=num_qubits,
                            operational=device.get('deviceStatus') == 'ONLINE',
                            is_simulator=device.get('deviceType') == 'SIMULATOR',
                            basis_gates=basis_gates,
                            max_shots=10000 
                        )
                        backends.append(b_info)
                    except Exception as e:
                        logger.warning("device_details_fetch_failed", deviceArn=device.get('deviceArn'), error=str(e))
                        errors.append(
                            EnumerationError(
                                module="braket",
                                operation=f"get_device_{device.get('deviceArn')}",
                                error_type=type(e).__name__,
                                message=f"Failed to get device details: {str(e)}"
                            )
                        )
        except Exception as e:
            logger.error("device_listing_failed", error=str(e))
            errors.append(
                EnumerationError(
                    module="braket",
                    operation="search_devices",
                    error_type=type(e).__name__,
                    message=f"Failed to list devices: {str(e)}"
                )
            )

        try:
            buckets = self.s3_client.list_buckets()
            braket_buckets = []
            for b in buckets.get('Buckets', []):
                name = b['Name']
                if "braket" in name.lower() or "quantum" in name.lower():
                    braket_buckets.append(name)
            
            account_info["braket_s3_buckets"] = braket_buckets
            if braket_buckets:
                notes.append(f"Found {len(braket_buckets)} potentially Braket-related S3 buckets.")
        except Exception as e:
            logger.warning("s3_bucket_listing_failed", error=str(e))
            errors.append(
                EnumerationError(
                    module="braket",
                    operation="list_buckets",
                    error_type=type(e).__name__,
                    message=f"Failed to list S3 buckets: {str(e)}"
                )
            )

        try:
            paginator = self.client.get_paginator('search_quantum_tasks')
            page_iterator = paginator.paginate(filters=[], PaginationConfig={'MaxItems': 20})
            
            recent_tasks = []
            for page in page_iterator:
                for task in page.get('quantumTasks', []):
                    recent_tasks.append({
                        "task_arn": task.get('quantumTaskArn'),
                        "status": task.get('status'),
                        "device_arn": task.get('deviceArn'),
                        "created_at": str(task.get('createdAt'))
                    })
            account_info["recent_tasks"] = recent_tasks
        except Exception as e:
             logger.warning("task_history_listing_failed", error=str(e))
             errors.append(
                EnumerationError(
                    module="braket",
                    operation="search_quantum_tasks",
                    error_type=type(e).__name__,
                    message=f"Failed to list recent tasks: {str(e)}"
                )
            )

        permission_results = {}
        
        try:
            self.client.get_device(deviceArn="arn:aws:braket:::device/quantum-simulator/amazon/sv1")
            permission_results["get_device"] = "Allowed"
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                permission_results["get_device"] = "Denied"
            else:
                 logger.debug("iam_probe_get_device_error", error=str(e))
                 permission_results["get_device"] = "Error"
        except BotoCoreError as e:
            logger.debug("iam_probe_get_device_error", error=str(e))
            permission_results["get_device"] = "Error"
                 
        try:
            permission_results["list_tags"] = "Skipped"
        except Exception as e:
            logger.debug("iam_probe_list_tags_error", error=str(e))
            
        account_info["iam_probe_results"] = permission_results
        notes.append("Completed IAM permission probes.")

        duration = time.time() - start_time
        logger.info("braket_enumeration_complete", duration=duration, backends=len(backends))
        return BraketEnumerationResult(
            platform="amazon-braket",
            enumeration_timestamp=_now_utc(),
            backends=backends,
            account_info=account_info,
            api_metadata=api_metadata,
            rate_limit_info=rate_limit_info,
            attack_surface_notes=notes,
            errors=errors,
            raw_findings=findings,
            enumeration_duration_seconds=duration
        )
