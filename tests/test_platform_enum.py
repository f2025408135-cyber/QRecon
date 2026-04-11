import json
import pytest
import respx
from httpx import Response

from qrecon.platform_enum.ibm import IBMQuantumEnumerator
from qrecon.platform_enum.braket import BraketEnumerator
from qrecon.platform_enum.azure import AzureQuantumEnumerator
from qrecon.platform_enum.ionq import IonQEnumerator


@pytest.fixture
def mock_ibm_responses():
    with open("tests/fixtures/mock_ibm_responses.json", "r") as f:
        return json.load(f)


@pytest.fixture
def mock_braket_responses():
    with open("tests/fixtures/mock_braket_responses.json", "r") as f:
        return json.load(f)


class MockIBMBackend:
    def __init__(self, data):
        self._data = data
        self.name = data["backend_name"]

    def configuration(self):
        class Conf:
            n_qubits = self._data["n_qubits"]
            simulator = self._data["simulator"]
            basis_gates = self._data["basis_gates"]
            max_shots = self._data["max_shots"]
            coupling_map = self._data["coupling_map"]
        return Conf()

    def status(self):
        class Stat:
            operational = self._data["operational"]
        return Stat()

    def properties(self):
        if self._data["simulator"]:
            return None
            
        class Props:
            # We construct a mock structure that IBMQuantumEnumerator expects
            class QubitProp:
                def __init__(self, name, value):
                    self.name = name
                    self.value = value
                    
            class GatePropParam:
                def __init__(self, name, value):
                    self.name = name
                    self.value = value
                    
            class GateProp:
                def __init__(self, gate, qubits, params):
                    self.gate = gate
                    self.qubits = qubits
                    self.parameters = params

            qubits = [
                [
                    QubitProp("T1", 210.5e-6),
                    QubitProp("T2", 150.2e-6),
                    QubitProp("readout_error", 0.015)
                ],
                [
                    QubitProp("T1", 190.1e-6),
                    QubitProp("T2", 140.8e-6),
                    QubitProp("readout_error", 0.018)
                ]
            ]
            gates = [
                GateProp("cx", [0, 1], [GatePropParam("gate_error", 0.008)]),
                GateProp("cx", [1, 0], [GatePropParam("gate_error", 0.008)])
            ]
        return Props()


class MockIBMQRuntimeService:
    def __init__(self, channel, token, mock_data):
        self.channel = channel
        self.token = token
        self._mock_data = mock_data
        
        class _Account:
            channel = "ibm_quantum"
            instance = "ibm-q/open/main"
        self._account = _Account()

    def backends(self):
        return [MockIBMBackend(b) for b in self._mock_data["backends"]]

    def jobs(self, limit=10):
        class MockJob:
            def __init__(self, data):
                self._data = data
            def job_id(self):
                return self._data["id"]
            @property
            def creation_date(self):
                return self._data["creation_date"]
            def status(self):
                return self._data["status"]
            def backend(self):
                class MockB:
                    name = self._data["backend_name"]
                return MockB()
        return [MockJob(j) for j in self._mock_data["jobs"]]


@pytest.fixture
def patch_ibm_qiskit(monkeypatch, mock_ibm_responses):
    def mock_service(*args, **kwargs):
        return MockIBMQRuntimeService(mock_data=mock_ibm_responses, *args, **kwargs)
    monkeypatch.setattr("qrecon.platform_enum.ibm.QiskitRuntimeService", mock_service)


@respx.mock
def test_ibm_enumerator_returns_attack_surface_map(patch_ibm_qiskit):
    # Mock the direct API call used for metadata/rate limits
    respx.get("https://api.quantum-computing.ibm.com/v4/users/me").mock(
        return_value=Response(
            200, 
            json={"id": "user123"},
            headers={"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99"}
        )
    )
    
    enumerator = IBMQuantumEnumerator(ibm_token="fake_token")
    result = enumerator.enumerate()
    
    assert result.platform == "ibm-quantum"
    assert len(result.backends) == 2
    assert "channel" in result.account_info
    assert len(result.account_info["recent_jobs"]) == 2
    assert "x-ratelimit-limit" in result.rate_limit_info


@respx.mock
def test_ibm_enumerator_collects_all_backends(patch_ibm_qiskit):
    respx.get("https://api.quantum-computing.ibm.com/v4/users/me").mock(return_value=Response(200))
    
    enumerator = IBMQuantumEnumerator(ibm_token="fake_token")
    result = enumerator.enumerate()
    
    names = [b.name for b in result.backends]
    assert "ibm_brisbane" in names
    assert "ibmq_qasm_simulator" in names


@respx.mock
def test_ibm_enumerator_populates_attack_surface_notes_when_detailed_calibration_present(patch_ibm_qiskit):
    respx.get("https://api.quantum-computing.ibm.com/v4/users/me").mock(return_value=Response(200))
    
    enumerator = IBMQuantumEnumerator(ibm_token="fake_token")
    result = enumerator.enumerate()
    
    has_cal_note = any("exposes detailed calibration data" in note for note in result.attack_surface_notes)
    assert has_cal_note
    
    brisbane = next(b for b in result.backends if b.name == "ibm_brisbane")
    assert brisbane.calibration is not None
    assert "0" in brisbane.calibration
    assert brisbane.calibration["0"].t1_us == 210.5


@respx.mock
def test_ibm_enumerator_handles_calibration_api_failure_gracefully(monkeypatch, mock_ibm_responses):
    class FailingPropertiesBackend(MockIBMBackend):
        def properties(self):
            raise Exception("API Error")

    class MockFailingService(MockIBMQRuntimeService):
        def backends(self):
            return [FailingPropertiesBackend(b) for b in self._mock_data["backends"]]

    monkeypatch.setattr("qrecon.platform_enum.ibm.QiskitRuntimeService", lambda **kw: MockFailingService(mock_data=mock_ibm_responses, channel="c", token="t"))
    respx.get("https://api.quantum-computing.ibm.com/v4/users/me").mock(return_value=Response(200))

    enumerator = IBMQuantumEnumerator(ibm_token="fake_token")
    result = enumerator.enumerate()
    
    # It should still return the backends, just without calibration
    assert len(result.backends) == 2
    
    # We should have an error logged
    assert len(result.errors) > 0
    assert any("calibration" in e.operation for e in result.errors)


@respx.mock
def test_ibm_enumerator_detects_rate_limit_headers(patch_ibm_qiskit):
    respx.get("https://api.quantum-computing.ibm.com/v4/users/me").mock(
        return_value=Response(
            200, 
            json={"id": "user123"},
            headers={"X-RateLimit-Limit": "100", "Retry-After": "3600"}
        )
    )
    
    enumerator = IBMQuantumEnumerator(ibm_token="fake_token")
    result = enumerator.enumerate()
    
    assert "x-ratelimit-limit" in result.rate_limit_info
    assert "retry-after" in result.rate_limit_info
    has_rate_note = any("Rate limit headers detected" in note for note in result.attack_surface_notes)
    assert has_rate_note


class MockBoto3Session:
    def __init__(self, mock_data, aws_access_key_id, aws_secret_access_key, region_name):
        self.mock_data = mock_data
        
    def client(self, service_name):
        if service_name == 'braket':
            class MockBraketClient:
                def __init__(self, data):
                    self.data = data
                def get_paginator(self, op):
                    outer_data = self.data
                    if op == 'search_devices':
                        class P:
                            def paginate(self, filters):
                                return [{"devices": outer_data["devices"]}]
                        return P()
                    if op == 'search_quantum_tasks':
                        class P:
                            def paginate(self, filters, PaginationConfig=None):
                                return [{"quantumTasks": outer_data["tasks"]}]
                        return P()
                def get_device(self, deviceArn):
                    # Find in mock data
                    for d in self.data["devices"]:
                        if d["deviceArn"] == deviceArn:
                            return {"deviceCapabilities": d["deviceCapabilities"]}
                    return {"deviceCapabilities": "{}"}
            return MockBraketClient(self.mock_data)
            
        if service_name == 's3':
            class MockS3Client:
                def list_buckets(self):
                    return {"Buckets": [{"Name": "amazon-braket-test-bucket"}, {"Name": "other-bucket"}]}
            return MockS3Client()


@pytest.fixture
def patch_boto3(monkeypatch, mock_braket_responses):
    def mock_session(**kwargs):
        return MockBoto3Session(mock_data=mock_braket_responses, **kwargs)
    monkeypatch.setattr("boto3.Session", mock_session)


def test_braket_enumerator_returns_enumeration_result(patch_boto3):
    enumerator = BraketEnumerator("fake_id", "fake_secret")
    result = enumerator.enumerate()
    
    assert result.platform == "amazon-braket"
    assert len(result.backends) == 2
    
    names = [b.name for b in result.backends]
    assert "SV1" in names
    assert "Aria 1" in names
    
    assert "amazon-braket-test-bucket" in result.account_info.get("braket_s3_buckets", [])
    assert len(result.account_info.get("recent_tasks", [])) == 1


def test_braket_enumerator_records_iam_permission_probe_results(patch_boto3):
    enumerator = BraketEnumerator("fake_id", "fake_secret")
    result = enumerator.enumerate()
    
    assert "iam_probe_results" in result.account_info
    assert result.account_info["iam_probe_results"].get("get_device") == "Allowed"


def test_azure_enumerator_raises_not_implemented():
    enumerator = AzureQuantumEnumerator("sub", "rg", "workspace")
    with pytest.raises(NotImplementedError) as exc:
        enumerator.enumerate()
    assert "Azure Quantum enumeration not yet implemented" in str(exc.value)


def test_results_serialize_to_json_without_error(patch_ibm_qiskit):
    enumerator = IBMQuantumEnumerator(ibm_token="fake_token")
    result = enumerator.enumerate()
    
    # Should not raise exception
    json_data = result.model_dump_json()
    assert "ibm_brisbane" in json_data
