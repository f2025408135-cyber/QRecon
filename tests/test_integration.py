import json
import pytest
from typer.testing import CliRunner

from cli import app

runner = CliRunner()

@pytest.fixture
def mock_env_vars(monkeypatch):
    monkeypatch.setenv("IBM_QUANTUM_TOKEN", "mock_ibm_token")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock_aws_key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock_aws_secret")
    monkeypatch.setenv("GITHUB_TOKEN", "mock_github_token")

# Mock enumerator so we don't actually hit the network in integration tests
@pytest.fixture
def mock_enumerators(monkeypatch):
    from qrecon.platform_enum.models import IBMEnumerationResult, BraketEnumerationResult
    from datetime import datetime
    
    class MockIBM:
        def __init__(self, token):
            self.token = token
        def enumerate(self):
            return IBMEnumerationResult(
                platform="ibm-quantum",
                enumeration_timestamp=datetime.utcnow(),
                backends=[], account_info={}, api_metadata={}, rate_limit_info={},
                attack_surface_notes=[], errors=[], raw_findings=[], enumeration_duration_seconds=0.1
            )
            
    monkeypatch.setattr("cli.IBMQuantumEnumerator", MockIBM)


def test_full_cli_enum_command_runs_with_mock_credentials(mock_env_vars, mock_enumerators, tmp_path):
    output_file = tmp_path / "report.json"
    result = runner.invoke(app, ["enum", "--platform", "ibm", "--output", str(output_file)])
    
    assert result.exit_code == 0
    assert "Enumeration complete!" in result.stdout
    assert output_file.exists()


def test_full_cli_outputs_valid_json(mock_env_vars, mock_enumerators, tmp_path):
    output_file = tmp_path / "report.json"
    result = runner.invoke(app, ["enum", "--platform", "ibm", "--output", str(output_file)])
    
    assert result.exit_code == 0
    with open(output_file, "r") as f:
        data = json.load(f)
        assert data["platform"] == "ibm-quantum"


def test_attck_list_command_outputs_17_techniques():
    result = runner.invoke(app, ["attck", "list-techniques"])
    
    assert result.exit_code == 0
    # Output should contain all 17 technique IDs
    for i in range(1, 18):
        assert f"QTT0{i:02d}" in result.stdout


def test_attck_show_command_outputs_technique_detail():
    result = runner.invoke(app, ["attck", "show", "QTT011"])
    
    assert result.exit_code == 0
    assert "Circuit intellectual property extraction" in result.stdout
    assert "Severity:" in result.stdout
    assert "critical" in result.stdout
