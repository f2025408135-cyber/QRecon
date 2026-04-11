import pytest
import respx
from httpx import Response

from qrecon.auth_probe.token_scope import TokenScopeProber
from qrecon.auth_probe.cross_tenant import CrossTenantProber
from qrecon.auth_probe.rate_limits import RateLimitProber
from qrecon.auth_probe.credential_leak import CredentialLeakScanner


@respx.mock
def test_token_scope_prober_detects_tier2_unexpected_success():
    respx.get("https://api.quantum-computing.ibm.com/v4/users/me").mock(return_value=Response(200))
    respx.get("https://api.quantum-computing.ibm.com/admin/config").mock(return_value=Response(200))
    respx.get("https://api.quantum-computing.ibm.com/network").mock(return_value=Response(403))
    respx.get("https://api.quantum-computing.ibm.com/v4/users").mock(return_value=Response(403))

    prober = TokenScopeProber("ibm-quantum", {"ibm_token": "token"})
    result = prober.probe()

    assert result.tier_2_results["admin_config"] == "200"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "high"
    assert "admin/config" in result.findings[0].raw_data["url"]


@respx.mock
def test_token_scope_prober_records_expected_403_as_non_finding():
    respx.get("https://api.quantum-computing.ibm.com/v4/users/me").mock(return_value=Response(200))
    respx.get("https://api.quantum-computing.ibm.com/admin/config").mock(return_value=Response(403))
    respx.get("https://api.quantum-computing.ibm.com/network").mock(return_value=Response(403))
    respx.get("https://api.quantum-computing.ibm.com/v4/users").mock(return_value=Response(403))

    prober = TokenScopeProber("ibm-quantum", {"ibm_token": "token"})
    result = prober.probe()

    assert result.tier_2_results["admin_config"] == "403"
    assert len(result.findings) == 0


@respx.mock
def test_cross_tenant_prober_flags_200_on_foreign_job_as_critical_finding():
    base_url = "https://api.quantum-computing.ibm.com/v4/jobs"
    
    respx.get(f"{base_url}/job_12346").mock(return_value=Response(200))
    respx.delete(f"{base_url}/job_12346").mock(return_value=Response(403))
    
    respx.get(url__regex=rf"{base_url}/.*").mock(return_value=Response(404))
    respx.delete(url__regex=rf"{base_url}/.*").mock(return_value=Response(404))

    prober = CrossTenantProber("token")
    result = prober.probe("job_12345")
    
    assert "job_12346" in result.probed_job_ids
    assert result.job_responses["job_12346"]["GET"] == "200"
    
    findings = [f for f in result.findings if f.raw_data.get("job_id") == "job_12346"]
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "read access" in findings[0].title.lower()


@respx.mock
def test_cross_tenant_prober_handles_404_on_all_candidates_gracefully():
    base_url = "https://api.quantum-computing.ibm.com/v4/jobs"
    respx.get(url__regex=rf"{base_url}/.*").mock(return_value=Response(404))
    respx.delete(url__regex=rf"{base_url}/.*").mock(return_value=Response(404))

    prober = CrossTenantProber("token")
    result = prober.probe("job_12345")
    
    assert len(result.probed_job_ids) > 0
    assert len(result.findings) == 0


@respx.mock
def test_rate_limit_prober_detects_absent_rate_limiting():
    respx.get("https://api.quantum-computing.ibm.com/v4/users/me").mock(return_value=Response(200))

    prober = RateLimitProber("ibm-quantum", {"ibm_token": "token"})
    result = prober.probe()
    
    assert len(result.probes_executed) == 1
    assert len(result.probes_executed[0]["results"]) == 10
    
    assert len(result.findings) == 1
    assert result.findings[0].severity == "medium"
    assert "Absent Rate Limiting" in result.findings[0].title


class MockRepository:
    def __init__(self, full_name, html_url):
        self.full_name = full_name
        self.html_url = html_url

class MockContentFile:
    def __init__(self, name, path, repo):
        self.name = name
        self.path = path
        self.repository = repo

class MockGithub:
    def __init__(self, token):
        self.token = token
    def search_code(self, query):
        if "QiskitRuntimeService token" in query:
            repo = MockRepository("user/repo", "http://github.com/user/repo")
            return [MockContentFile("main.py", "src/main.py", repo)]
        return []

@pytest.fixture
def patch_github(monkeypatch):
    monkeypatch.setattr("qrecon.auth_probe.credential_leak.Github", MockGithub)

def test_credential_scanner_detects_real_token_pattern_in_mock_results(patch_github):
    scanner = CredentialLeakScanner("fake_github_token")
    result = scanner.scan()
    
    assert result.queries_executed > 0
    assert len(result.findings) > 0
    assert result.findings[0].severity == "critical"
    assert result.findings[0].raw_data["path"] == "src/main.py"

def test_credential_scanner_ignores_placeholder_tokens(patch_github, monkeypatch):
    class MockGithubPlaceholders(MockGithub):
        def search_code(self, query):
            if "QiskitRuntimeService token" in query:
                repo = MockRepository("user/repo", "http://github.com/user/repo")
                return [MockContentFile("test.py", "src/test.py", repo)]
            return []
    
    monkeypatch.setattr("qrecon.auth_probe.credential_leak.Github", MockGithubPlaceholders)
    
    scanner = CredentialLeakScanner("fake_github_token")
    result = scanner.scan()
    
    assert len(result.findings) == 0

def test_credential_scanner_includes_disclaimer_in_output(patch_github):
    scanner = CredentialLeakScanner("fake_github_token")
    result = scanner.scan()
    
    assert "responsible disclosure" in result.disclaimer
