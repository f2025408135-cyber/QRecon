import json
from typing import Dict, List, Any, Optional

try:
    from anthropic import Anthropic, APIError, APITimeoutError
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from qrecon.platform_enum.models import AttackSurfaceMap
from qrecon.auth_probe.token_scope import TokenScopeProbingResult
from qrecon.auth_probe.cross_tenant import CrossTenantProbingResult
from qrecon.auth_probe.rate_limits import RateLimitProbingResult
from qrecon.circuit_lens.models import CircuitFinding
from qrecon.q_attck.models import MappedFinding
from qrecon.qhypo.models import Hypothesis, HypothesisReport, TestRequest
from qrecon.qhypo.prompts import SYSTEM_PROMPT, HYPOTHESIS_GENERATION_PROMPT_TEMPLATE

class QHypoAgent:
    def __init__(self, anthropic_api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        self.api_key = anthropic_api_key
        self.model = model
        self.client = Anthropic(api_key=self.api_key) if ANTHROPIC_AVAILABLE and self.api_key else None

    def generate_hypotheses(
        self,
        attack_surface_map: AttackSurfaceMap,
        auth_probe_result: Optional[Any] = None, 
        circuit_findings: Optional[List[CircuitFinding]] = None,
        q_attck_mappings: Optional[List[MappedFinding]] = None,
        hypothesis_count: int = 10
    ) -> HypothesisReport:
        
        if not self.client:
            return HypothesisReport(
                platform=attack_surface_map.platform,
                model_used=self.model,
                hypothesis_count=0,
                generation_notes="Anthropic API key missing or SDK not installed. Failed to generate hypotheses."
            )

        backend_summary = json.dumps([
            {"name": b.name, "qubits": b.num_qubits, "simulator": b.is_simulator, "gates": b.basis_gates}
            for b in attack_surface_map.backends
        ], indent=2)

        attack_surface_notes = "\n".join(attack_surface_map.attack_surface_notes)

        auth_probe_summary = "No auth probe data provided."
        if auth_probe_result:
            if hasattr(auth_probe_result, 'findings') and getattr(auth_probe_result, 'findings'):
                 auth_probe_summary = "\n".join([
                     f"- {f.title} ({f.severity.value}): {f.description}" 
                     for f in getattr(auth_probe_result, 'findings')
                 ])

        circuit_findings_summary = "No circuit findings provided."
        if circuit_findings:
            circuit_findings_summary = "\n".join([
                f"- {f.title} (Tech: {f.technique_id}): {f.rationale}"
                for f in circuit_findings
            ])

        existing_mappings = "No existing mappings provided."
        if q_attck_mappings:
            existing_mappings = "\n".join([
                f"- {m.finding.title} -> {m.technique_id} ({m.confidence:.2f} confidence)"
                for m in q_attck_mappings
            ])

        user_prompt = HYPOTHESIS_GENERATION_PROMPT_TEMPLATE.format(
            platform=attack_surface_map.platform,
            timestamp=attack_surface_map.enumeration_timestamp.isoformat(),
            backend_summary=backend_summary,
            attack_surface_notes=attack_surface_notes,
            auth_probe_summary=auth_probe_summary,
            circuit_findings_summary=circuit_findings_summary,
            existing_mappings=existing_mappings,
            hypothesis_count=hypothesis_count
        )

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=0.7,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            content = response.content[0].text
        except (APIError, APITimeoutError) as e:
            return HypothesisReport(
                platform=attack_surface_map.platform,
                model_used=self.model,
                hypothesis_count=0,
                generation_notes=f"API call failed: {str(e)}"
            )
        except Exception as e:
            return HypothesisReport(
                platform=attack_surface_map.platform,
                model_used=self.model,
                hypothesis_count=0,
                generation_notes=f"Unexpected error during generation: {str(e)}"
            )

        try:
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
                
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return HypothesisReport(
                platform=attack_surface_map.platform,
                model_used=self.model,
                hypothesis_count=0,
                generation_notes=f"Failed to parse model output as JSON: {str(e)}\nRaw output: {content[:200]}..."
            )

        hypotheses = []
        notes = "Successfully generated hypotheses."
        try:
            if not isinstance(data, list):
                 data = [data] 
                 
            for item in data:
                 hypo = Hypothesis(
                     hypothesis_id=item.get("hypothesis_id", "H000"),
                     title=item.get("title", "Untitled"),
                     technique_hypothesis=item.get("technique_hypothesis", "Unknown"),
                     rationale=item.get("rationale", ""),
                     test_request=TestRequest(**item.get("test_request", {"method":"GET", "endpoint_pattern":""})),
                     expected_vulnerable_response=item.get("expected_vulnerable_response", ""),
                     expected_secure_response=item.get("expected_secure_response", ""),
                     confidence=float(item.get("confidence", 0.0)),
                     novelty=item.get("novelty", "")
                 )
                 hypotheses.append(hypo)
        except Exception as e:
            notes = f"Validation errors occurred while parsing some hypotheses: {str(e)}"

        return HypothesisReport(
            platform=attack_surface_map.platform,
            model_used=self.model,
            hypothesis_count=len(hypotheses),
            hypotheses=hypotheses[:hypothesis_count],
            generation_notes=notes
        )
