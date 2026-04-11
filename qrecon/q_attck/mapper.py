from typing import Optional
from qrecon.q_attck.loader import QuantumATTCKLoader
from qrecon.q_attck.models import Finding, MappedFinding, Severity

class FindingMapper:
    def __init__(self, loader: Optional[QuantumATTCKLoader] = None):
        self.loader = loader or QuantumATTCKLoader()

    def map_finding(self, finding: Finding) -> Optional[MappedFinding]:
        title = finding.title.lower()
        description = finding.description.lower()
        
        if "credential" in title or "token" in title or "api key" in title:
            if "jupyter" in description or "notebook" in description or "colab" in description:
                return MappedFinding(finding=finding, tactic_id="QTA003", technique_id="QTT017", confidence=0.9, mapping_rationale="Matches keywords for Jupyter notebook credential exposure.")
            else:
                return MappedFinding(finding=finding, tactic_id="QTA003", technique_id="QTT004", confidence=0.8, mapping_rationale="Matches keywords for general API key exposure.")
        
        if "idor" in title or "foreign job" in description or "other user" in description:
            if "cancel" in description or "modify" in description or "delete" in description:
                return MappedFinding(finding=finding, tactic_id="QTA007", technique_id="QTT016", confidence=0.9, mapping_rationale="Matches keywords for quantum job interference.")
            else:
                return MappedFinding(finding=finding, tactic_id="QTA006", technique_id="QTT011", confidence=0.8, mapping_rationale="Matches keywords for reading other users' job data.")
        
        if "oauth" in title or "scope" in title or "admin endpoint" in description:
            return MappedFinding(finding=finding, tactic_id="QTA003", technique_id="QTT005", confidence=0.85, mapping_rationale="Matches keywords for OAuth scope misconfiguration.")
            
        if "calibration" in title and "harvesting" in description:
            return MappedFinding(finding=finding, tactic_id="QTA001", technique_id="QTT002", confidence=0.9, mapping_rationale="Matches keywords for calibration data harvesting.")
            
        if "timing" in title and "oracle" in description:
            return MappedFinding(finding=finding, tactic_id="QTA001", technique_id="QTT003", confidence=0.85, mapping_rationale="Matches keywords for timing oracle detection.")

        if "depth" in title and "resource" in description and "exhaustion" in description:
            return MappedFinding(finding=finding, tactic_id="QTA004", technique_id="QTT008", confidence=0.85, mapping_rationale="Matches keywords for resource exhaustion.")
            
        if "cross-talk" in title and "probe" in description:
            return MappedFinding(finding=finding, tactic_id="QTA005", technique_id="QTT009", confidence=0.85, mapping_rationale="Matches keywords for multi-tenant boundary probing.")
            
        if "reset" in title and "measure" in title and "loop" in description:
            return MappedFinding(finding=finding, tactic_id="QTA006", technique_id="QTT012", confidence=0.85, mapping_rationale="Matches keywords for reset-and-measure loop result leakage.")

        if "qtt" in title or "qtt" in description:
            for tech in self.loader.techniques:
                if tech.id.lower() in title or tech.id.lower() in description:
                    return MappedFinding(finding=finding, tactic_id=tech.tactic_id, technique_id=tech.id, confidence=0.7, mapping_rationale=f"Explicitly mentioned {tech.id} in title or description.")
        
        return None
