import json
from pathlib import Path
from typing import List, Optional

from qrecon.q_attck.models import Tactic, Technique, Severity

class QuantumATTCKLoader:
    def __init__(self, taxonomy_path: Optional[Path] = None):
        if taxonomy_path is None:
            taxonomy_path = Path(__file__).parent / "taxonomy.json"
        
        with open(taxonomy_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        self.tactics = [Tactic(**t) for t in data["tactics"]]
        self.techniques = [Technique(**t) for t in data["techniques"]]

    def get_tactic(self, tactic_id: str) -> Optional[Tactic]:
        return next((t for t in self.tactics if t.id == tactic_id), None)

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        return next((t for t in self.techniques if t.id == technique_id), None)

    def get_techniques_for_tactic(self, tactic_id: str) -> List[Technique]:
        return [t for t in self.techniques if t.tactic_id == tactic_id]

    def get_techniques_for_platform(self, platform_name: str) -> List[Technique]:
        return [t for t in self.techniques if platform_name in t.platforms]

    def get_techniques_by_severity(self, severity: Severity) -> List[Technique]:
        return [t for t in self.techniques if t.severity == severity]
