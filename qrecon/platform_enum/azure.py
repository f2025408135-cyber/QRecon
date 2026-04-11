class AzureQuantumEnumerator:
    def __init__(self, subscription_id: str, resource_group: str, workspace_name: str):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name

    def enumerate(self):
        raise NotImplementedError(
            "Azure Quantum enumeration not yet implemented. Planned for v0.2.0. "
            "Contributions welcome — see docs/platform-notes/azure-quantum.md"
        )
