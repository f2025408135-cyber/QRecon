class IonQEnumerator:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def enumerate(self):
        raise NotImplementedError(
            "IonQ enumeration not yet implemented. Planned for v0.2.0. "
            "Contributions welcome — see docs/platform-notes/ionq.md"
        )
