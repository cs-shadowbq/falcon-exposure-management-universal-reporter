from typing import List


class FalconAPIError(Exception):
    """Raised when a CrowdStrike Falcon API call returns an error response."""

    def __init__(self, operation: str, status_code: int, errors: List[dict]) -> None:
        self.operation = operation
        self.status_code = status_code
        self.errors = errors
        if errors:
            details = "; ".join(
                f"{e.get('code', '')}: {e.get('message', '')}" for e in errors
            )
        else:
            details = f"HTTP {status_code}"
        super().__init__(f"[{operation}] {details}")
