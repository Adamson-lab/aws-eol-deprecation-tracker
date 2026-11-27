from typing import Any
import httpx


class OPAClient:
    def __init__(self, base_url: str, timeout_seconds: float = 3.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def evaluate(self, payload: dict[str, Any]) -> tuple[bool, str]:
        with httpx.Client(timeout=self.timeout_seconds) as client:
            sov_resp = client.post(f"{self.base_url}/v1/data/eol/sovereignty", json={"input": payload})
            sov_resp.raise_for_status()
            sov_res = sov_resp.json().get("result") or {}
            if not sov_res.get("allow", False):
                return False, sov_res.get("reason", "denied by sovereignty policy")

            win_resp = client.post(f"{self.base_url}/v1/data/eol/window", json={"input": payload})
            win_resp.raise_for_status()
            win_res = win_resp.json().get("result") or {}
            if not win_res.get("allow", False):
                return False, win_res.get("reason", "denied by scan window policy")

            return True, win_res.get("reason", "allowed")
