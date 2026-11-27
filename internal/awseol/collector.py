from datetime import datetime, timezone
import json
import logging
import time
from typing import Any

logger = logging.getLogger("eol_tracker.awseol")

# Curated AWS lifecycle reference dates used to flag approaching or past EOL versions.
AWS_EOL_REFERENCE: dict[str, str] = {
    "lambda:python3.8": "2024-10-14",
    "lambda:nodejs18.x": "2025-09-01",
    "eks:1.28": "2025-06-24",
    "rds:postgres12": "2025-02-28",
}


class _FallbackClientError(Exception):
    def __init__(self, message: str = "aws client error", response: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.response = response or {}


def _load_boto3() -> tuple[Any, Any]:
    try:
        import boto3
        from botocore.exceptions import ClientError

        return boto3, ClientError
    except ImportError:
        return None, _FallbackClientError


def _is_throttled(exc: Any) -> bool:
    resp = getattr(exc, "response", {}) or {}
    code = resp.get("Error", {}).get("Code", "")
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
    return code in {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
    } or status in {429, 502, 503, 504}


def _call_with_backoff(op_name: str, fn: Any, client_error_cls: Any, max_attempts: int = 4) -> Any:
    delay = 0.1
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except client_error_cls as exc:
            if not _is_throttled(exc) or attempt == max_attempts:
                raise
            # Cap per-retry sleep at 2.0s so webhook callers do not time out during API rate bursts.
            sleep_for = min(delay, 2.0)
            logger.warning("retrying aws call op=%s attempt=%d sleep_s=%.2f err=%s", op_name, attempt, sleep_for, exc)
            time.sleep(sleep_for)
            delay *= 2.0


class AWSEOLCollector:
    def __init__(
        self,
        region: str = "us-east-1",
        endpoint_url: str | None = "http://localhost:4566",
        bucket: str = "aws-eol-tracker-reports",
        ssm_client: Any | None = None,
        s3_client: Any | None = None,
        client_error_cls: Any | None = None,
    ) -> None:
        self.region = region
        self.bucket = bucket
        boto3_mod, default_err = _load_boto3()
        self._client_error = client_error_cls or default_err

        client_kwargs: dict[str, Any] = {"region_name": region}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
            client_kwargs["aws_access_key_id"] = "test"
            client_kwargs["aws_secret_access_key"] = "test"

        if ssm_client is not None:
            self.ssm = ssm_client
        else:
            if boto3_mod is None:
                raise RuntimeError("boto3 is required when ssm_client is not provided")
            self.ssm = boto3_mod.client("ssm", **client_kwargs)

        if s3_client is not None:
            self.s3 = s3_client
        else:
            if boto3_mod is None:
                raise RuntimeError("boto3 is required when s3_client is not provided")
            self.s3 = boto3_mod.client("s3", **client_kwargs)

    def _ensure_bucket(self) -> None:
        try:
            self.s3.head_bucket(Bucket=self.bucket)
        except self._client_error:
            try:
                self.s3.create_bucket(Bucket=self.bucket)
            except self._client_error as exc:
                code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "")
                if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                    raise

    def collect_and_store(self, correlation_id: str, grace_minutes: int) -> dict[str, Any]:
        self._ensure_bucket()

        params_resp = _call_with_backoff(
            "ssm:get_parameters_by_path",
            lambda: self.ssm.get_parameters_by_path(Path="/eol/tracked/", Recursive=True),
            self._client_error,
        )

        findings: list[dict[str, Any]] = []
        for p in params_resp.get("Parameters", []):
            name = p.get("Name", "")
            raw_val = p.get("Value", "")
            runtime_key = raw_val.strip()
            eol_date = AWS_EOL_REFERENCE.get(runtime_key, "untracked")
            status = (
                "expired"
                if eol_date != "untracked" and eol_date < datetime.now(timezone.utc).strftime("%Y-%m-%d")
                else "monitored"
            )
            findings.append({
                "parameter": name,
                "runtime": runtime_key,
                "eol_date": eol_date,
                "status": status,
            })

        now_iso = datetime.now(timezone.utc).isoformat()
        report = {
            "correlation_id": correlation_id,
            "collected_at_utc": now_iso,
            "region": self.region,
            "grace_extension_minutes": grace_minutes,
            "findings_count": len(findings),
            "findings": findings,
        }

        key = f"reports/{datetime.now(timezone.utc).strftime('%Y-%m-%d')}/{correlation_id}.json"
        body_bytes = json.dumps(report, indent=2).encode("utf-8")
        _call_with_backoff(
            "s3:put_object",
            lambda: self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body_bytes,
                ContentType="application/json",
            ),
            self._client_error,
        )

        return {
            "s3_bucket": self.bucket,
            "s3_key": key,
            "report": report,
        }
