from datetime import datetime, timezone
import json
import logging
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
import httpx

from internal.awseol.collector import AWSEOLCollector
from internal.policy.opa import OPAClient
from internal.webhook.auth import verify_request

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("eol_tracker.api")

app = FastAPI(title="aws-eol-deprecation-tracker", version="0.1.0")


def _build_services() -> tuple[str, OPAClient, AWSEOLCollector]:
    secret = os.getenv("WEBHOOK_HMAC_SECRET", "local-dev-eol-secret")
    opa_url = os.getenv("OPA_URL", "http://localhost:8181")
    aws_endpoint = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")
    region = os.getenv("AWS_REGION", "us-east-1")
    bucket = os.getenv("EOL_BUCKET", "aws-eol-tracker-reports")
    return secret, OPAClient(opa_url, timeout_seconds=3.0), AWSEOLCollector(region=region, endpoint_url=aws_endpoint, bucket=bucket)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    opa_url = os.getenv("OPA_URL", "http://localhost:8181")
    aws_endpoint = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")
    opa_ok = False
    ls_ok = False
    try:
        with httpx.Client(timeout=2.0) as client:
            opa_ok = client.get(f"{opa_url}/health").status_code == 200
            ls_ok = client.get(f"{aws_endpoint}/_localstack/health").status_code == 200
    except Exception:
        pass
    if not (opa_ok and ls_ok):
        raise HTTPException(status_code=503, detail={"status": "degraded", "opa": opa_ok, "localstack": ls_ok})
    return {"status": "ok", "opa": opa_ok, "localstack": ls_ok, "utc_time": datetime.now(timezone.utc).isoformat()}


@app.post("/v1/eol/scan")
async def scan_eol(
    request: Request,
    x_signature_256: str | None = Header(default=None, alias="X-Signature-256"),
    x_timestamp: str | None = Header(default=None, alias="X-Timestamp"),
    x_correlation_id: str | None = Header(default=None, alias="X-Correlation-ID"),
) -> dict[str, Any]:
    raw_body = await request.body()
    secret, opa_client, collector = _build_services()

    ok, reason = verify_request(secret, x_signature_256, x_timestamp, raw_body)
    if not ok:
        raise HTTPException(status_code=401, detail={"error": reason})

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "malformed json payload"})

    now_utc = datetime.now(timezone.utc)
    corr_id = x_correlation_id or payload.get("correlation_id") or f"eol-{int(now_utc.timestamp())}"
    grace_ext = payload.get("grace_extension") or {}
    grace_minutes = int(grace_ext.get("extra_minutes", 0)) if grace_ext.get("enabled") else 0

    opa_input = {
        "correlation_id": corr_id,
        "role": payload.get("role", "cron-runner"),
        "residency": payload.get("residency", "general"),
        "region": payload.get("region", os.getenv("AWS_REGION", "us-east-1")),
        "utc_hour": now_utc.hour,
        "grace_extension": grace_ext,
    }

    try:
        allowed, policy_reason = opa_client.evaluate(opa_input)
    except Exception as exc:
        logger.error("opa evaluation failed corr=%s err=%s", corr_id, exc)
        raise HTTPException(status_code=502, detail={"error": "opa policy engine unavailable"})

    if not allowed:
        raise HTTPException(status_code=403, detail={"correlation_id": corr_id, "status": "denied", "reason": policy_reason})

    try:
        result = collector.collect_and_store(correlation_id=corr_id, grace_minutes=grace_minutes)
    except Exception as exc:
        logger.error("aws eol collection failed corr=%s err=%s", corr_id, exc)
        raise HTTPException(status_code=502, detail={"error": f"aws collection failed: {exc}"})

    return {
        "correlation_id": corr_id,
        "status": "completed",
        "policy_reason": policy_reason,
        "result": result,
    }
