# Design Notes: AWS Cloud Service Deprecation and End-of-Life Tracker

This service checks AWS runtime and version entries stored in SSM Parameter Store (`/eol/tracked/`) against known AWS end-of-life dates, enforces residency and UTC scan window rules in Open Policy Agent (OPA), and writes JSON reports to S3.

## Sequence and Error Handling

```mermaid
sequenceDiagram
    autonumber
    participant Caller as Caller
    participant API as Python FastAPI :8080
    participant OPA as OPA :8181
    participant AWS as LocalStack :4566

    Caller->>API: POST /v1/eol/scan (X-Timestamp, X-Signature-256)
    API->>API: verify_request (HMAC-SHA256 + UTC timestamp skew)
    alt Missing header, stale timestamp, or bad signature
        API-->>Caller: 401 Unauthorized
    else Signature valid
        API->>OPA: POST /v1/data/eol/sovereignty and /v1/data/eol/window
        alt OPA unreachable or non-200
            API-->>Caller: 502 Bad Gateway
        else Residency or UTC window denied
            API-->>Caller: 403 Forbidden
        else Policy allowed
            API->>AWS: ssm:get_parameters_by_path (/eol/tracked/)
            Note over API,AWS: Retry up to 4 times with backoff (0.1s..2.0s) on throttling or 503
            API->>AWS: s3:put_object (EOL report JSON)
            API-->>Caller: 200 OK
        end
    end
```

## Scan Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> Received
    Received --> RejectedAuth: Bad HMAC or timestamp skew > 300s
    Received --> CheckingPolicy: Signature verified
    CheckingPolicy --> Denied: Residency or UTC window policy rejected
    CheckingPolicy --> CollectingAWS: Policy allowed
    CollectingAWS --> RetryingAWS: Throttling or HTTP 503
    RetryingAWS --> CollectingAWS: Backoff elapsed (attempt < 4)
    RetryingAWS --> Failed: AWS or S3 error after retries
    CollectingAWS --> Stored: Report written to S3
    RejectedAuth --> [*]
    Denied --> [*]
    Failed --> [*]
    Stored --> [*]
```

## Edge Cases and Limitations

Timestamp verification and scan hours use UTC (`time.time()` and `datetime.now(timezone.utc)`) so Daylight Saving Time changes do not alter window enforcement. When `grace_extension.enabled` is true with `extra_minutes` up to 15 and a reference ID of at least 5 characters, off-window scans are allowed for `platform-ops` or `compliance-lead`. AWS API calls retry throttling and HTTP `429`/`502`/`503`/`504` responses with per-step sleep capped at `2.0s`.

Current limitations: `AWS_EOL_REFERENCE` in `internal/awseol/collector.py` holds a static dictionary of sample runtimes rather than fetching live AWS service lifecycle feeds, and `get_parameters_by_path` reads the first page of parameters without `NextToken` pagination.
