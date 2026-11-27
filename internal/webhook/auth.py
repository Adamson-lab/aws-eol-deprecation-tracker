import hashlib
import hmac
import time


def compute_signature(secret: str, timestamp_unix: int, body: bytes) -> str:
    msg = f"{timestamp_unix}.".encode("utf-8") + body
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_request(
    secret: str,
    signature_header: str | None,
    timestamp_header: str | None,
    body: bytes,
    max_skew_seconds: int = 300,
    now_utc_unix: int | None = None,
) -> tuple[bool, str]:
    if not signature_header or not timestamp_header:
        return False, "missing X-Signature-256 or X-Timestamp header"

    try:
        ts = int(timestamp_header.strip())
    except ValueError:
        return False, "invalid X-Timestamp header"

    # Compare strictly against UTC unix epoch so Daylight Saving Time changes never skew replay checks.
    current = int(time.time()) if now_utc_unix is None else now_utc_unix
    if abs(current - ts) > max_skew_seconds:
        return False, "request timestamp outside replay window"

    expected = compute_signature(secret, ts, body)
    if not hmac.compare_digest(expected, signature_header.strip()):
        return False, "invalid hmac signature"

    return True, "ok"
