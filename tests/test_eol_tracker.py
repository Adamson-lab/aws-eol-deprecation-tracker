import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from internal.awseol.collector import AWSEOLCollector
from internal.webhook.auth import compute_signature, verify_request


class TestEOLTracker(unittest.TestCase):
    def test_hmac_verification_and_replay_window(self) -> None:
        secret = "test-secret"
        body = b'{"residency":"fedramp-high","region":"us-east-1"}'
        now = 1764267000
        sig = compute_signature(secret, now, body)

        ok, _ = verify_request(secret, sig, str(now), body, now_utc_unix=now)
        self.assertTrue(ok)

        bad_ok, bad_reason = verify_request(secret, "sha256=deadbeef", str(now), body, now_utc_unix=now)
        self.assertFalse(bad_ok)
        self.assertEqual(bad_reason, "invalid hmac signature")

        stale_ts = now - 400
        stale_sig = compute_signature(secret, stale_ts, body)
        stale_ok, stale_reason = verify_request(secret, stale_sig, str(stale_ts), body, now_utc_unix=now)
        self.assertFalse(stale_ok)
        self.assertEqual(stale_reason, "request timestamp outside replay window")

    def test_collector_flags_expired_runtime_and_writes_s3(self) -> None:
        fake_ssm = MagicMock()
        fake_ssm.get_parameters_by_path.return_value = {
            "Parameters": [
                {"Name": "/eol/tracked/payments-fn", "Value": "lambda:python3.8"},
                {"Name": "/eol/tracked/orders-eks", "Value": "eks:1.28"},
            ]
        }
        fake_s3 = MagicMock()

        col = AWSEOLCollector(
            region="us-east-1",
            endpoint_url=None,
            bucket="test-eol-bucket",
            ssm_client=fake_ssm,
            s3_client=fake_s3,
        )
        out = col.collect_and_store(correlation_id="corr-101", grace_minutes=15)

        self.assertEqual(out["s3_bucket"], "test-eol-bucket")
        self.assertEqual(out["report"]["findings_count"], 2)
        self.assertTrue(all(item["status"] == "expired" for item in out["report"]["findings"]))
        self.assertEqual(out["report"]["grace_extension_minutes"], 15)
        fake_s3.put_object.assert_called_once()
        written_json = json.loads(fake_s3.put_object.call_args.kwargs["Body"].decode("utf-8"))
        self.assertEqual(written_json["correlation_id"], "corr-101")

    def test_bench_signature_verification(self) -> None:
        secret = "bench-secret"
        body = b'{"role":"platform-ops","residency":"general","region":"us-east-1"}'
        now = int(time.time())
        sig = compute_signature(secret, now, body)

        iterations = 5000
        start = time.perf_counter()
        for _ in range(iterations):
            ok, _ = verify_request(secret, sig, str(now), body, now_utc_unix=now)
            self.assertTrue(ok)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        print(f"BENCH verify_request: {iterations} calls in {elapsed_ms:.2f} ms ({(elapsed_ms / iterations) * 1000:.2f} us/call)")


if __name__ == "__main__":
    unittest.main()
