import base64
import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from thresholdsafe import receipts
from thresholdsafe.backup import encode as canonical_json
from thresholdsafe.errors import ThresholdSafeError
from thresholdsafe.service import ThresholdSafe

HOLDERS = ["alice", "bob", "carol"]
SECRET = "demo-root-key-do-not-store"


def create_body(**overrides):
    body = {
        "id": "prod-db-root",
        "name": "Production database root key",
        "threshold": 2,
        "holders": list(HOLDERS),
        "approvals_required": 2,
        "secret": SECRET,
    }
    body.update(overrides)
    return body


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "thresholdsafe.db")
        self.service = ThresholdSafe(self.database)
        self.service.create_secret(create_body(), "create-1")

    def tearDown(self):
        self.directory.cleanup()

    def issue(self, sequence=1, nonce="nonce-1", key="receipt-1", secret_id="prod-db-root"):
        return self.service.issue_audit_receipt(secret_id, {"sequence": sequence, "nonce": nonce}, key)

    def assert_code(self, code, function, *args):
        with self.assertRaises(ThresholdSafeError) as captured:
            function(*args)
        self.assertEqual(code, captured.exception.code)
        return captured.exception

    def event_count(self, event_type="audit_receipt_issued"):
        row = self.service.store.connection.execute(
            "SELECT COUNT(*) AS total FROM audit_events WHERE secret_id = ? AND type = ?",
            ("prod-db-root", event_type),
        ).fetchone()
        return row["total"]

    # ------------------------------------------------------------- receipt key
    def test_receipt_key_info_matches_raw_public_key_digest(self):
        info = self.service.receipt_key_info()
        self.assertEqual({"algorithm", "key_id", "public_key"}, set(info))
        self.assertEqual("Ed25519", info["algorithm"])
        public = b64url_decode(info["public_key"])
        self.assertEqual(32, len(public))
        self.assertEqual(hashlib.sha256(public).hexdigest(), info["key_id"])

    def test_receipt_key_is_shared_across_instances_and_stable(self):
        first = self.service.receipt_key_info()
        second = ThresholdSafe(self.database).receipt_key_info()
        self.assertEqual(first, second)
        self.assertEqual(first, self.service.receipt_key_info())

    def test_private_key_never_appears_in_responses_or_backups(self):
        receipt = self.issue()
        exposed = json.dumps(
            [self.service.receipt_key_info(), receipt, self.service.export_backup("prod-db-root")]
        )
        stored = self.service.store.connection.execute(
            "SELECT private_key FROM receipt_signing_key WHERE id = 1"
        ).fetchone()["private_key"]
        self.assertNotIn(stored, exposed)
        self.assertNotIn("private", exposed)

    # ---------------------------------------------------------------- issuance
    def test_issued_receipt_verifies_against_the_published_key(self):
        receipt = self.issue()
        self.assertEqual("Ed25519", receipt["algorithm"])
        self.assertEqual("prod-db-root", receipt["secret_id"])
        self.assertEqual("nonce-1", receipt["nonce"])
        self.assertEqual(1, receipt["event"]["sequence"])
        self.assertEqual("secret_created", receipt["event"]["type"])
        audit = self.service.audit("prod-db-root")
        self.assertEqual(2, receipt["head_sequence"])
        self.assertEqual(audit["head_hash"], receipt["head_hash"])
        self.assertEqual("audit_receipt_issued", audit["events"][-1]["type"])
        self.assertEqual(
            {"sequence": 1, "nonce": "nonce-1", "key_id": receipt["key_id"]},
            audit["events"][-1]["payload"],
        )
        unsigned = {key: value for key, value in receipt.items() if key != "signature"}
        Ed25519PublicKey.from_public_bytes(b64url_decode(self.service.receipt_key_info()["public_key"])).verify(
            b64url_decode(receipt["signature"]), canonical_json(unsigned).encode("utf-8")
        )

    def test_issuance_appends_exactly_one_event_and_keeps_chain_valid(self):
        self.issue()
        self.issue(sequence=2, nonce="nonce-2", key="receipt-2")
        audit = self.service.audit("prod-db-root")
        self.assertTrue(audit["chain_valid"])
        self.assertEqual(2, self.event_count())
        self.assertEqual(3, len(audit["events"]))

    def test_issuance_is_idempotent_under_the_same_key(self):
        first = self.issue()
        second = self.issue()
        self.assertEqual(first, second)
        self.assertEqual(1, self.event_count())

    def test_same_key_with_different_request_conflicts(self):
        self.issue()
        self.assert_code("conflict", self.issue, 1, "other-nonce")
        self.assert_code("conflict", self.issue, 2, "nonce-1", "receipt-1")
        self.assertEqual(1, self.event_count())

    def test_concurrent_issuance_with_one_key_matches_serial_replay(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.issue(), range(8)))
        first = results[0]
        for result in results:
            self.assertEqual(first, result)
        self.assertEqual(1, self.event_count())

    def test_frozen_secret_still_issues_receipts(self):
        self.service.freeze_secret("prod-db-root", {"reason": "incident"}, "freeze-1")
        receipt = self.issue(sequence=2)
        self.assertEqual("secret_frozen", receipt["event"]["type"])
        self.assertEqual(1, self.event_count())

    def test_issuance_requires_idempotency_key(self):
        self.assert_code("validation_error", self.service.issue_audit_receipt,
                         "prod-db-root", {"sequence": 1, "nonce": "n"}, None)

    def test_issuance_rejects_malformed_bodies(self):
        for body in (
            {},
            {"sequence": 1},
            {"nonce": "n"},
            {"sequence": 1, "nonce": "n", "extra": True},
            {"sequence": 0, "nonce": "n"},
            {"sequence": -1, "nonce": "n"},
            {"sequence": True, "nonce": "n"},
            {"sequence": "1", "nonce": "n"},
            {"sequence": 1, "nonce": ""},
            {"sequence": 1, "nonce": "x" * 129},
            {"sequence": 1, "nonce": "é" * 65},
            {"sequence": 1, "nonce": 42},
        ):
            self.assert_code("validation_error", self.service.issue_audit_receipt,
                             "prod-db-root", body, "key")
        self.assertEqual(0, self.event_count())

    def test_issuance_accepts_128_byte_nonce_verbatim(self):
        nonce = "é" * 64  # 128 UTF-8 bytes
        receipt = self.issue(nonce=nonce)
        self.assertEqual(nonce, receipt["nonce"])

    def test_missing_secret_or_event_is_not_found(self):
        self.assert_code("not_found", self.issue, 1, "n", "key", "no-such-secret")
        self.assert_code("not_found", self.issue, 99)
        self.assertEqual(0, self.event_count())

    def test_broken_chain_rejects_issuance_with_audit_integrity(self):
        self.service.store.connection.execute(
            "UPDATE audit_events SET payload = ? WHERE secret_id = ? AND sequence = 1",
            (json.dumps({"tampered": True}), "prod-db-root"),
        )
        self.assertFalse(self.service.audit("prod-db-root")["chain_valid"])
        self.assert_code("audit_integrity", self.issue)
        self.assertEqual(0, self.event_count())

    # -------------------------------------------------------------- verification
    def verify(self, receipt, public_key=None):
        if public_key is None:
            public_key = self.service.receipt_key_info()["public_key"]
        return self.service.verify_receipt({"receipt": receipt, "public_key": public_key})

    def test_verify_accepts_a_fresh_receipt(self):
        self.assertEqual({"valid": True}, self.verify(self.issue()))

    def test_verify_detects_tampered_content_as_receipt_integrity(self):
        receipt = self.issue()
        tampered = dict(receipt, event=dict(receipt["event"], hash="0" * 64))
        self.assertEqual({"valid": False, "reason": "receipt_integrity"}, self.verify(tampered))
        tampered = dict(receipt, event=dict(receipt["event"], payload={"tampered": True}))
        self.assertEqual({"valid": False, "reason": "receipt_integrity"}, self.verify(tampered))

    def test_verify_detects_a_key_id_mismatch_as_receipt_integrity(self):
        receipt = self.issue()
        other = ThresholdSafe(str(Path(self.directory.name) / "other.db")).receipt_key_info()
        self.assertEqual(
            {"valid": False, "reason": "receipt_integrity"},
            self.verify(receipt, other["public_key"]),
        )

    def test_verify_detects_a_wrong_signature_as_signature_mismatch(self):
        receipt = self.issue()
        other = ThresholdSafe(str(Path(self.directory.name) / "other.db"))
        other.create_secret(create_body(), "create-1")
        signed_elsewhere = other.issue_audit_receipt("prod-db-root", {"sequence": 1, "nonce": "n"}, "k")
        swapped = dict(receipt, signature=signed_elsewhere["signature"])
        self.assertEqual({"valid": False, "reason": "signature_mismatch"}, self.verify(swapped))
        tampered = dict(receipt, nonce="other-nonce")
        self.assertEqual({"valid": False, "reason": "signature_mismatch"}, self.verify(tampered))

    def test_verify_rejects_malformed_bodies(self):
        receipt = self.issue()
        key = self.service.receipt_key_info()["public_key"]
        bad_bodies = [
            {},
            {"receipt": receipt},
            {"public_key": key},
            {"receipt": receipt, "public_key": key, "extra": 1},
            {"receipt": None, "public_key": key},
            {"receipt": dict(receipt, algorithm="RSA"), "public_key": key},
            {"receipt": dict(receipt, key_id="zz" * 32), "public_key": key},
            {"receipt": {k: v for k, v in receipt.items() if k != "nonce"}, "public_key": key},
            {"receipt": dict(receipt, nonce=""), "public_key": key},
            {"receipt": dict(receipt, head_sequence=0), "public_key": key},
            {"receipt": dict(receipt, signature="!!!"), "public_key": key},
            {"receipt": dict(receipt, signature="AQID"), "public_key": key},
            {"receipt": receipt, "public_key": "not base64!!"},
            {"receipt": receipt, "public_key": "AQID"},
        ]
        for body in bad_bodies:
            self.assert_code("validation_error", self.service.verify_receipt, body)

    def test_verify_writes_nothing(self):
        receipt = self.issue()
        before = self.service.audit("prod-db-root")
        self.verify(receipt)
        self.assertEqual(before, self.service.audit("prod-db-root"))


if __name__ == "__main__":
    unittest.main()
