import tempfile
import unittest
from pathlib import Path

from thresholdsafe.errors import ThresholdSafeError
from thresholdsafe.service import ThresholdSafe

HOLDERS = ["alice", "bob", "carol", "dave", "erin"]
SECRET = "demo-root-key-do-not-store"


def create_body(**overrides):
    body = {
        "id": "prod-db-root",
        "name": "Production database root key",
        "threshold": 3,
        "holders": list(HOLDERS),
        "approvals_required": 2,
        "secret": SECRET,
    }
    body.update(overrides)
    return body


class ThresholdSafeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "thresholdsafe.db")
        self.service = ThresholdSafe(self.database)

    def tearDown(self):
        self.directory.cleanup()

    def create(self, key="create-1", **overrides):
        return self.service.create_secret(create_body(**overrides), key)

    def distribute(self, holders=HOLDERS, key_prefix="share"):
        return {
            holder: self.service.distribute_share(
                "prod-db-root", {"holder": holder}, f"{key_prefix}-{holder}"
            )["share"]
            for holder in holders
        }

    def approve(self, approvers, key_prefix="approval"):
        return [
            self.service.record_approval("prod-db-root", {"approver": approver}, f"{key_prefix}-{approver}")
            for approver in approvers
        ]

    @staticmethod
    def claims(issued, holders):
        return [{"share_id": issued[h]["share_id"], "value": issued[h]["value"]} for h in holders]

    def reconstruct(self, issued, holders, key):
        return self.service.reconstruct("prod-db-root", {"shares": self.claims(issued, holders)}, key)

    def assert_code(self, code, function, *args):
        with self.assertRaises(ThresholdSafeError) as captured:
            function(*args)
        self.assertEqual(code, captured.exception.code)
        return captured.exception

    # ------------------------------------------------------------------ creation
    def test_creation_registers_holders_and_issues_undistributed_shares(self):
        record = self.create()
        self.assertEqual(1, record["version"])
        self.assertEqual(3, record["threshold"])
        self.assertEqual(HOLDERS, record["holders"])
        self.assertEqual(5, record["share_count"])
        self.assertEqual(0, record["distributed_shares"])
        self.assertEqual({"recorded": 0, "required": 2, "satisfied": False}, record["approvals"])
        self.assertEqual(record, self.service.get_secret("prod-db-root"))

    def test_distribution_returns_one_share_per_holder(self):
        self.create()
        response = self.service.distribute_share("prod-db-root", {"holder": "alice"}, "share-alice")
        self.assertEqual("prod-db-root", response["secret_id"])
        self.assertEqual(1, response["version"])
        self.assertEqual(3, response["threshold"])
        self.assertEqual("prod-db-root.v1.alice", response["share"]["share_id"])
        self.assertEqual("alice", response["share"]["holder"])
        self.assertEqual(132, len(response["share"]["value"]))
        self.assertEqual(1, self.service.get_secret("prod-db-root")["distributed_shares"])

    def test_distribution_is_idempotent_and_single_use(self):
        self.create()
        first = self.service.distribute_share("prod-db-root", {"holder": "alice"}, "same-key")
        self.assertEqual(first, self.service.distribute_share("prod-db-root", {"holder": "alice"}, "same-key"))
        self.assert_code(
            "share_already_distributed", self.service.distribute_share, "prod-db-root", {"holder": "alice"}, "other"
        )
        self.assert_code(
            "validation_error", self.service.distribute_share, "prod-db-root", {"holder": "mallory"}, "third"
        )

    # ------------------------------------------------------------- reconstruction
    def test_reconstruction_with_threshold_shares_and_two_approvals(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        result = self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-1")
        self.assertEqual(SECRET, result["secret"])
        self.assertEqual(3, result["threshold"])
        self.assertEqual(["prod-db-root.v1.alice", "prod-db-root.v1.bob", "prod-db-root.v1.carol"], result["used_shares"])
        self.assertEqual(["alice", "bob", "carol"], result["holders"])

    def test_reconstruction_rejects_fewer_than_threshold_shares(self):
        self.create()
        issued = self.distribute(["alice", "bob"])
        self.approve(["alice", "bob"])
        error = self.assert_code(
            "insufficient_shares", self.reconstruct, issued, ["alice", "bob"], "reconstruct-1"
        )
        self.assertIn("requires 3 shares", str(error))
        self.assertEqual(2, self.service.get_secret("prod-db-root")["approvals"]["recorded"])

    def test_reconstruction_is_order_independent_and_uses_extra_shares(self):
        self.create()
        issued = self.distribute()
        self.approve(["alice", "bob"])
        result = self.reconstruct(issued, ["erin", "carol", "alice", "dave"], "reconstruct-1")
        self.assertEqual(SECRET, result["secret"])
        self.assertEqual(
            ["prod-db-root.v1.alice", "prod-db-root.v1.carol", "prod-db-root.v1.dave", "prod-db-root.v1.erin"],
            result["used_shares"],
        )

    def test_reconstruction_requires_the_approval_policy(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice"])
        self.assert_code("insufficient_approvals", self.reconstruct, issued, ["alice", "bob", "carol"], "again-1")
        self.approve(["bob"], key_prefix="second")
        result = self.reconstruct(issued, ["alice", "bob", "carol"], "again-2")
        self.assertEqual(SECRET, result["secret"])

    def test_successful_reconstruction_consumes_approvals(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-1")
        self.assertEqual(0, self.service.get_secret("prod-db-root")["approvals"]["recorded"])
        self.assert_code(
            "insufficient_approvals", self.reconstruct, issued, ["alice", "bob", "carol"], "reconstruct-2"
        )
        self.approve(["alice", "carol"], key_prefix="again")
        self.assertEqual(SECRET, self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-3")["secret"])

    def test_undistributed_share_cannot_be_used(self):
        self.create()
        issued = self.distribute(["alice", "bob"])
        self.approve(["alice", "bob"])
        claims = self.claims(issued, ["alice", "bob"])
        claims.append({"share_id": "prod-db-root.v1.carol", "value": "00" * 66})
        self.assert_code(
            "share_not_distributed", self.service.reconstruct, "prod-db-root", {"shares": claims}, "k"
        )

    def test_tampered_share_value_is_rejected(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        claims = self.claims(issued, ["alice", "bob", "carol"])
        claims[1]["value"] = ("0" * 131) + "1"
        self.assert_code("share_mismatch", self.service.reconstruct, "prod-db-root", {"shares": claims}, "k")

    def test_share_lookup_happens_before_the_threshold_count(self):
        self.create()
        self.approve(["alice", "bob"])
        unknown = {"shares": [{"share_id": "prod-db-root.v1.nobody", "value": "00" * 66}]}
        self.assert_code("not_found", self.service.reconstruct, "prod-db-root", unknown, "k1")
        issued = self.distribute(["alice"])
        self.service.create_secret(create_body(id="other-root", secret="other-value"), "create-2")
        self.service.record_approval("other-root", {"approver": "alice"}, "other-root-approval")
        foreign = {"shares": self.claims(issued, ["alice"])}
        self.assert_code("not_found", self.service.reconstruct, "other-root", foreign, "k2")

    def test_reconstruction_body_validation(self):
        self.create()
        issued = self.distribute(["alice"])
        claims = self.claims(issued, ["alice"])
        service = self.service.reconstruct
        self.assert_code("validation_error", service, "prod-db-root", {"shares": []}, "k1")
        self.assert_code("validation_error", service, "prod-db-root", {"shares": claims + claims}, "k2")
        self.assert_code(
            "validation_error",
            service,
            "prod-db-root",
            {"shares": [{"share_id": claims[0]["share_id"], "value": "NOT-HEX"}]},
            "k3",
        )
        self.assert_code("validation_error", service, "prod-db-root", {"shares": claims, "why": "x"}, "k4")

    # ------------------------------------------------------------------ approvals
    def test_approvals_are_holder_scoped_and_single_shot(self):
        self.create()
        record_approval = self.service.record_approval
        self.assert_code("validation_error", record_approval, "prod-db-root", {"approver": "mallory"}, "k1")
        self.assert_code("validation_error", record_approval, "prod-db-root", {"approver": "alice", "ticket": "1"}, "k2")
        first = self.approve(["alice"], key_prefix="pair")[0]
        self.assertEqual((1, 2, False), (first["approvals"], first["required"], first["satisfied"]))
        self.assert_code("duplicate_approval", record_approval, "prod-db-root", {"approver": "alice"}, "k3")
        self.assertTrue(self.approve(["bob"], key_prefix="pair")[0]["satisfied"])

    # -------------------------------------------------------------------- rotation
    def test_rotation_requires_approvals(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.assert_code("insufficient_approvals", self.service.rotate, "prod-db-root", {}, "rotate-1")
        self.approve(["alice"])
        self.assert_code("insufficient_approvals", self.service.rotate, "prod-db-root", {}, "rotate-2")
        self.approve(["bob"], key_prefix="second")
        record = self.service.rotate("prod-db-root", {}, "rotate-3")
        self.assertEqual((2, 0, 5), (record["version"], record["distributed_shares"], record["share_count"]))
        self.assertEqual(record, self.service.get_secret("prod-db-root"))
        self.assert_code("stale_share", self.reconstruct, issued, ["alice"], "reconstruct-1")

    def test_rotation_invalidates_old_shares(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.service.rotate("prod-db-root", {}, "rotate-1")
        stale = self.assert_code("stale_share", self.reconstruct, issued, ["alice"], "reconstruct-1")
        self.assertIn("version 1", str(stale))
        fresh = {"shares": [{"share_id": "prod-db-root.v2.alice", "value": "00" * 66}]}
        self.assert_code("share_not_distributed", self.service.reconstruct, "prod-db-root", fresh, "reconstruct-2")

    def test_rotation_reissues_the_same_secret_and_needs_fresh_approvals(self):
        self.create()
        self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.service.rotate("prod-db-root", {}, "rotate-1")
        self.approve(["alice"], key_prefix="v2")
        issued = self.distribute(["alice", "bob", "carol"], key_prefix="v2-share")
        self.assert_code("insufficient_approvals", self.reconstruct, issued, ["alice", "bob", "carol"], "reconstruct-1")
        self.approve(["bob"], key_prefix="v2-second")
        result = self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-2")
        self.assertEqual((SECRET, 2), (result["secret"], result["version"]))

    def test_rotation_can_change_policy_roster_and_secret(self):
        self.create()
        self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.assert_code(
            "validation_error",
            self.service.rotate,
            "prod-db-root",
            {"threshold": 4, "holders": ["frank", "grace", "heidi"]},
            "rotate-invalid",
        )
        record = self.service.rotate(
            "prod-db-root",
            {"secret": "rotated-root-key", "threshold": 2, "holders": ["frank", "grace", "heidi"], "approvals_required": 2},
            "rotate-1",
        )
        self.assertEqual((2, 2, ["frank", "grace", "heidi"]), (record["version"], record["threshold"], record["holders"]))
        self.assertEqual(0, record["approvals"]["recorded"])
        self.assert_code("insufficient_approvals", self.service.rotate, "prod-db-root", {}, "rotate-2")
        self.approve(["frank", "heidi"], key_prefix="v2")
        issued = self.distribute(["grace", "heidi"], key_prefix="v2-share")
        result = self.reconstruct(issued, ["grace", "heidi"], "reconstruct-1")
        self.assertEqual("rotated-root-key", result["secret"])

    def test_rotation_request_validation(self):
        self.create()
        self.assert_code("validation_error", self.service.rotate, "prod-db-root", {"reason": "x"}, "rotate-1")
        self.assert_code("validation_error", self.service.rotate, "prod-db-root", {"threshold": 1}, "rotate-2")

    # ----------------------------------------------------------------------- audit
    def test_audit_stream_is_hash_linked_and_ordered(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-1")
        run = self.service.audit("prod-db-root")
        self.assertTrue(run["chain_valid"])
        self.assertEqual(1, run["version"])
        self.assertEqual(
            [
                "secret_created",
                "share_distributed",
                "share_distributed",
                "share_distributed",
                "approval_recorded",
                "approval_recorded",
                "approvals_consumed",
                "secret_reconstructed",
            ],
            [event["type"] for event in run["events"]],
        )
        self.assertEqual([1, 2, 3, 4, 5, 6, 7, 8], [event["sequence"] for event in run["events"]])
        self.assertEqual("0" * 64, run["events"][0]["previous_hash"])
        self.assertEqual(run["head_hash"], run["events"][-1]["hash"])
        for previous, event in zip(run["events"], run["events"][1:]):
            self.assertEqual(previous["hash"], event["previous_hash"])

    def test_failed_reconstruction_is_audited_without_consuming_approvals(self):
        self.create()
        issued = self.distribute(["alice", "bob"])
        self.approve(["alice", "bob"])
        self.assert_code("insufficient_shares", self.reconstruct, issued, ["alice", "bob"], "reconstruct-1")
        run = self.service.audit("prod-db-root")
        failure = run["events"][-1]
        self.assertEqual("reconstruction_failed", failure["type"])
        self.assertEqual(("insufficient_shares", 2), (failure["payload"]["code"], failure["payload"]["shares_provided"]))
        self.assertTrue(run["chain_valid"])
        self.assertEqual(2, self.service.get_secret("prod-db-root")["approvals"]["recorded"])
        self.assert_code("validation_error", self.service.reconstruct, "prod-db-root", {"shares": []}, "reconstruct-2")
        self.assertEqual(len(run["events"]), len(self.service.audit("prod-db-root")["events"]))

    def test_audit_chain_detects_a_tampered_event(self):
        self.create()
        self.assertTrue(self.service.audit("prod-db-root")["chain_valid"])
        self.service.store.connection.execute(
            "UPDATE audit_events SET payload = ? WHERE secret_id = ? AND sequence = 1",
            ('{"version":1,"tampered":true}', "prod-db-root"),
        )
        self.assertFalse(self.service.audit("prod-db-root")["chain_valid"])

    # ------------------------------------------------------------------- storage
    def test_plaintext_secret_is_never_persisted(self):
        secret = "plaintext-must-never-be-stored"
        self.create(secret=secret)
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        blob = b"".join(
            Path(self.database + suffix).read_bytes()
            for suffix in ("", "-wal", "-shm")
            if Path(self.database + suffix).exists()
        )
        self.assertNotIn(secret.encode(), blob)
        self.assertEqual(secret, self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-1")["secret"])

    def test_issuance_is_reproducible_for_an_explicit_seed(self):
        services = [ThresholdSafe(str(Path(self.directory.name) / f"seed-{index}.db")) for index in range(3)]
        for index, seed in enumerate((7, 7, 8)):
            services[index].create_secret(create_body(seed=seed), "create-1")
        issued = [
            [
                service.distribute_share("prod-db-root", {"holder": holder}, f"{index}-{holder}")["share"]["value"]
                for holder in HOLDERS
            ]
            for index, service in enumerate(services)
        ]
        self.assertEqual(issued[0], issued[1])
        self.assertNotEqual(issued[0][0], issued[2][0])

    # -------------------------------------------------------------- request shapes
    def test_creation_validation(self):
        cases = [
            ({"threshold": 1}, "greater than or equal to 2"),
            ({"threshold": 6}, "must not exceed"),
            ({"threshold": True}, "greater than or equal to 2"),
            ({"approvals_required": 0}, "greater than or equal to 1"),
            ({"approvals_required": 6}, "must not exceed"),
            ({"holders": []}, "non-empty array"),
            ({"holders": ["alice", "alice"]}, "must not repeat"),
            ({"holders": ["alice smith"]}, "must start with a letter or digit"),
            ({"id": "prod db root"}, "must start with a letter or digit"),
            ({"secret": ""}, "non-empty string"),
            ({"secret": "x" * 65}, "at most 64 bytes"),
            ({"name": "  "}, "non-empty string"),
        ]
        for index, (overrides, message) in enumerate(cases):
            with self.assertRaisesRegex(ThresholdSafeError, message):
                self.service.create_secret(create_body(**overrides), f"case-{index}")
        self.assert_code("validation_error", self.service.create_secret, create_body(owner="ops"), "unknown")
        self.assert_code("validation_error", self.service.create_secret, {"id": "only-an-id"}, "missing")
        self.service.create_secret(create_body(), "create-ok")
        self.assert_code("conflict", self.service.create_secret, create_body(), "create-again")
        self.assert_code("conflict", self.service.create_secret, create_body(id="other"), "create-ok")

    def test_mutating_requests_require_an_idempotency_key(self):
        self.create()
        self.assert_code("validation_error", self.service.distribute_share, "prod-db-root", {"holder": "alice"}, None)
        self.assert_code("validation_error", self.service.record_approval, "prod-db-root", {"approver": "alice"}, None)
        self.assert_code("validation_error", self.service.reconstruct, "prod-db-root", {"shares": []}, None)
        self.assert_code("validation_error", self.service.rotate, "prod-db-root", {}, None)
        self.assert_code("validation_error", self.service.create_secret, create_body(id="another"), None)

    def test_unknown_secret_is_not_found(self):
        claim = {"shares": [{"share_id": "prod-db-root.v1.alice", "value": "00" * 66}]}
        self.assert_code("not_found", self.service.get_secret, "missing")
        self.assert_code("not_found", self.service.audit, "missing")
        self.assert_code("not_found", self.service.distribute_share, "missing", {"holder": "alice"}, "k1")
        self.assert_code("not_found", self.service.reconstruct, "missing", claim, "k2")
        self.assert_code("not_found", self.service.rotate, "missing", {}, "k3")
        self.assert_code("not_found", self.service.record_approval, "missing", {"approver": "alice"}, "k4")


if __name__ == "__main__":
    unittest.main()
