import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from thresholdsafe.errors import SecretFrozen, SecretNotFrozen, ThresholdSafeError
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

    def freeze(self, reason="security incident under investigation", key="freeze-1"):
        return self.service.freeze_secret("prod-db-root", {"reason": reason}, key)

    def unfreeze(self, reason="incident resolved", key="unfreeze-1"):
        return self.service.unfreeze_secret("prod-db-root", {"reason": reason}, key)

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

    # ---------------------------------------------------------- freeze lifecycle
    def test_new_secret_starts_active_without_a_reason(self):
        record = self.create()
        self.assertEqual("active", record["status"])
        self.assertIsNone(record["status_reason"])
        self.assertEqual(record["created_at"], record["status_changed_at"])
        self.assertEqual(record, self.service.get_secret("prod-db-root"))

    def test_freeze_sets_status_reason_and_timestamp(self):
        self.create()
        before = self.service.get_secret("prod-db-root")
        frozen = self.freeze()
        self.assertEqual("frozen", frozen["status"])
        self.assertEqual("security incident under investigation", frozen["status_reason"])
        self.assertNotEqual(before["status_changed_at"], frozen["status_changed_at"])
        self.assertEqual(frozen, self.service.get_secret("prod-db-root"))
        # Custody fields are untouched by the transition.
        self.assertEqual(1, frozen["version"])
        self.assertEqual(3, frozen["threshold"])
        self.assertEqual(HOLDERS, frozen["holders"])
        self.assertEqual(5, frozen["share_count"])
        self.assertEqual(0, frozen["distributed_shares"])

    def test_unfreeze_returns_to_active(self):
        self.create()
        self.freeze()
        active = self.unfreeze()
        self.assertEqual("active", active["status"])
        self.assertEqual("incident resolved", active["status_reason"])
        self.assertEqual(active, self.service.get_secret("prod-db-root"))

    def test_freeze_is_idempotent_for_the_same_transition(self):
        self.create()
        first = self.freeze(key="same-key")
        self.assertEqual(first, self.service.freeze_secret("prod-db-root", {"reason": "later reason"}, "same-key"))
        self.assertEqual(
            "security incident under investigation",
            self.service.get_secret("prod-db-root")["status_reason"],
        )

    def test_unfreeze_is_idempotent_for_the_same_transition(self):
        self.create()
        self.freeze()
        first = self.unfreeze(key="same-key")
        self.assertEqual(first, self.service.unfreeze_secret("prod-db-root", {"reason": "later"}, "same-key"))

    def test_repeated_freeze_is_secret_frozen_and_repeated_unfreeze_is_secret_not_frozen(self):
        self.create()
        self.freeze(key="freeze-1")
        self.assert_code("secret_frozen", self.freeze, "different reason", "freeze-2")
        self.unfreeze(key="unfreeze-1")
        self.assert_code("secret_not_frozen", self.unfreeze, "again", "unfreeze-2")

    def test_reusing_a_key_for_the_opposite_transition_is_a_conflict(self):
        self.create()
        self.freeze(key="shared")
        self.assert_code("conflict", self.unfreeze, "resolved", "shared")

    def test_reusing_a_freeze_key_after_a_new_cycle_is_a_conflict(self):
        self.create()
        self.freeze(key="freeze-cycle")
        self.unfreeze(key="unfreeze-1")
        # The old key belongs to the first freeze cycle, not the second.
        self.assert_code("conflict", self.freeze, "second incident", "freeze-cycle")
        # A fresh key opens the second freeze cycle normally.
        second = self.freeze(key="freeze-2")
        self.assertEqual("frozen", second["status"])

    def test_freeze_reasons_are_trimmed_and_validated(self):
        self.create()
        record = self.service.freeze_secret("prod-db-root", {"reason": "  urgent incident  "}, "freeze-1")
        self.assertEqual("urgent incident", record["status_reason"])
        cases = [
            {},
            {"reason": "   "},
            {"reason": ""},
            {"reason": "x" * 201},
            {"reason": 12},
            {"reason": None},
            {"reason": "ok", "extra": 1},
            ["frozen"],
        ]
        for index, body in enumerate(cases):
            self.assert_code("validation_error", self.service.freeze_secret, "prod-db-root", body, f"f-{index}")
            self.assert_code("validation_error", self.service.unfreeze_secret, "prod-db-root", body, f"u-{index}")
        self.assertEqual("frozen", self.service.get_secret("prod-db-root")["status"])

    def test_a_200_character_reason_is_accepted(self):
        self.create()
        reason = "a" * 150 + " " + "b" * 49
        self.assertEqual(200, len(reason))
        record = self.freeze(reason=reason, key="freeze-1")
        self.assertEqual(reason, record["status_reason"])

    def test_freeze_and_unfreeze_require_an_idempotency_key(self):
        self.create()
        self.assert_code("validation_error", self.service.freeze_secret, "prod-db-root", {"reason": "x"}, None)
        self.freeze()
        self.assert_code("validation_error", self.service.unfreeze_secret, "prod-db-root", {"reason": "x"}, None)

    def test_freeze_and_unfreeze_unknown_secret_is_not_found(self):
        self.assert_code("not_found", self.service.freeze_secret, "missing", {"reason": "x"}, "k1")
        self.assert_code("not_found", self.service.unfreeze_secret, "missing", {"reason": "x"}, "k2")

    def test_frozen_blocks_the_four_write_endpoints_without_changing_state(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice"])
        self.freeze()

        claim = {"shares": self.claims(issued, ["alice", "bob", "carol"])}
        self.assert_code("secret_frozen", self.service.distribute_share,
                         "prod-db-root", {"holder": "dave"}, "share-dave")
        self.assert_code("secret_frozen", self.service.record_approval,
                         "prod-db-root", {"approver": "bob"}, "approval-bob")
        self.assert_code("secret_frozen", self.service.reconstruct, "prod-db-root", claim, "reconstruct-1")
        self.assert_code("secret_frozen", self.service.rotate, "prod-db-root", {}, "rotate-1")

        record = self.service.get_secret("prod-db-root")
        self.assertEqual("frozen", record["status"])
        self.assertEqual(1, record["version"])
        self.assertEqual(3, record["distributed_shares"])
        self.assertEqual(1, record["approvals"]["recorded"])

    def test_blocked_writes_do_not_consume_idempotency_keys(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.freeze()

        claim = {"shares": self.claims(issued, ["alice", "bob", "carol"])}
        self.assert_code("secret_frozen", self.service.reconstruct, "prod-db-root", claim, "shared")
        # While still frozen every retry with the same key is blocked afresh ...
        self.assert_code("secret_frozen", self.service.reconstruct, "prod-db-root", claim, "shared")
        self.unfreeze()
        # ... and after unfreezing the same key performs the operation instead
        # of replaying a stored response.
        result = self.service.reconstruct("prod-db-root", claim, "shared")
        self.assertEqual(SECRET, result["secret"])

    def test_blocked_writes_append_operation_blocked_events(self):
        self.create()
        issued = self.distribute(["alice", "bob"])
        self.freeze()
        self.assert_code("secret_frozen", self.service.distribute_share,
                         "prod-db-root", {"holder": "carol"}, "share-carol")
        self.assert_code("secret_frozen", self.service.record_approval,
                         "prod-db-root", {"approver": "alice"}, "approval-alice")
        self.assert_code(
            "secret_frozen",
            self.service.reconstruct,
            "prod-db-root",
            {"shares": self.claims(issued, ["alice", "bob"])},
            "reconstruct-1",
        )
        self.assert_code("secret_frozen", self.service.rotate, "prod-db-root", {}, "rotate-1")
        # Retrying a blocked request records another blocked event.
        self.assert_code("secret_frozen", self.service.rotate, "prod-db-root", {}, "rotate-2")

        run = self.service.audit("prod-db-root")
        self.assertTrue(run["chain_valid"])
        blocked = [event for event in run["events"] if event["type"] == "operation_blocked"]
        self.assertEqual(
            ["distribute_share", "record_approval", "reconstruct", "rotate", "rotate"],
            [event["payload"]["operation"] for event in blocked],
        )
        self.assertTrue(all(event["payload"]["code"] == "secret_frozen" for event in blocked))

    def test_successful_freeze_and_unfreeze_are_audited_with_the_version(self):
        self.create()
        self.freeze(reason="incident-42")
        self.unfreeze(reason="all-clear")
        run = self.service.audit("prod-db-root")
        self.assertTrue(run["chain_valid"])
        frozen_event, unfrozen_event = [
            event for event in run["events"] if event["type"] in {"secret_frozen", "secret_unfrozen"}
        ]
        self.assertEqual({"version": 1, "reason": "incident-42"}, frozen_event["payload"])
        self.assertEqual({"version": 1, "reason": "all-clear"}, unfrozen_event["payload"])

    def test_unfreeze_restores_existing_shares_and_approvals(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.freeze()
        self.unfreeze()
        result = self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-1")
        self.assertEqual(SECRET, result["secret"])

    def test_freeze_does_not_change_version_threshold_or_secret_commitment(self):
        self.create()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        before = self.service.get_secret("prod-db-root")
        self.freeze()
        self.unfreeze()
        after = self.service.get_secret("prod-db-root")
        self.assertEqual(before["version"], after["version"])
        self.assertEqual(before["threshold"], after["threshold"])
        self.assertEqual(before["holders"], after["holders"])
        self.assertEqual(before["secret_length"], after["secret_length"])
        self.assertEqual(before["share_count"], after["share_count"])
        self.assertEqual(before["distributed_shares"], after["distributed_shares"])
        self.assertEqual(before["approvals"], after["approvals"])
        result = self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-1")
        self.assertEqual(SECRET, result["secret"])

    def test_frozen_state_survives_across_service_instances(self):
        self.create()
        self.freeze()
        reopened = ThresholdSafe(self.database)
        self.assertEqual("frozen", reopened.get_secret("prod-db-root")["status"])
        self.assert_code(
            "secret_frozen", reopened.distribute_share, "prod-db-root", {"holder": "alice"}, "share-alice-2"
        )

    def test_concurrent_transitions_linearize_into_alternating_events(self):
        import threading

        self.create()
        errors: list[Exception] = []

        def cycle(index: int) -> None:
            attempt = [0]
            try:
                # Retry through cycles another thread won: only a 200 means
                # this thread performed the transition.
                while True:
                    try:
                        self.service.freeze_secret(
                            "prod-db-root", {"reason": f"freeze-{index}"}, f"f-{index}-{attempt[0]}"
                        )
                        break
                    except SecretFrozen:
                        attempt[0] += 1
                attempt[0] += 1
                while True:
                    try:
                        self.service.unfreeze_secret(
                            "prod-db-root", {"reason": f"unfreeze-{index}"}, f"u-{index}-{attempt[0]}"
                        )
                        break
                    except SecretNotFrozen:
                        attempt[0] += 1
            except Exception as error:  # pragma: no cover - surfaced below
                errors.append(error)

        threads = [threading.Thread(target=cycle, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([], errors)

        run = self.service.audit("prod-db-root")
        self.assertTrue(run["chain_valid"])
        transitions = [event["type"] for event in run["events"]
                       if event["type"] in {"secret_frozen", "secret_unfrozen"}]
        self.assertEqual(16, len(transitions))
        self.assertEqual(["secret_frozen", "secret_unfrozen"] * 8, transitions)
        self.assertEqual("active", self.service.get_secret("prod-db-root")["status"])

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

    # ---------------------------------------------------------------------- backup
    def test_backup_contains_everything_but_the_plaintext(self):
        self.create()
        issued = self.distribute(["alice", "bob"])
        self.approve(["alice", "bob"])
        backup = self.service.export_backup("prod-db-root")
        self.assertEqual(
            {"backup_version", "generated_at", "authorization_policy", "secret", "versions",
             "shares", "approvals", "audit_events", "checksum"},
            set(backup),
        )
        self.assertEqual("thresholdsafe-backup-v3", backup["backup_version"])
        self.assertIsNone(backup["authorization_policy"])
        self.assertTrue(backup["generated_at"].endswith("Z"))
        self.assertNotIn(SECRET, json.dumps(backup))
        secret = backup["secret"]
        self.assertEqual(len(SECRET.encode()), secret["secret_length"])
        self.assertRegex(secret["secret_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(5, len(backup["shares"]))
        for share in backup["shares"]:
            self.assertEqual(
                {"share_id", "secret_id", "version", "holder", "coordinate", "value",
                 "commitment", "distributed_at", "invalidated_at"},
                set(share),
            )
        states = {share["holder"]: share for share in backup["shares"]}
        self.assertIsNotNone(states["alice"]["distributed_at"])
        self.assertIsNone(states["carol"]["distributed_at"])
        self.assertIsNone(states["carol"]["invalidated_at"])
        self.assertEqual(2, len(backup["approvals"]))
        self.assertEqual(5, len(backup["audit_events"]))
        self.assertEqual(issued["alice"]["value"], states["alice"]["value"])

    def test_backup_checksum_ignores_field_order(self):
        self.create()
        backup = self.service.export_backup("prod-db-root")
        unsigned = {key: backup[key] for key in backup if key != "checksum"}
        encoded = json.dumps(unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        self.assertEqual(hashlib.sha256(encoded.encode()).hexdigest(), backup["checksum"])
        shuffled = dict(reversed(list(backup.items())))
        self.assertTrue(self.service.verify_backup({"backup": shuffled})["valid"])

    def test_verify_accepts_a_fresh_backup_and_reports_counts(self):
        self.create()
        self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        backup = self.service.export_backup("prod-db-root")
        result = self.service.verify_backup({"backup": backup})
        self.assertEqual(
            {"valid": True, "secret_id": "prod-db-root", "version": 1,
             "share_count": 5, "approval_count": 2, "event_count": 6},
            result,
        )

    def test_verify_accepts_a_backup_spanning_a_rotation(self):
        self.create()
        self.approve(["alice", "bob"])
        self.service.rotate("prod-db-root", {"threshold": 2}, "rotate-1")
        backup = self.service.export_backup("prod-db-root")
        self.assertEqual(10, len(backup["shares"]))
        result = self.service.verify_backup({"backup": backup})
        self.assertEqual(2, result["version"])
        self.assertEqual(10, result["share_count"])

    def test_frozen_secret_still_exports(self):
        self.create()
        self.freeze()
        backup = self.service.export_backup("prod-db-root")
        self.assertEqual("frozen", backup["secret"]["status"])
        self.assertTrue(self.service.verify_backup({"backup": backup})["valid"])

    def test_backup_of_unknown_secret_is_not_found(self):
        self.assert_code("not_found", self.service.export_backup, "missing")

    def test_verify_does_not_touch_service_state(self):
        self.create()
        backup = self.service.export_backup("prod-db-root")
        before = self.service.audit("prod-db-root")
        self.service.verify_backup({"backup": backup})
        self.assertEqual(before, self.service.audit("prod-db-root"))
        count = self.service.store.connection.execute("SELECT COUNT(*) AS n FROM idempotency").fetchone()
        self.assertEqual(1, count["n"])  # only the create key

    def test_verify_rejects_malformed_requests(self):
        self.create()
        backup = self.service.export_backup("prod-db-root")
        self.assert_code("validation_error", self.service.verify_backup, {})
        self.assert_code("validation_error", self.service.verify_backup, {"backup": backup, "extra": 1})
        self.assert_code("validation_error", self.service.verify_backup, {"backup": "not-an-object"})
        for mutate in (
            lambda b: b.pop("shares"),
            lambda b: b.pop("authorization_policy"),
            lambda b: b.pop("versions"),
            lambda b: b.update(unexpected=True),
            lambda b: b.update(backup_version="thresholdsafe-backup-v1"),
            lambda b: b.update(backup_version="thresholdsafe-backup-v4"),
            lambda b: b.update(authorization_policy={"all": []}),
            lambda b: b.update(generated_at=None),
            lambda b: b["secret"].update(version="1"),
            lambda b: b["secret"].pop("secret_digest"),
            lambda b: b["shares"][0].update(coordinate="1"),
            lambda b: b["approvals"].append({"secret_id": "prod-db-root"}),
            lambda b: b["audit_events"][0].update(sequence="1"),
            lambda b: b["versions"][0].update(approval_mode="broken"),
            lambda b: b["versions"][0].pop("approvers"),
        ):
            broken = copy.deepcopy(backup)
            mutate(broken)
            self.assert_code("validation_error", self.service.verify_backup, {"backup": broken})
        self.assertTrue(self.service.verify_backup({"backup": backup})["valid"])

    def test_verify_rejects_tampered_backups_as_backup_integrity(self):
        self.create()
        self.distribute(["alice"])
        self.approve(["alice", "bob"])
        backup = self.service.export_backup("prod-db-root")

        def restamp(broken):
            unsigned = {k: v for k, v in broken.items() if k != "checksum"}
            encoded = json.dumps(unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            broken["checksum"] = hashlib.sha256(encoded.encode()).hexdigest()
            return broken

        tampers = [
            lambda b: b["shares"][0].update(secret_id="other"),
            lambda b: b["shares"][0].update(share_id="prod-db-root.v1.mallory"),
            lambda b: b["shares"][0].update(value="ff" * 66),
            lambda b: b["shares"][0].update(commitment="0" * 64),
            lambda b: b["shares"][0].update(version=2),
            lambda b: b["approvals"][0].update(approver="mallory"),
            lambda b: b["approvals"][0].update(secret_id="other"),
            lambda b: b["audit_events"][1].update(sequence=5),
            lambda b: b["audit_events"][1].update(previous_hash="1" * 64),
            lambda b: b["audit_events"][1].update(hash="1" * 64),
            lambda b: b["audit_events"][0].update(payload={"tampered": True}),
        ]
        bad_checksum = copy.deepcopy(backup)
        bad_checksum["checksum"] = "0" * 64
        self.assert_code("backup_integrity", self.service.verify_backup, {"backup": bad_checksum})
        for tamper in tampers:
            broken = copy.deepcopy(backup)
            tamper(broken)
            # Re-stamp so the checksum is honest and the tamper itself is caught.
            self.assert_code("backup_integrity", self.service.verify_backup, {"backup": restamp(broken)})
        self.assertTrue(self.service.verify_backup({"backup": backup})["valid"])

    def test_verify_rejects_a_dropped_version_as_backup_integrity(self):
        self.create()
        self.approve(["alice", "bob"])
        self.service.rotate("prod-db-root", {}, "rotate-1")
        backup = self.service.export_backup("prod-db-root")
        broken = copy.deepcopy(backup)
        broken["shares"] = [share for share in broken["shares"] if share["version"] == 2]
        broken["checksum"] = hashlib.sha256(
            json.dumps({k: v for k, v in broken.items() if k != "checksum"},
                       ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        self.assert_code("backup_integrity", self.service.verify_backup, {"backup": broken})

    # ------------------------------------------------------------- authorization policy
    RECONSTRUCT_ONLY = {"fact": {"fact": "action", "op": "eq", "value": "reconstruct"}}
    EXTRA_SHARES = {"fact": {"fact": "presented_shares", "op": "gte", "value": 4}}

    def test_secret_without_a_policy_reports_null_and_behaves_as_before(self):
        self.create()
        self.assertEqual({"policy": None}, self.service.get_policy("prod-db-root"))
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.assertEqual(SECRET, self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-1")["secret"])

    def test_policy_is_set_at_creation_and_read_back(self):
        policy = {"all": [self.RECONSTRUCT_ONLY, self.EXTRA_SHARES]}
        self.create(policy=policy)
        self.assertEqual({"policy": policy}, self.service.get_policy("prod-db-root"))
        # The custody record itself is unchanged in shape.
        self.assertNotIn("policy", self.service.get_secret("prod-db-root"))

    def test_policy_read_is_allowed_while_frozen_and_writes_nothing(self):
        self.create(policy=self.RECONSTRUCT_ONLY)
        self.freeze()
        before = self.service.audit("prod-db-root")
        self.assertEqual({"policy": self.RECONSTRUCT_ONLY}, self.service.get_policy("prod-db-root"))
        self.assertEqual(before, self.service.audit("prod-db-root"))
        count = self.service.store.connection.execute("SELECT COUNT(*) AS n FROM idempotency").fetchone()
        self.assertEqual(2, count["n"])  # only the create and freeze keys

    def test_policy_of_unknown_secret_is_not_found(self):
        self.assert_code("not_found", self.service.get_policy, "missing")

    def test_policy_validation_rejects_bad_expressions(self):
        good = {"not": {"fact": {"fact": "action", "op": "ne", "value": "rotate"}}}
        cases = [
            "not-an-object",
            {},
            {"all": []},
            {"any": []},
            {"all": "not-a-list"},
            {"all": [good], "not": good},
            {"not": [good]},
            {"not": {"unknown": {}}},
            {"unknown": {}},
            {"fact": {"fact": "action", "op": "eq"}},
            {"fact": {"fact": "action", "op": "eq", "value": "reconstruct", "extra": 1}},
            {"fact": {"fact": "owner", "op": "eq", "value": 1}},
            {"fact": {"fact": "action", "op": "gte", "value": "reconstruct"}},
            {"fact": {"fact": "action", "op": "eq", "value": "distribute"}},
            {"fact": {"fact": "action", "op": "eq", "value": 1}},
            {"fact": {"fact": "version", "op": "gt", "value": 1}},
            {"fact": {"fact": "version", "op": "eq", "value": -1}},
            {"fact": {"fact": "version", "op": "eq", "value": True}},
            {"fact": {"fact": "version", "op": "eq", "value": "1"}},
            {"fact": {"fact": "presented_shares", "op": "lte", "value": 1.5}},
        ]
        for index, policy in enumerate(cases):
            self.assert_code(
                "validation_error", self.service.create_secret, create_body(id=f"p-{index}", policy=policy), f"c-{index}"
            )
        self.service.create_secret(create_body(policy=good), "create-ok")
        self.assertEqual({"policy": good}, self.service.get_policy("prod-db-root"))
        # Rotation validates a new policy the same way.
        self.assert_code("validation_error", self.service.rotate, "prod-db-root", {"policy": {"all": []}}, "r-bad")
        self.assert_code("validation_error", self.service.rotate, "prod-db-root", {"policy": 7}, "r-bad-2")

    def test_policy_denial_blocks_reconstruction_without_side_effects(self):
        self.create(policy={"all": [self.RECONSTRUCT_ONLY, self.EXTRA_SHARES]})
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        error = self.assert_code(
            "policy_denied", self.reconstruct, issued, ["alice", "bob", "carol"], "reconstruct-1"
        )
        self.assertEqual(409, error.status)
        # Approvals are not consumed and no idempotency response is stored.
        self.assertEqual(2, self.service.get_secret("prod-db-root")["approvals"]["recorded"])
        self.assert_code(
            "policy_denied", self.reconstruct, issued, ["alice", "bob", "carol"], "reconstruct-1"
        )
        run = self.service.audit("prod-db-root")
        self.assertTrue(run["chain_valid"])
        denied = [event for event in run["events"] if event["type"] == "authorization_denied"]
        self.assertEqual(2, len(denied))
        self.assertEqual(
            {"action": "reconstruct", "version": 1, "presented_shares": 3, "approvals": 2},
            denied[0]["payload"],
        )
        # Presenting a fourth share satisfies the policy with the same key.
        issued["dave"] = self.service.distribute_share("prod-db-root", {"holder": "dave"}, "share-dave")["share"]
        result = self.reconstruct(issued, ["alice", "bob", "carol", "dave"], "reconstruct-1")
        self.assertEqual(SECRET, result["secret"])
        self.assertEqual(0, self.service.get_secret("prod-db-root")["approvals"]["recorded"])

    def test_policy_facts_are_evaluated_with_pre_execution_values(self):
        policy = {
            "all": [
                {"fact": {"fact": "action", "op": "eq", "value": "reconstruct"}},
                {"fact": {"fact": "version", "op": "eq", "value": 1}},
                {"fact": {"fact": "threshold", "op": "eq", "value": 3}},
                {"fact": {"fact": "approvals", "op": "gte", "value": 2}},
                {"fact": {"fact": "presented_shares", "op": "lte", "value": 3}},
            ]
        }
        self.create(policy=policy)
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.assertEqual(SECRET, self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-1")["secret"])

    def test_rotation_policy_gate_uses_zero_presented_shares(self):
        policy = {"any": [
            {"fact": {"fact": "action", "op": "eq", "value": "reconstruct"}},
            {"fact": {"fact": "presented_shares", "op": "ne", "value": 0}},
        ]}
        self.create(policy=policy)
        self.approve(["alice", "bob"])
        error = self.assert_code("policy_denied", self.service.rotate, "prod-db-root", {}, "rotate-1")
        self.assertEqual(409, error.status)
        # Nothing moved: no consumption, no new version, no invalidation.
        record = self.service.get_secret("prod-db-root")
        self.assertEqual((1, 2), (record["version"], record["approvals"]["recorded"]))
        denied = [e for e in self.service.audit("prod-db-root")["events"] if e["type"] == "authorization_denied"]
        self.assertEqual(
            [{"action": "rotate", "version": 1, "presented_shares": 0, "approvals": 2}],
            [event["payload"] for event in denied],
        )

    def test_rotation_updates_clears_and_preserves_the_policy(self):
        always = {"fact": {"fact": "presented_shares", "op": "gte", "value": 0}}
        self.create(policy=always)
        self.approve(["alice", "bob"])
        # Omitting policy preserves it.
        self.service.rotate("prod-db-root", {}, "rotate-1")
        self.assertEqual({"policy": always}, self.service.get_policy("prod-db-root"))
        # A new policy replaces it.
        replacement = {"fact": {"fact": "version", "op": "gte", "value": 1}}
        self.approve(["alice", "bob"], key_prefix="v2")
        self.service.rotate("prod-db-root", {"policy": replacement}, "rotate-2")
        self.assertEqual({"policy": replacement}, self.service.get_policy("prod-db-root"))
        # An explicit null clears it.
        self.approve(["alice", "bob"], key_prefix="v3")
        self.service.rotate("prod-db-root", {"policy": None}, "rotate-3")
        self.assertEqual({"policy": None}, self.service.get_policy("prod-db-root"))
        # With no policy, rotation is back to the legacy behaviour.
        self.approve(["alice", "bob"], key_prefix="v4")
        record = self.service.rotate("prod-db-root", {}, "rotate-4")
        self.assertEqual(5, record["version"])

    def test_policy_applies_to_the_action_not_the_new_policy_being_set(self):
        # The current policy forbids rotation; installing a permissive policy
        # in the same request is still denied.
        self.create(policy={"fact": {"fact": "action", "op": "eq", "value": "reconstruct"}})
        self.approve(["alice", "bob"])
        self.assert_code(
            "policy_denied", self.service.rotate, "prod-db-root", {"policy": None}, "rotate-1"
        )
        self.assertEqual(
            {"policy": {"fact": {"fact": "action", "op": "eq", "value": "reconstruct"}}},
            self.service.get_policy("prod-db-root"),
        )

    def test_policy_denied_is_not_audited_as_reconstruction_failed(self):
        self.create(policy={"fact": {"fact": "action", "op": "eq", "value": "rotate"}})
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["alice", "bob"])
        self.assert_code("policy_denied", self.reconstruct, issued, ["alice", "bob", "carol"], "reconstruct-1")
        types = [event["type"] for event in self.service.audit("prod-db-root")["events"]]
        self.assertIn("authorization_denied", types)
        self.assertNotIn("reconstruction_failed", types)

    # -------------------------------------------------------------- backup v2
    def test_backup_carries_the_authorization_policy(self):
        policy = {"any": [self.RECONSTRUCT_ONLY, self.EXTRA_SHARES]}
        self.create(policy=policy)
        backup = self.service.export_backup("prod-db-root")
        self.assertEqual("thresholdsafe-backup-v3", backup["backup_version"])
        self.assertEqual(policy, backup["authorization_policy"])
        self.assertNotIn("policy", backup["secret"])
        self.assertTrue(self.service.verify_backup({"backup": backup})["valid"])

    def test_verify_still_accepts_v1_backups(self):
        self.create()
        backup = self.service.export_backup("prod-db-root")
        v1 = {key: value for key, value in backup.items() if key not in ("authorization_policy", "versions")}
        v1["backup_version"] = "thresholdsafe-backup-v1"
        v1["checksum"] = hashlib.sha256(
            json.dumps({k: v for k, v in v1.items() if k != "checksum"},
                       ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        self.assertTrue(self.service.verify_backup({"backup": v1})["valid"])
        # A v1 document must not carry the v2/v3 fields.
        v1["authorization_policy"] = None
        self.assert_code("validation_error", self.service.verify_backup, {"backup": v1})
        v1.pop("authorization_policy")
        v1["versions"] = []
        self.assert_code("validation_error", self.service.verify_backup, {"backup": v1})

    def test_verify_v3_rejects_bad_policy_and_checksum(self):
        self.create(policy=self.RECONSTRUCT_ONLY)
        backup = self.service.export_backup("prod-db-root")
        broken = copy.deepcopy(backup)
        broken["authorization_policy"] = {"fact": {"fact": "action", "op": "eq", "value": "delete"}}
        self.assert_code("validation_error", self.service.verify_backup, {"backup": broken})
        broken = copy.deepcopy(backup)
        broken["authorization_policy"] = None
        self.assert_code("backup_integrity", self.service.verify_backup, {"backup": broken})

    def test_verify_still_accepts_v2_backups(self):
        self.create(policy=self.RECONSTRUCT_ONLY)
        backup = self.service.export_backup("prod-db-root")
        v2 = {key: value for key, value in backup.items() if key != "versions"}
        v2["backup_version"] = "thresholdsafe-backup-v2"
        v2["checksum"] = hashlib.sha256(
            json.dumps({k: v for k, v in v2.items() if k != "checksum"},
                       ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        self.assertTrue(self.service.verify_backup({"backup": v2})["valid"])
        # A v2 document must not carry the v3 field.
        v2["versions"] = backup["versions"]
        self.assert_code("validation_error", self.service.verify_backup, {"backup": v2})

    # -------------------------------------------------------------- approval roles
    APPROVERS = ["nina", "oscar", "pam"]

    def create_separated(self, key="create-1", **overrides):
        body = {"approvers": list(self.APPROVERS), "approvals_required": 2}
        body.update(overrides)
        return self.create(key=key, **body)

    def test_legacy_creation_reports_holders_as_approvers(self):
        record = self.create()
        self.assertEqual("legacy", record["approval_mode"])
        self.assertEqual(HOLDERS, record["approvers"])
        self.assertEqual(record, self.service.get_secret("prod-db-root"))

    def test_separated_creation_records_the_roles(self):
        record = self.create_separated()
        self.assertEqual("separated", record["approval_mode"])
        self.assertEqual(self.APPROVERS, record["approvers"])
        self.assertEqual(HOLDERS, record["holders"])
        self.assertEqual({"recorded": 0, "required": 2, "satisfied": False}, record["approvals"])
        self.assertEqual(record, self.service.get_secret("prod-db-root"))

    def test_separated_creation_validation(self):
        cases = [
            {"approvers": ["nina"]},                                  # fewer than two approvers
            {"approvers": ["nina", "nina"]},                          # repeated approver
            {"approvers": ["nina", "oscar"], "approvals_required": 1},   # quorum below two
            {"approvers": ["nina", "oscar"], "approvals_required": 3},   # quorum above roster
            {"approvers": ["alice", "nina"]},                         # overlaps the holders
            {"approvers": ["nina", "bad name"]},                      # invalid identifier
            {"approvers": "nina"},                                    # not an array
            {"approvers": []},                                        # empty roster
        ]
        for index, overrides in enumerate(cases):
            self.assert_code(
                "validation_error",
                self.service.create_secret,
                create_body(id=f"sep-{index}", **overrides),
                f"create-{index}",
            )
        # An explicit null is the legacy mode.
        record = self.service.create_secret(create_body(approvers=None), "create-null")
        self.assertEqual("legacy", record["approval_mode"])

    def test_separated_approvals_come_from_the_approver_roster(self):
        self.create_separated()
        record_approval = self.service.record_approval
        # Holders are not approvers in separated mode, and vice versa.
        self.assert_code("validation_error", record_approval, "prod-db-root", {"approver": "alice"}, "k1")
        first = self.approve(["nina"], key_prefix="pair")[0]
        self.assertEqual((1, 2, False), (first["approvals"], first["required"], first["satisfied"]))
        self.assert_code("duplicate_approval", record_approval, "prod-db-root", {"approver": "nina"}, "k2")
        self.assertTrue(self.approve(["oscar"], key_prefix="pair")[0]["satisfied"])

    def test_separated_reconstruction_uses_holder_shares_and_approver_quorum(self):
        self.create_separated()
        issued = self.distribute(["alice", "bob", "carol"])
        self.approve(["nina"])
        self.assert_code(
            "insufficient_approvals", self.reconstruct, issued, ["alice", "bob", "carol"], "reconstruct-1"
        )
        self.approve(["pam"], key_prefix="second")
        result = self.reconstruct(issued, ["alice", "bob", "carol"], "reconstruct-2")
        self.assertEqual(SECRET, result["secret"])
        self.assertEqual(0, self.service.get_secret("prod-db-root")["approvals"]["recorded"])

    def test_rotation_omitting_approvers_keeps_the_separated_roster(self):
        self.create_separated()
        self.approve(["nina", "oscar"])
        record = self.service.rotate("prod-db-root", {"holders": ["frank", "grace", "heidi"]}, "rotate-1")
        self.assertEqual("separated", record["approval_mode"])
        self.assertEqual(self.APPROVERS, record["approvers"])
        self.assertEqual(["frank", "grace", "heidi"], record["holders"])
        # The old version's approvals were consumed; the same roster approves v2.
        self.assert_code("insufficient_approvals", self.service.rotate, "prod-db-root", {}, "rotate-2")
        self.approve(["nina", "pam"], key_prefix="v2")
        record = self.service.rotate("prod-db-root", {}, "rotate-3")
        self.assertEqual((3, "separated"), (record["version"], record["approval_mode"]))

    def test_rotation_omitting_approvers_keeps_legacy_following_the_holders(self):
        self.create()
        self.approve(["alice", "bob"])
        record = self.service.rotate(
            "prod-db-root", {"holders": ["frank", "grace", "heidi"], "approvals_required": 2}, "rotate-1"
        )
        self.assertEqual("legacy", record["approval_mode"])
        self.assertEqual(["frank", "grace", "heidi"], record["approvers"])
        # The new holders are the approvers now.
        self.assert_code(
            "validation_error", self.service.record_approval, "prod-db-root", {"approver": "alice"}, "k1"
        )
        self.approve(["frank", "grace"], key_prefix="v2")

    def test_rotation_switches_modes_with_an_array_or_null(self):
        self.create()
        self.approve(["alice", "bob"])
        record = self.service.rotate(
            "prod-db-root", {"approvers": ["nina", "oscar"], "approvals_required": 2}, "rotate-1"
        )
        self.assertEqual("separated", record["approval_mode"])
        self.assertEqual(["nina", "oscar"], record["approvers"])
        # Holders can no longer approve; the new approver roster can.
        self.assert_code(
            "validation_error", self.service.record_approval, "prod-db-root", {"approver": "alice"}, "k1"
        )
        self.approve(["nina", "oscar"], key_prefix="v2")
        record = self.service.rotate("prod-db-root", {"approvers": None}, "rotate-2")
        self.assertEqual("legacy", record["approval_mode"])
        self.assertEqual(HOLDERS, record["approvers"])
        self.assert_code(
            "validation_error", self.service.record_approval, "prod-db-root", {"approver": "nina"}, "k2"
        )

    def test_rotation_rejects_an_invalid_target_role_configuration(self):
        self.create_separated()
        self.approve(["nina", "oscar"])
        rotate = self.service.rotate
        # The retained separated roster would overlap the new holders.
        self.assert_code(
            "validation_error", rotate, "prod-db-root", {"holders": ["nina", "grace", "heidi"]}, "r1"
        )
        # An explicit roster overlapping the holders.
        self.assert_code("validation_error", rotate, "prod-db-root", {"approvers": ["alice", "pam"]}, "r2")
        # A quorum outside 2..len(approvers) for the explicit roster.
        self.assert_code(
            "validation_error", rotate, "prod-db-root",
            {"approvers": ["p1", "p2"], "approvals_required": 3}, "r3",
        )
        self.assert_code(
            "validation_error", rotate, "prod-db-root", {"approvers": ["only-one"]}, "r4",
        )
        # Switching to legacy with a quorum the holders cannot meet.
        self.assert_code(
            "validation_error", rotate, "prod-db-root",
            {"approvers": None, "holders": ["frank", "grace"], "threshold": 2, "approvals_required": 3},
            "r5",
        )
        # Nothing moved: version, mode, roster and approvals are untouched.
        record = self.service.get_secret("prod-db-root")
        self.assertEqual((1, "separated"), (record["version"], record["approval_mode"]))
        self.assertEqual(self.APPROVERS, record["approvers"])
        self.assertEqual(2, record["approvals"]["recorded"])
        # The same approvals still authorize a valid rotation.
        record = self.service.rotate("prod-db-root", {}, "rotate-ok")
        self.assertEqual(2, record["version"])

    def test_role_information_is_audited(self):
        self.create_separated()
        self.approve(["nina", "oscar"])
        self.service.rotate("prod-db-root", {}, "rotate-1")
        run = self.service.audit("prod-db-root")
        self.assertTrue(run["chain_valid"])
        created = run["events"][0]
        self.assertEqual("secret_created", created["type"])
        self.assertEqual("separated", created["payload"]["approval_mode"])
        self.assertEqual(self.APPROVERS, created["payload"]["approvers"])
        approval = next(event for event in run["events"] if event["type"] == "approval_recorded")
        self.assertEqual("separated", approval["payload"]["approval_mode"])
        self.assertEqual(self.APPROVERS, approval["payload"]["approvers"])
        rotated = next(event for event in run["events"] if event["type"] == "secret_rotated")
        self.assertEqual("separated", rotated["payload"]["approval_mode"])
        self.assertEqual(self.APPROVERS, rotated["payload"]["approvers"])

    def test_backup_v3_carries_per_version_role_snapshots(self):
        self.create_separated()
        self.approve(["nina", "oscar"])
        self.service.rotate(
            "prod-db-root",
            {"holders": ["frank", "grace", "heidi"], "threshold": 2, "approvers": None},
            "rotate-1",
        )
        backup = self.service.export_backup("prod-db-root")
        self.assertEqual("thresholdsafe-backup-v3", backup["backup_version"])
        versions = backup["versions"]
        self.assertEqual([1, 2], [entry["version"] for entry in versions])
        self.assertEqual(
            {"version": 1, "approval_mode": "separated", "holders": HOLDERS, "approvers": self.APPROVERS},
            versions[0],
        )
        self.assertEqual(
            {"version": 2, "approval_mode": "legacy",
             "holders": ["frank", "grace", "heidi"], "approvers": ["frank", "grace", "heidi"]},
            versions[1],
        )
        self.assertNotIn("approvers", backup["secret"])
        self.assertNotIn("approval_mode", backup["secret"])
        self.assertTrue(self.service.verify_backup({"backup": backup})["valid"])

    def test_verify_v3_rejects_role_attribution_tampering(self):
        self.create_separated()
        self.approve(["nina", "oscar"])
        backup = self.service.export_backup("prod-db-root")

        def restamp(broken):
            unsigned = {k: v for k, v in broken.items() if k != "checksum"}
            encoded = json.dumps(unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            broken["checksum"] = hashlib.sha256(encoded.encode()).hexdigest()
            return broken

        tampers = [
            # An approver the version snapshot does not list.
            lambda b: b["versions"][0].update(approvers=["nina", "pam"]),
            # Snapshot holders diverging from the issued shares.
            lambda b: b["versions"][0].update(holders=["alice", "bob", "carol"]),
            # A legacy entry whose approvers differ from its holders.
            lambda b: b["versions"][0].update(approval_mode="legacy"),
            # A separated entry whose roles overlap.
            lambda b: b["versions"][0].update(approvers=["alice", "nina", "oscar"]),
            # Broken version continuity.
            lambda b: b["versions"][0].update(version=2),
        ]
        for tamper in tampers:
            broken = copy.deepcopy(backup)
            tamper(broken)
            self.assert_code("backup_integrity", self.service.verify_backup, {"backup": restamp(broken)})
        self.assertTrue(self.service.verify_backup({"backup": backup})["valid"])

    def test_pre_roles_database_records_read_as_legacy(self):
        self.create()
        self.approve(["alice", "bob"])
        # Simulate a document written before approval modes existed.
        document = self.service._document("prod-db-root")
        for key in ("approval_mode", "approvers", "versions"):
            document.pop(key)
        self.service.store.connection.execute(
            "UPDATE secrets SET document = ? WHERE id = ?",
            (self.service.store.encode(document), "prod-db-root"),
        )
        record = self.service.get_secret("prod-db-root")
        self.assertEqual("legacy", record["approval_mode"])
        self.assertEqual(HOLDERS, record["approvers"])
        # Rotation rebuilds the version history from the issued shares.
        record = self.service.rotate("prod-db-root", {}, "rotate-1")
        self.assertEqual("legacy", record["approval_mode"])
        backup = self.service.export_backup("prod-db-root")
        self.assertEqual([1, 2], [entry["version"] for entry in backup["versions"]])
        self.assertTrue(all(entry["approval_mode"] == "legacy" for entry in backup["versions"]))
        self.assertEqual(HOLDERS, backup["versions"][0]["approvers"])
        self.assertTrue(self.service.verify_backup({"backup": backup})["valid"])

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
