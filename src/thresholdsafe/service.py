from __future__ import annotations

import hashlib
import sqlite3
from typing import Any, Callable

from . import receipts, shamir
from .backup import (
    BACKUP_VERSION,
    ZERO_HASH,
    event_hash as _event_hash,
    share_commitment as _share_commitment,
    stamp as _stamp,
    verify as _verify,
)
from .errors import (
    AuditIntegrity,
    ConflictError,
    DuplicateApproval,
    InsufficientApprovals,
    InsufficientShares,
    IntegrityFailure,
    NotFoundError,
    PolicyDenied,
    SecretFrozen,
    SecretNotFrozen,
    ShareAlreadyDistributed,
    ShareMismatch,
    ShareNotDistributed,
    StaleShare,
    ThresholdSafeError,
    ValidationError,
)
from .model import (
    UNSET,
    RotationSpec,
    SecretSpec,
    ShareClaim,
    parse_share_claims,
    reason_field,
    resolve_roles,
    single_field,
)
from .policy import evaluate as evaluate_policy
from .shamir import RandomSource, SeededRandomSource, SystemRandomSource
from .store import Store

# Rejected attempts that are custody decisions rather than malformed requests
# are worth recording even though they changed nothing else.
AUDITED_FAILURES = frozenset(
    {
        "insufficient_shares",
        "insufficient_approvals",
        "stale_share",
        "share_not_distributed",
        "share_mismatch",
        "integrity_failure",
    }
)


def _share_id(secret_id: str, version: int, holder: str) -> str:
    return f"{secret_id}.v{version}.{holder}"


def _secret_digest(secret: bytes) -> str:
    return hashlib.sha256(b"thresholdsafe:v1:secret:" + secret).hexdigest()


class ThresholdSafe:
    def __init__(self, database: str, source: RandomSource | None = None):
        self.store = Store(database)
        self.source: RandomSource = source if source is not None else SystemRandomSource()
        self._receipt_key = self._load_receipt_key()

    def _load_receipt_key(self) -> receipts.ReceiptKey:
        """The receipt-signing key of this database, created on first use.

        Runs inside one ``BEGIN IMMEDIATE`` transaction, so concurrent
        processes opening the same database — old or new — converge on a
        single persisted key. The private half never leaves the database.
        """
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT private_key FROM receipt_keys WHERE id = 1"
            ).fetchone()
            if row is not None:
                return receipts.ReceiptKey.load(row["private_key"])
            key = receipts.ReceiptKey.generate()
            connection.execute(
                "INSERT INTO receipt_keys(id, algorithm, private_key, public_key, key_id, created_at) "
                "VALUES (1, ?, ?, ?, ?, ?)",
                (receipts.ALGORITHM, key.private_key, key.public_key, key.key_id, self.store.now()),
            )
            return key

    # ------------------------------------------------------------------ create
    def create_secret(self, raw: Any, key: str | None) -> dict[str, Any]:
        spec = SecretSpec.parse(raw)

        def create() -> dict[str, Any]:
            now = self.store.now()
            points = shamir.split(spec.secret, spec.threshold, len(spec.holders), self._source(spec.seed))
            mode = "separated" if spec.approvers is not None else "legacy"
            approvers = list(spec.approvers) if spec.approvers is not None else list(spec.holders)
            document = {
                "id": spec.id,
                "name": spec.name,
                "version": 1,
                "threshold": spec.threshold,
                "holders": list(spec.holders),
                "approvals_required": spec.approvals_required,
                "approval_mode": mode,
                "approvers": list(spec.approvers) if spec.approvers is not None else None,
                "versions": [{
                    "version": 1,
                    "approval_mode": mode,
                    "holders": list(spec.holders),
                    "approvers": approvers,
                }],
                "secret_digest": _secret_digest(spec.secret),
                "secret_length": len(spec.secret),
                "policy": spec.policy,
                "status": "active",
                "status_reason": None,
                "status_changed_at": now,
                "status_epoch": 0,
                "created_at": now,
                "updated_at": now,
            }
            try:
                self.store.connection.execute(
                    "INSERT INTO secrets(id, document, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (spec.id, self.store.encode(document), now, now),
                )
            except sqlite3.IntegrityError as error:
                if "UNIQUE constraint" not in str(error):
                    raise
                raise ConflictError(f"secret {spec.id} already exists") from error
            self._issue(1, spec.id, spec.holders, points)
            self._append(spec.id, "secret_created", {
                "version": 1,
                "name": spec.name,
                "threshold": spec.threshold,
                "approvals_required": spec.approvals_required,
                "approval_mode": mode,
                "approvers": approvers,
                "holders": list(spec.holders),
                "share_count": len(spec.holders),
                "secret_length": len(spec.secret),
                "deterministic": spec.seed is not None,
            })
            return self._record(spec.id)

        return self._idempotent(key, f"create-secret:{spec.id}", create)

    def get_secret(self, secret_id: str) -> dict[str, Any]:
        return self._record(secret_id)

    def get_policy(self, secret_id: str) -> dict[str, Any]:
        """Return the persistent authorization policy of one secret.

        Read-only: a frozen secret answers exactly like an active one, and no
        audit event or idempotency record is written. Secrets without a policy
        respond with ``{"policy": None}``.
        """
        return {"policy": self._document(secret_id).get("policy")}

    # ------------------------------------------------------- freeze / unfreeze
    def freeze_secret(self, secret_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        self._require_key(key)
        reason = reason_field(raw)

        def freeze_operation() -> str:
            document = self._document(secret_id)
            epoch = document["status_epoch"]
            # A completed freeze carries the epoch it entered; a pending freeze
            # while active would open the next epoch, so retries after an
            # unfreeze cannot replay an older freeze cycle's response.
            scope = epoch if document["status"] == "frozen" else epoch + 1
            return f"freeze-secret:{secret_id}:e{scope}"

        def freeze() -> dict[str, Any]:
            document = self._document(secret_id)
            if document["status"] == "frozen":
                raise SecretFrozen(f"secret {secret_id} is already frozen")
            now = self.store.now()
            document["status"] = "frozen"
            document["status_reason"] = reason
            document["status_changed_at"] = now
            document["status_epoch"] = document["status_epoch"] + 1
            self.store.connection.execute(
                "UPDATE secrets SET document = ? WHERE id = ?",
                (self.store.encode(document), secret_id),
            )
            self._append(secret_id, "secret_frozen", {"version": document["version"], "reason": reason})
            return self._record(secret_id, document)

        return self._idempotent(key, freeze_operation, freeze)

    def unfreeze_secret(self, secret_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        self._require_key(key)
        reason = reason_field(raw)

        def unfreeze_operation() -> str:
            document = self._document(secret_id)
            return f"unfreeze-secret:{secret_id}:e{document['status_epoch']}"

        def unfreeze() -> dict[str, Any]:
            document = self._document(secret_id)
            if document["status"] != "frozen":
                raise SecretNotFrozen(f"secret {secret_id} is not frozen")
            now = self.store.now()
            document["status"] = "active"
            document["status_reason"] = reason
            document["status_changed_at"] = now
            self.store.connection.execute(
                "UPDATE secrets SET document = ? WHERE id = ?",
                (self.store.encode(document), secret_id),
            )
            self._append(secret_id, "secret_unfrozen", {"version": document["version"], "reason": reason})
            return self._record(secret_id, document)

        return self._idempotent(key, unfreeze_operation, unfreeze)

    @staticmethod
    def _require_active(document: dict[str, Any], secret_id: str) -> None:
        if document["status"] == "frozen":
            raise SecretFrozen(f"secret {secret_id} is frozen")

    # ------------------------------------------------------------- distribution
    def distribute_share(self, secret_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        self._require_key(key)
        holder = single_field(raw, "holder", "share distribution body")
        document = self._document(secret_id)
        operation = f"distribute-share:{secret_id}:v{document['version']}:{holder}"

        def distribute() -> dict[str, Any]:
            document = self._document(secret_id)
            self._require_active(document, secret_id)
            if holder not in document["holders"]:
                raise ValidationError(f"holder {holder} is not registered for secret {secret_id}")
            share_id = _share_id(secret_id, document["version"], holder)
            row = self.store.connection.execute(
                "SELECT value, distributed_at FROM shares WHERE share_id = ?", (share_id,)
            ).fetchone()
            if row is None:
                raise IntegrityFailure(f"share {share_id} is missing from the store")
            if row["distributed_at"] is not None:
                raise ShareAlreadyDistributed(f"share {share_id} was already distributed")
            now = self.store.now()
            self.store.connection.execute(
                "UPDATE shares SET distributed_at = ? WHERE share_id = ?", (now, share_id)
            )
            self._append(secret_id, "share_distributed",
                         {"share_id": share_id, "holder": holder, "version": document["version"]})
            return {
                "secret_id": secret_id,
                "version": document["version"],
                "threshold": document["threshold"],
                "share": {
                    "share_id": share_id,
                    "holder": holder,
                    "value": row["value"],
                    "distributed_at": now,
                },
            }

        return self._idempotent(
            key, operation, distribute, blocked=(secret_id, "distribute_share")
        )

    # ---------------------------------------------------------------- approvals
    def record_approval(self, secret_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        self._require_key(key)
        approver = single_field(raw, "approver", "approval body")
        document = self._document(secret_id)
        operation = f"record-approval:{secret_id}:v{document['version']}:{approver}"

        def record() -> dict[str, Any]:
            document = self._document(secret_id)
            self._require_active(document, secret_id)
            mode, approvers = self._roles(document)
            if approver not in approvers:
                role = "approver" if mode == "separated" else "holder"
                raise ValidationError(f"approver {approver} is not a registered {role} of secret {secret_id}")
            version = document["version"]
            existing = self.store.connection.execute(
                "SELECT consumed_at FROM approvals WHERE secret_id = ? AND version = ? AND approver = ?",
                (secret_id, version, approver),
            ).fetchone()
            if existing is not None and existing["consumed_at"] is None:
                raise DuplicateApproval(f"approver {approver} has already approved version {version}")
            now = self.store.now()
            if existing is None:
                self.store.connection.execute(
                    "INSERT INTO approvals(secret_id, version, approver, created_at, consumed_at) "
                    "VALUES (?, ?, ?, ?, NULL)",
                    (secret_id, version, approver, now),
                )
            else:
                self.store.connection.execute(
                    "UPDATE approvals SET created_at = ?, consumed_at = NULL "
                    "WHERE secret_id = ? AND version = ? AND approver = ?",
                    (now, secret_id, version, approver),
                )
            recorded = self._approval_count(secret_id, version)
            required = document["approvals_required"]
            self._append(secret_id, "approval_recorded", {
                "approver": approver,
                "version": version,
                "approvals": recorded,
                "required": required,
                "approval_mode": mode,
                "approvers": approvers,
            })
            return {
                "secret_id": secret_id,
                "approver": approver,
                "version": version,
                "approvals": recorded,
                "required": required,
                "satisfied": recorded >= required,
                "recorded_at": now,
            }

        return self._idempotent(
            key, operation, record, blocked=(secret_id, "record_approval")
        )

    # ------------------------------------------------------------- reconstruct
    def reconstruct(self, secret_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        self._require_key(key)
        claims = parse_share_claims(raw)
        self._document(secret_id)
        try:
            return self._idempotent(
                key,
                f"reconstruct:{secret_id}",
                lambda: self._reconstruct(secret_id, claims),
                blocked=(secret_id, "reconstruct"),
            )
        except ThresholdSafeError as error:
            if error.code in AUDITED_FAILURES:
                self._audit_failure(secret_id, error, len(claims))
            raise

    def _reconstruct(self, secret_id: str, claims: list[ShareClaim]) -> dict[str, Any]:
        document = self._document(secret_id)
        self._require_active(document, secret_id)
        version, threshold = document["version"], document["threshold"]
        points: list[tuple[int, int]] = []
        used: list[str] = []
        holders: list[str] = []
        for claim in claims:
            row = self.store.connection.execute(
                "SELECT * FROM shares WHERE share_id = ?", (claim.share_id,)
            ).fetchone()
            if row is None or row["secret_id"] != secret_id:
                raise NotFoundError(f"share {claim.share_id} was not found for secret {secret_id}")
            if row["version"] != version:
                raise StaleShare(
                    f"share {claim.share_id} belongs to version {row['version']} and was invalidated "
                    f"by rotation to version {version}"
                )
            if row["distributed_at"] is None:
                raise ShareNotDistributed(f"share {claim.share_id} has not been distributed to its holder")
            if row["value"] != claim.value:
                raise ShareMismatch(f"share {claim.share_id} value does not match the issued commitment")
            points.append((int(row["coordinate"]), int(row["value"], 16)))
            used.append(claim.share_id)
            holders.append(row["holder"])
        if len(points) < threshold:
            raise InsufficientShares(f"reconstruction requires {threshold} shares but {len(points)} were provided")
        if len({coordinate for coordinate, _ in points}) != len(points):
            raise ValidationError("shares must come from distinct holders")
        required = document["approvals_required"]
        recorded = self._approval_count(secret_id, version)
        if recorded < required:
            raise InsufficientApprovals(
                f"reconstruction requires {required} approvals for version {version} but {recorded} were recorded"
            )
        self._authorize(secret_id, document, "reconstruct", version, recorded, len(points))
        try:
            secret = shamir.combine(points).to_bytes(document["secret_length"], "big")
        except OverflowError as error:
            raise IntegrityFailure("reconstructed value does not fit the recorded secret length") from error
        if _secret_digest(secret) != document["secret_digest"]:
            raise IntegrityFailure("reconstructed secret does not match the stored commitment")
        now = self.store.now()
        self._consume_approvals(secret_id, version, now, recorded, "reconstruct")
        self._append(secret_id, "secret_reconstructed", {
            "version": version,
            "threshold": threshold,
            "share_ids": sorted(used),
            "holders": sorted(holders),
        })
        return {
            "id": secret_id,
            "version": version,
            "secret": secret.decode("utf-8"),
            "threshold": threshold,
            "used_shares": sorted(used),
            "holders": sorted(holders),
            "reconstructed_at": now,
        }

    # ------------------------------------------------------------------- rotate
    def rotate(self, secret_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        self._require_key(key)
        spec = RotationSpec.parse(raw)
        document = self._document(secret_id)
        operation = f"rotate:{secret_id}:v{document['version']}"

        def apply() -> dict[str, Any]:
            document = self._document(secret_id)
            self._require_active(document, secret_id)
            previous = document["version"]
            required = document["approvals_required"]
            recorded = self._approval_count(secret_id, previous)
            if recorded < required:
                raise InsufficientApprovals(
                    f"rotation requires {required} approvals for version {previous} but {recorded} were recorded"
                )
            threshold = spec.threshold if spec.threshold is not None else document["threshold"]
            holders = spec.holders if spec.holders is not None else tuple(document["holders"])
            approvals_required = (
                spec.approvals_required if spec.approvals_required is not None else document["approvals_required"]
            )
            # Resolve the target approval mode before touching any state: an
            # omitted approvers field continues the current mode (legacy follows
            # the final holders, separated keeps its roster), an explicit null
            # returns to legacy, and an array installs a separated roster.
            if spec.approvers is UNSET:
                mode = document.get("approval_mode", "legacy")
                approvers = list(document["approvers"]) if mode == "separated" else None
            elif spec.approvers is None:
                mode, approvers = "legacy", None
            else:
                mode, approvers = "separated", list(spec.approvers)
            resolve_roles(threshold, holders, approvals_required, mode, approvers)
            self._authorize(secret_id, document, "rotate", previous, recorded, 0)
            secret = spec.secret if spec.secret is not None else self._recover(secret_id, document)
            now = self.store.now()
            self._consume_approvals(secret_id, previous, now, recorded, "rotate")
            invalidated = self.store.connection.execute(
                "UPDATE shares SET invalidated_at = ? WHERE secret_id = ? AND version = ? AND invalidated_at IS NULL",
                (now, secret_id, previous),
            ).rowcount
            version = previous + 1
            self._issue(version, secret_id, holders, shamir.split(secret, threshold, len(holders), self._source(spec.seed)))
            history = document.get("versions")
            if history is None:
                # A document written before approval modes existed: every past
                # version is legacy, with the holders acting as approvers.
                history = self._legacy_history(secret_id, previous)
            effective = approvers if approvers is not None else list(holders)
            document["versions"] = history + [{
                "version": version,
                "approval_mode": mode,
                "holders": list(holders),
                "approvers": effective,
            }]
            document.update({
                "version": version,
                "threshold": threshold,
                "holders": list(holders),
                "approvals_required": approvals_required,
                "approval_mode": mode,
                "approvers": approvers,
                "secret_digest": _secret_digest(secret),
                "secret_length": len(secret),
                "updated_at": now,
            })
            if spec.policy is not UNSET:
                document["policy"] = spec.policy
            self.store.connection.execute(
                "UPDATE secrets SET document = ?, updated_at = ? WHERE id = ?",
                (self.store.encode(document), now, secret_id),
            )
            self._append(secret_id, "secret_rotated", {
                "version": version,
                "previous_version": previous,
                "threshold": threshold,
                "approvals_required": approvals_required,
                "approval_mode": mode,
                "approvers": effective,
                "holders": list(holders),
                "share_count": len(holders),
                "invalidated_shares": invalidated,
                "secret_changed": spec.secret is not None,
            })
            return self._record(secret_id)

        return self._idempotent(key, operation, apply, blocked=(secret_id, "rotate"))

    # ------------------------------------------------------------------ backup
    def export_backup(self, secret_id: str) -> dict[str, Any]:
        """Export a self-contained, checksummed backup of one secret.

        Read-only: a frozen secret exports exactly like an active one, and no
        audit event or idempotency record is written. The plaintext secret is
        never included — only its digest and length — but share values are, so
        the backup is sensitive material.
        """
        document = self._document(secret_id)
        shares = self.store.connection.execute(
            "SELECT share_id, secret_id, version, holder, coordinate, value, commitment, "
            "distributed_at, invalidated_at FROM shares WHERE secret_id = ? "
            "ORDER BY version, coordinate",
            (secret_id,),
        ).fetchall()
        approvals = self.store.connection.execute(
            "SELECT secret_id, version, approver, created_at, consumed_at FROM approvals "
            "WHERE secret_id = ? ORDER BY version, approver",
            (secret_id,),
        ).fetchall()
        events = self.store.connection.execute(
            "SELECT sequence, type, payload, occurred_at, previous_hash, hash FROM audit_events "
            "WHERE secret_id = ? ORDER BY sequence",
            (secret_id,),
        ).fetchall()
        versions = document.get("versions")
        if versions is None:
            # A document written before approval modes existed: derive the
            # per-version rosters from the shares, all in legacy mode.
            versions = self._legacy_history(secret_id, document["version"])
        return _stamp({
            "backup_version": BACKUP_VERSION,
            "generated_at": self.store.now(),
            "authorization_policy": document.get("policy"),
            "secret": {
                key: value
                for key, value in document.items()
                if key not in ("policy", "approval_mode", "approvers", "versions")
            },
            "versions": [dict(entry) for entry in versions],
            "shares": [dict(row) for row in shares],
            "approvals": [dict(row) for row in approvals],
            "audit_events": [
                {
                    "sequence": row["sequence"],
                    "type": row["type"],
                    "payload": self.store.decode(row["payload"]),
                    "occurred_at": row["occurred_at"],
                    "previous_hash": row["previous_hash"],
                    "hash": row["hash"],
                }
                for row in events
            ],
        })

    def verify_backup(self, raw: Any) -> dict[str, Any]:
        """Independently verify a backup document without touching service state."""
        if not isinstance(raw, dict) or set(raw) != {"backup"}:
            raise ValidationError("backup verification body must contain exactly backup")
        return _verify(raw["backup"])

    # -------------------------------------------------------------------- audit
    def audit(self, secret_id: str) -> dict[str, Any]:
        document = self._document(secret_id)
        events, chain_valid = self._audit_events(secret_id)
        return {
            "secret_id": secret_id,
            "version": document["version"],
            "chain_valid": chain_valid,
            "head_hash": events[-1]["hash"] if events else ZERO_HASH,
            "events": events,
        }

    def _audit_events(self, secret_id: str) -> tuple[list[dict[str, Any]], bool]:
        """The decoded event stream of one secret plus its chain verdict."""
        rows = self.store.connection.execute(
            "SELECT sequence, type, payload, occurred_at, previous_hash, hash FROM audit_events "
            "WHERE secret_id = ? ORDER BY sequence",
            (secret_id,),
        ).fetchall()
        events: list[dict[str, Any]] = []
        previous = ZERO_HASH
        chain_valid = True
        for row in rows:
            events.append({
                "sequence": row["sequence"],
                "type": row["type"],
                "payload": self.store.decode(row["payload"]),
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
                "hash": row["hash"],
            })
            expected = _event_hash(row["previous_hash"], row["sequence"], row["type"], row["payload"], row["occurred_at"])
            if row["previous_hash"] != previous or row["hash"] != expected:
                chain_valid = False
            previous = row["hash"]
        return events, chain_valid

    # ----------------------------------------------------------------- receipts
    def receipt_key(self) -> dict[str, Any]:
        """The public half of the receipt-signing key.

        Read-only: no audit event or idempotency record is written, and the
        private half never appears here (or anywhere else outside the
        database).
        """
        return {
            "algorithm": receipts.ALGORITHM,
            "key_id": self._receipt_key.key_id,
            "public_key": self._receipt_key.public_key,
        }

    def issue_receipt(self, secret_id: str, raw: Any, key: str | None) -> dict[str, Any]:
        """Sign a receipt certifying one audit event of one secret.

        The whole chain is re-verified first: a broken chain is
        ``409 audit_integrity``. The issuance itself is appended to the
        chain as ``audit_receipt_issued`` in the same transaction, and the
        receipt's head points at that event. A frozen secret is served
        exactly like an active one; failures write nothing.
        """
        self._require_key(key)
        sequence, nonce = receipts.parse_request(raw)
        operation = "audit-receipt:" + self.store.encode([secret_id, sequence, nonce])

        def issue() -> dict[str, Any]:
            self._document(secret_id)
            events, chain_valid = self._audit_events(secret_id)
            if not chain_valid:
                raise AuditIntegrity(f"the audit chain of secret {secret_id} is broken")
            target = next((event for event in events if event["sequence"] == sequence), None)
            if target is None:
                raise NotFoundError(f"event {sequence} was not found for secret {secret_id}")
            head = self._append(secret_id, "audit_receipt_issued", {
                "key_id": self._receipt_key.key_id,
                "nonce": nonce,
                "target_sequence": sequence,
            })
            receipt = {
                "algorithm": receipts.ALGORITHM,
                "key_id": self._receipt_key.key_id,
                "secret_id": secret_id,
                "event": target,
                "nonce": nonce,
                "head_sequence": head["sequence"],
                "head_hash": head["hash"],
            }
            receipt["signature"] = self._receipt_key.sign(receipts.signing_payload(receipt))
            return receipt

        return self._idempotent(key, operation, issue)

    def verify_receipt(self, raw: Any) -> dict[str, Any]:
        """Independently verify an audit receipt without touching service state."""
        if not isinstance(raw, dict) or set(raw) != {"receipt", "public_key"}:
            raise ValidationError("receipt verification body must contain exactly receipt and public_key")
        return receipts.verify(raw["receipt"], raw["public_key"])

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _roles(document: dict[str, Any]) -> tuple[str, list[str]]:
        """Effective approval mode and approver roster of the current version.

        Documents written before approval modes existed carry no role fields
        and are read as legacy: the holders are the approvers.
        """
        mode = document.get("approval_mode", "legacy")
        if mode == "separated":
            return mode, list(document["approvers"])
        return "legacy", list(document["holders"])

    def _legacy_history(self, secret_id: str, upto: int) -> list[dict[str, Any]]:
        """Per-version role snapshots for a pre-roles document, all legacy."""
        rows = self.store.connection.execute(
            "SELECT version, holder FROM shares WHERE secret_id = ? AND version <= ? "
            "ORDER BY version, coordinate",
            (secret_id, upto),
        ).fetchall()
        history: list[dict[str, Any]] = []
        for row in rows:
            if not history or history[-1]["version"] != row["version"]:
                history.append({
                    "version": row["version"],
                    "approval_mode": "legacy",
                    "holders": [],
                    "approvers": [],
                })
            history[-1]["holders"].append(row["holder"])
            history[-1]["approvers"].append(row["holder"])
        return history

    def _source(self, seed: int | None) -> RandomSource:
        return SeededRandomSource(seed) if seed is not None else self.source

    def _issue(self, version: int, secret_id: str, holders: tuple[str, ...], points: list[tuple[int, int]]) -> None:
        for holder, (coordinate, value) in zip(holders, points):
            rendered = shamir.format_share(value)
            self.store.connection.execute(
                "INSERT INTO shares(share_id, secret_id, version, holder, coordinate, value, commitment, "
                "distributed_at, invalidated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (_share_id(secret_id, version, holder), secret_id, version, holder, coordinate, rendered,
                 _share_commitment(secret_id, version, holder, rendered)),
            )

    def _recover(self, secret_id: str, document: dict[str, Any]) -> bytes:
        rows = self.store.connection.execute(
            "SELECT coordinate, value FROM shares WHERE secret_id = ? AND version = ? ORDER BY coordinate LIMIT ?",
            (secret_id, document["version"], document["threshold"]),
        ).fetchall()
        if len(rows) < document["threshold"]:
            raise IntegrityFailure("stored shares are insufficient to re-share the current secret")
        points = [(int(row["coordinate"]), int(row["value"], 16)) for row in rows]
        try:
            return shamir.combine(points).to_bytes(document["secret_length"], "big")
        except OverflowError as error:
            raise IntegrityFailure("stored shares do not reproduce the recorded secret") from error

    def _record(self, secret_id: str, document: dict[str, Any] | None = None) -> dict[str, Any]:
        if document is None:
            document = self._document(secret_id)
        rows = self.store.connection.execute(
            "SELECT distributed_at FROM shares WHERE secret_id = ? AND version = ?",
            (secret_id, document["version"]),
        ).fetchall()
        recorded = self._approval_count(secret_id, document["version"])
        required = document["approvals_required"]
        mode, approvers = self._roles(document)
        return {
            "id": secret_id,
            "name": document["name"],
            "version": document["version"],
            "threshold": document["threshold"],
            "holders": list(document["holders"]),
            "approvals_required": required,
            "approval_mode": mode,
            "approvers": approvers,
            "share_count": len(rows),
            "distributed_shares": sum(1 for row in rows if row["distributed_at"] is not None),
            "approvals": {"recorded": recorded, "required": required, "satisfied": recorded >= required},
            "secret_length": document["secret_length"],
            "status": document["status"],
            "status_reason": document["status_reason"],
            "status_changed_at": document["status_changed_at"],
            "created_at": document["created_at"],
            "updated_at": document["updated_at"],
        }

    def _document(self, secret_id: str) -> dict[str, Any]:
        row = self.store.connection.execute("SELECT document FROM secrets WHERE id = ?", (secret_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"secret {secret_id} was not found")
        return self.store.decode(row["document"])

    def _approval_count(self, secret_id: str, version: int) -> int:
        row = self.store.connection.execute(
            "SELECT COUNT(*) AS total FROM approvals WHERE secret_id = ? AND version = ? AND consumed_at IS NULL",
            (secret_id, version),
        ).fetchone()
        return int(row["total"])

    def _authorize(
        self,
        secret_id: str,
        document: dict[str, Any],
        action: str,
        version: int,
        approvals: int,
        presented_shares: int,
    ) -> None:
        """Evaluate the persistent authorization policy, if one is attached.

        Runs only after the request, status, share and approval checks have
        passed. A denial is a custody decision: it is appended to the audit
        chain as ``authorization_denied`` and raised as ``policy_denied``, but
        consumes no approvals, moves no shares and stores no idempotency
        record. Facts are the pre-execution values; ``presented_shares`` is
        the number of distinct shares that passed validation (0 for rotation).
        """
        policy = document.get("policy")
        if policy is None:
            return
        facts = {
            "action": action,
            "version": version,
            "threshold": document["threshold"],
            "approvals": approvals,
            "presented_shares": presented_shares,
        }
        if evaluate_policy(policy, facts):
            return
        self._append(secret_id, "authorization_denied", {
            "action": action,
            "version": version,
            "presented_shares": presented_shares,
            "approvals": approvals,
        })
        raise PolicyDenied(f"the authorization policy of secret {secret_id} denies {action}")

    def _consume_approvals(self, secret_id: str, version: int, now: str, recorded: int, reason: str) -> None:
        self.store.connection.execute(
            "UPDATE approvals SET consumed_at = ? WHERE secret_id = ? AND version = ? AND consumed_at IS NULL",
            (now, secret_id, version),
        )
        self._append(secret_id, "approvals_consumed", {"version": version, "approvals": recorded, "reason": reason})

    def _audit_failure(self, secret_id: str, error: ThresholdSafeError, shares_provided: int) -> None:
        version = self._document(secret_id)["version"]
        with self.store.transaction():
            self._append(secret_id, "reconstruction_failed", {
                "version": version,
                "code": error.code,
                "shares_provided": shares_provided,
                "message": str(error),
            })

    def _append(self, secret_id: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        row = self.store.connection.execute(
            "SELECT hash FROM audit_events WHERE secret_id = ? ORDER BY sequence DESC LIMIT 1", (secret_id,)
        ).fetchone()
        previous = row["hash"] if row else ZERO_HASH
        sequence = self.store.connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence FROM audit_events WHERE secret_id = ?", (secret_id,)
        ).fetchone()["sequence"]
        occurred_at = self.store.now()
        encoded = self.store.encode(payload)
        event_hash = _event_hash(previous, sequence, event_type, encoded, occurred_at)
        self.store.connection.execute(
            "INSERT INTO audit_events(secret_id, sequence, type, payload, occurred_at, previous_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (secret_id, sequence, event_type, encoded, occurred_at, previous, event_hash),
        )
        return {
            "sequence": sequence,
            "type": event_type,
            "payload": payload,
            "occurred_at": occurred_at,
            "previous_hash": previous,
            "hash": event_hash,
        }

    def _idempotent(
        self,
        key: str | None,
        operation: str | Callable[[], str],
        action: Callable[[], dict[str, Any]],
        blocked: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        self._require_key(key)
        rejection: SecretFrozen | PolicyDenied | None = None
        with self.store.transaction() as connection:
            operation_name = operation() if callable(operation) else operation
            existing = connection.execute(
                "SELECT operation, response FROM idempotency WHERE key = ?", (key,)
            ).fetchone()
            if existing:
                if existing["operation"] != operation_name:
                    raise ConflictError("idempotency key was already used for another operation")
                return self.store.decode(existing["response"])
            try:
                response = action()
            except SecretFrozen as error:
                # The guard is the first thing the action checks, so nothing was
                # mutated. Commit (at most) the operation_blocked event, store no
                # idempotency record, and surface the rejection after commit.
                rejection = error
                if blocked is not None:
                    secret_id, operation_name_recorded = blocked
                    self._append(secret_id, "operation_blocked",
                                 {"operation": operation_name_recorded, "code": error.code})
            except PolicyDenied as error:
                # The action already appended its authorization_denied event;
                # commit that event but store no idempotency record, so a
                # retry with the same key re-evaluates the policy.
                rejection = error
            else:
                connection.execute(
                    "INSERT INTO idempotency(key, operation, response) VALUES (?, ?, ?)",
                    (key, operation_name, self.store.encode(response)),
                )
                return response
        assert rejection is not None
        raise rejection

    @staticmethod
    def _require_key(key: str | None) -> None:
        if not key:
            raise ValidationError("Idempotency-Key header is required")
