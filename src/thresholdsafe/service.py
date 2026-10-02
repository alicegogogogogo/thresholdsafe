from __future__ import annotations

import hashlib
import sqlite3
from typing import Any, Callable

from . import shamir
from .errors import (
    BackupIntegrity,
    ConflictError,
    DuplicateApproval,
    InsufficientApprovals,
    InsufficientShares,
    IntegrityFailure,
    NotFoundError,
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
    RotationSpec,
    SecretSpec,
    ShareClaim,
    parse_share_claims,
    reason_field,
    resolve_policy,
    single_field,
)
from .shamir import RandomSource, SeededRandomSource, SystemRandomSource
from .store import Store

ZERO_HASH = "0" * 64

BACKUP_VERSION = "thresholdsafe-backup-v1"

# A backup document allows exactly these members at each level; anything
# missing, extra or mistyped is a validation error, not an integrity failure.
BACKUP_KEYS = {"backup_version", "generated_at", "secret", "shares", "approvals", "audit_events", "checksum"}
BACKUP_CONTENT_KEYS = ("backup_version", "generated_at", "secret", "shares", "approvals", "audit_events")
BACKUP_SECRET_KEYS = {
    "id", "name", "version", "threshold", "holders", "approvals_required", "secret_length",
    "secret_digest", "status", "status_reason", "status_changed_at", "created_at", "updated_at",
}
BACKUP_SHARE_KEYS = {
    "share_id", "holder", "version", "coordinate", "value", "commitment", "distributed_at", "invalidated_at",
}
BACKUP_APPROVAL_KEYS = {"version", "approver", "created_at", "consumed_at"}
BACKUP_EVENT_KEYS = {"sequence", "type", "payload", "occurred_at", "previous_hash", "hash"}

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


def _share_commitment(secret_id: str, version: int, holder: str, value: str) -> str:
    return hashlib.sha256(f"thresholdsafe:v1:share:{secret_id}:{version}:{holder}:{value}".encode()).hexdigest()


def _event_hash(previous: str, sequence: int, event_type: str, encoded: str, occurred_at: str) -> str:
    return hashlib.sha256(f"{previous}|{sequence}|{event_type}|{encoded}|{occurred_at}".encode()).hexdigest()


def _backup_checksum(backup: dict[str, Any]) -> str:
    # Only the member order and whitespace of the submitted document may vary:
    # the checksum is taken over the canonical re-encoding of the content.
    material = {key: backup[key] for key in BACKUP_CONTENT_KEYS}
    return hashlib.sha256(Store.encode(material).encode("utf-8")).hexdigest()


def _exact_keys(value: Any, keys: set[str], description: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValidationError(f"{description} must contain exactly {', '.join(sorted(keys))}")
    return value


def _str_member(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    return value


def _int_member(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    return value


def _optional_str_member(value: Any, field: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{field} must be a string or null")
    return value


class ThresholdSafe:
    def __init__(self, database: str, source: RandomSource | None = None):
        self.store = Store(database)
        self.source: RandomSource = source if source is not None else SystemRandomSource()

    # ------------------------------------------------------------------ create
    def create_secret(self, raw: Any, key: str | None) -> dict[str, Any]:
        spec = SecretSpec.parse(raw)

        def create() -> dict[str, Any]:
            now = self.store.now()
            points = shamir.split(spec.secret, spec.threshold, len(spec.holders), self._source(spec.seed))
            document = {
                "id": spec.id,
                "name": spec.name,
                "version": 1,
                "threshold": spec.threshold,
                "holders": list(spec.holders),
                "approvals_required": spec.approvals_required,
                "secret_digest": _secret_digest(spec.secret),
                "secret_length": len(spec.secret),
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
                "holders": list(spec.holders),
                "share_count": len(spec.holders),
                "secret_length": len(spec.secret),
                "deterministic": spec.seed is not None,
            })
            return self._record(spec.id)

        return self._idempotent(key, f"create-secret:{spec.id}", create)

    def get_secret(self, secret_id: str) -> dict[str, Any]:
        return self._record(secret_id)

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
            if approver not in document["holders"]:
                raise ValidationError(f"approver {approver} is not a registered holder of secret {secret_id}")
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
            self._append(secret_id, "approval_recorded",
                         {"approver": approver, "version": version, "approvals": recorded, "required": required})
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
            resolve_policy(threshold, holders, approvals_required)
            secret = spec.secret if spec.secret is not None else self._recover(secret_id, document)
            now = self.store.now()
            self._consume_approvals(secret_id, previous, now, recorded, "rotate")
            invalidated = self.store.connection.execute(
                "UPDATE shares SET invalidated_at = ? WHERE secret_id = ? AND version = ? AND invalidated_at IS NULL",
                (now, secret_id, previous),
            ).rowcount
            version = previous + 1
            self._issue(version, secret_id, holders, shamir.split(secret, threshold, len(holders), self._source(spec.seed)))
            document.update({
                "version": version,
                "threshold": threshold,
                "holders": list(holders),
                "approvals_required": approvals_required,
                "secret_digest": _secret_digest(secret),
                "secret_length": len(secret),
                "updated_at": now,
            })
            self.store.connection.execute(
                "UPDATE secrets SET document = ?, updated_at = ? WHERE id = ?",
                (self.store.encode(document), now, secret_id),
            )
            self._append(secret_id, "secret_rotated", {
                "version": version,
                "previous_version": previous,
                "threshold": threshold,
                "approvals_required": approvals_required,
                "holders": list(holders),
                "share_count": len(holders),
                "invalidated_shares": invalidated,
                "secret_changed": spec.secret is not None,
            })
            return self._record(secret_id)

        return self._idempotent(key, operation, apply, blocked=(secret_id, "rotate"))

    # -------------------------------------------------------------------- audit
    def audit(self, secret_id: str) -> dict[str, Any]:
        document = self._document(secret_id)
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
        return {
            "secret_id": secret_id,
            "version": document["version"],
            "chain_valid": chain_valid,
            "head_hash": previous,
            "events": events,
        }

    # ------------------------------------------------------------------ backup
    def export_backup(self, secret_id: str) -> dict[str, Any]:
        # Read-only: a frozen secret exports exactly like an active one, and
        # the plaintext secret is never part of the document, only its
        # commitment (digest) and byte length. Share values are included, so
        # a backup is sensitive material and must be handled accordingly.
        document = self._document(secret_id)
        shares = [
            {
                "share_id": row["share_id"],
                "holder": row["holder"],
                "version": row["version"],
                "coordinate": row["coordinate"],
                "value": row["value"],
                "commitment": row["commitment"],
                "distributed_at": row["distributed_at"],
                "invalidated_at": row["invalidated_at"],
            }
            for row in self.store.connection.execute(
                "SELECT share_id, holder, version, coordinate, value, commitment, distributed_at, "
                "invalidated_at FROM shares WHERE secret_id = ? ORDER BY version, coordinate",
                (secret_id,),
            ).fetchall()
        ]
        approvals = [
            {
                "version": row["version"],
                "approver": row["approver"],
                "created_at": row["created_at"],
                "consumed_at": row["consumed_at"],
            }
            for row in self.store.connection.execute(
                "SELECT version, approver, created_at, consumed_at FROM approvals "
                "WHERE secret_id = ? ORDER BY version, approver",
                (secret_id,),
            ).fetchall()
        ]
        events = [
            {
                "sequence": row["sequence"],
                "type": row["type"],
                "payload": self.store.decode(row["payload"]),
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
                "hash": row["hash"],
            }
            for row in self.store.connection.execute(
                "SELECT sequence, type, payload, occurred_at, previous_hash, hash FROM audit_events "
                "WHERE secret_id = ? ORDER BY sequence",
                (secret_id,),
            ).fetchall()
        ]
        backup = {
            "backup_version": BACKUP_VERSION,
            "generated_at": self.store.now(),
            "secret": {
                key: document[key]
                for key in (
                    "id", "name", "version", "threshold", "holders", "approvals_required",
                    "secret_length", "secret_digest", "status", "status_reason",
                    "status_changed_at", "created_at", "updated_at",
                )
            },
            "shares": shares,
            "approvals": approvals,
            "audit_events": events,
        }
        backup["checksum"] = _backup_checksum(backup)
        return backup

    def verify_backup(self, raw: Any) -> dict[str, Any]:
        # Pure function of the submitted backup: the service state is neither
        # read nor modified, no idempotency key is required, and nothing is
        # audited. A backup is either accepted whole or rejected whole.
        if not isinstance(raw, dict) or set(raw) != {"backup"}:
            raise ValidationError("verify body must contain exactly backup")
        backup = _exact_keys(raw["backup"], BACKUP_KEYS, "backup")
        if backup["backup_version"] != BACKUP_VERSION:
            raise ValidationError(f"backup_version must be {BACKUP_VERSION}")
        _str_member(backup["generated_at"], "generated_at")
        _str_member(backup["checksum"], "checksum")
        secret = self._backup_secret(backup["secret"])
        shares = self._backup_shares(backup["shares"])
        approvals = self._backup_approvals(backup["approvals"])
        events = self._backup_events(backup["audit_events"])
        self._check_backup_integrity(backup, secret, shares, approvals, events)
        return {
            "valid": True,
            "secret_id": secret["id"],
            "version": secret["version"],
            "share_count": len(shares),
            "approval_count": len(approvals),
            "event_count": len(events),
        }

    @staticmethod
    def _backup_secret(raw: Any) -> dict[str, Any]:
        secret = _exact_keys(raw, BACKUP_SECRET_KEYS, "backup secret")
        _str_member(secret["id"], "secret.id")
        _str_member(secret["name"], "secret.name")
        _int_member(secret["version"], "secret.version")
        _int_member(secret["threshold"], "secret.threshold")
        holders = secret["holders"]
        if not isinstance(holders, list) or not all(isinstance(holder, str) for holder in holders):
            raise ValidationError("secret.holders must be an array of strings")
        _int_member(secret["approvals_required"], "secret.approvals_required")
        _int_member(secret["secret_length"], "secret.secret_length")
        _str_member(secret["secret_digest"], "secret.secret_digest")
        _str_member(secret["status"], "secret.status")
        _optional_str_member(secret["status_reason"], "secret.status_reason")
        _str_member(secret["status_changed_at"], "secret.status_changed_at")
        _str_member(secret["created_at"], "secret.created_at")
        _str_member(secret["updated_at"], "secret.updated_at")
        return secret

    @staticmethod
    def _backup_shares(raw: Any) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            raise ValidationError("shares must be an array")
        shares = []
        for entry in raw:
            share = _exact_keys(entry, BACKUP_SHARE_KEYS, "backup share")
            _str_member(share["share_id"], "share.share_id")
            _str_member(share["holder"], "share.holder")
            _int_member(share["version"], "share.version")
            _int_member(share["coordinate"], "share.coordinate")
            _str_member(share["value"], "share.value")
            _str_member(share["commitment"], "share.commitment")
            _optional_str_member(share["distributed_at"], "share.distributed_at")
            _optional_str_member(share["invalidated_at"], "share.invalidated_at")
            shares.append(share)
        return shares

    @staticmethod
    def _backup_approvals(raw: Any) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            raise ValidationError("approvals must be an array")
        approvals = []
        for entry in raw:
            approval = _exact_keys(entry, BACKUP_APPROVAL_KEYS, "backup approval")
            _int_member(approval["version"], "approval.version")
            _str_member(approval["approver"], "approval.approver")
            _str_member(approval["created_at"], "approval.created_at")
            _optional_str_member(approval["consumed_at"], "approval.consumed_at")
            approvals.append(approval)
        return approvals

    @staticmethod
    def _backup_events(raw: Any) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            raise ValidationError("audit_events must be an array")
        events = []
        for entry in raw:
            event = _exact_keys(entry, BACKUP_EVENT_KEYS, "backup audit event")
            _int_member(event["sequence"], "audit event.sequence")
            _str_member(event["type"], "audit event.type")
            if not isinstance(event["payload"], dict):
                raise ValidationError("audit event.payload must be an object")
            _str_member(event["occurred_at"], "audit event.occurred_at")
            _str_member(event["previous_hash"], "audit event.previous_hash")
            _str_member(event["hash"], "audit event.hash")
            events.append(event)
        return events

    @staticmethod
    def _check_backup_integrity(
        backup: dict[str, Any],
        secret: dict[str, Any],
        shares: list[dict[str, Any]],
        approvals: list[dict[str, Any]],
        events: list[dict[str, Any]],
    ) -> None:
        if _backup_checksum(backup) != backup["checksum"]:
            raise BackupIntegrity("checksum does not match the backup content")
        secret_id = secret["id"]
        version = secret["version"]
        holders = secret["holders"]
        if not shares:
            raise BackupIntegrity("backup contains no shares")
        if not events:
            raise BackupIntegrity("backup contains no audit events")
        if len(set(holders)) != len(holders):
            raise BackupIntegrity("secret holders must not repeat the same holder")
        versions = sorted({share["version"] for share in shares})
        if versions != list(range(1, version + 1)):
            raise BackupIntegrity("share versions are not continuous from 1 to the current version")
        roster: dict[int, set[str]] = {}
        seen_shares: set[tuple[int, str]] = set()
        for share in shares:
            share_version, holder = share["version"], share["holder"]
            if (share_version, holder) in seen_shares:
                raise BackupIntegrity(f"version {share_version} carries more than one share for {holder}")
            seen_shares.add((share_version, holder))
            if share["share_id"] != _share_id(secret_id, share_version, holder):
                raise BackupIntegrity(f"share {share['share_id']} does not belong to secret {secret_id}")
            if share["commitment"] != _share_commitment(secret_id, share_version, holder, share["value"]):
                raise BackupIntegrity(f"share {share['share_id']} value does not match its commitment")
            roster.setdefault(share_version, set()).add(holder)
        if roster[version] != set(holders):
            raise BackupIntegrity("current version shares do not match the secret holder roster")
        seen_approvals: set[tuple[int, str]] = set()
        for approval in approvals:
            approval_version, approver = approval["version"], approval["approver"]
            if approver not in roster.get(approval_version, set()):
                raise BackupIntegrity(f"approver {approver} is not a holder of version {approval_version}")
            if (approval_version, approver) in seen_approvals:
                raise BackupIntegrity(f"approver {approver} approves version {approval_version} more than once")
            seen_approvals.add((approval_version, approver))
        previous = ZERO_HASH
        for sequence, event in enumerate(events, start=1):
            if event["sequence"] != sequence:
                raise BackupIntegrity("audit events are not strictly sequential from 1")
            encoded = Store.encode(event["payload"])
            if event["previous_hash"] != previous or event["hash"] != _event_hash(
                previous, sequence, event["type"], encoded, event["occurred_at"]
            ):
                raise BackupIntegrity(f"audit event {sequence} does not match the hash chain")
            previous = event["hash"]

    # ------------------------------------------------------------------ helpers
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
        return {
            "id": secret_id,
            "name": document["name"],
            "version": document["version"],
            "threshold": document["threshold"],
            "holders": list(document["holders"]),
            "approvals_required": required,
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

    def _append(self, secret_id: str, event_type: str, payload: dict[str, Any]) -> None:
        row = self.store.connection.execute(
            "SELECT hash FROM audit_events WHERE secret_id = ? ORDER BY sequence DESC LIMIT 1", (secret_id,)
        ).fetchone()
        previous = row["hash"] if row else ZERO_HASH
        sequence = self.store.connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence FROM audit_events WHERE secret_id = ?", (secret_id,)
        ).fetchone()["sequence"]
        occurred_at = self.store.now()
        encoded = self.store.encode(payload)
        self.store.connection.execute(
            "INSERT INTO audit_events(secret_id, sequence, type, payload, occurred_at, previous_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (secret_id, sequence, event_type, encoded, occurred_at, previous,
             _event_hash(previous, sequence, event_type, encoded, occurred_at)),
        )

    def _idempotent(
        self,
        key: str | None,
        operation: str | Callable[[], str],
        action: Callable[[], dict[str, Any]],
        blocked: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        self._require_key(key)
        frozen_error: SecretFrozen | None = None
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
                frozen_error = error
                if blocked is not None:
                    secret_id, operation_name_recorded = blocked
                    self._append(secret_id, "operation_blocked",
                                 {"operation": operation_name_recorded, "code": error.code})
            else:
                connection.execute(
                    "INSERT INTO idempotency(key, operation, response) VALUES (?, ?, ?)",
                    (key, operation_name, self.store.encode(response)),
                )
                return response
        assert frozen_error is not None
        raise frozen_error

    @staticmethod
    def _require_key(key: str | None) -> None:
        if not key:
            raise ValidationError("Idempotency-Key header is required")
