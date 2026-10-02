"""Self-contained backup format and its independent verifier.

A backup exported by ``ThresholdSafe.export_backup`` carries everything needed
to reconstruct the custody state of one secret — the secret record (without
the plaintext secret), every share of every version, all approvals and the
full audit stream — plus a SHA-256 checksum over the remaining top-level
values. ``verify`` re-checks such a document without touching any service
state: structural problems raise :class:`ValidationError`, while a
well-formed document whose contents are inconsistent raises
:class:`BackupIntegrity`.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .errors import BackupIntegrity, ValidationError
from .model import identifier, positive_int
from .policy import parse as parse_policy

BACKUP_VERSION_V1 = "thresholdsafe-backup-v1"
BACKUP_VERSION = "thresholdsafe-backup-v2"
ZERO_HASH = "0" * 64
HEX_HASH = re.compile(r"^[0-9a-f]{64}$")
SHARE_VALUE = re.compile(r"^[0-9a-f]{1,132}$")

TOP_LEVEL_FIELDS = {
    "backup_version",
    "generated_at",
    "secret",
    "shares",
    "approvals",
    "audit_events",
    "checksum",
}
TOP_LEVEL_FIELDS_V2 = TOP_LEVEL_FIELDS | {"authorization_policy"}
SECRET_FIELDS = {
    "id",
    "name",
    "version",
    "threshold",
    "holders",
    "approvals_required",
    "secret_digest",
    "secret_length",
    "status",
    "status_reason",
    "status_changed_at",
    "status_epoch",
    "created_at",
    "updated_at",
}
SHARE_FIELDS = {
    "share_id",
    "secret_id",
    "version",
    "holder",
    "coordinate",
    "value",
    "commitment",
    "distributed_at",
    "invalidated_at",
}
APPROVAL_FIELDS = {"secret_id", "version", "approver", "created_at", "consumed_at"}
EVENT_FIELDS = {"sequence", "type", "payload", "occurred_at", "previous_hash", "hash"}


def encode(value: Any) -> str:
    """Canonical JSON: sorted keys, compact separators, no ASCII escaping."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def share_commitment(secret_id: str, version: int, holder: str, value: str) -> str:
    return hashlib.sha256(
        f"thresholdsafe:v1:share:{secret_id}:{version}:{holder}:{value}".encode()
    ).hexdigest()


def event_hash(previous: str, sequence: int, event_type: str, encoded: str, occurred_at: str) -> str:
    return hashlib.sha256(f"{previous}|{sequence}|{event_type}|{encoded}|{occurred_at}".encode()).hexdigest()


def checksum(unsigned: dict[str, Any]) -> str:
    """SHA-256 of the canonical encoding of every top-level value but the checksum."""
    return hashlib.sha256(encode(unsigned).encode()).hexdigest()


def stamp(backup: dict[str, Any]) -> dict[str, Any]:
    """Attach the checksum covering the other top-level values of a backup."""
    backup["checksum"] = checksum(backup)
    return backup


# ------------------------------------------------------------------ structure
def _require_object(raw: Any, fields: set[str], description: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValidationError(f"{description} must be an object")
    missing = sorted(fields - set(raw))
    if missing:
        raise ValidationError(f"{description} is missing required fields: {', '.join(missing)}")
    extra = sorted(set(raw) - fields)
    if extra:
        raise ValidationError(f"{description} does not allow these fields: {', '.join(extra)}")
    return raw


def _non_empty_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def _optional_text(value: Any, field: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{field} must be a string or null")
    return value


def _hash_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX_HASH.match(value):
        raise ValidationError(f"{field} must be a lowercase hexadecimal SHA-256 digest")
    return value


def _parse_secret(raw: Any) -> dict[str, Any]:
    secret = _require_object(raw, SECRET_FIELDS, "secret")
    identifier(secret["id"], "secret id")
    _non_empty_text(secret["name"], "secret name")
    positive_int(secret["version"], "secret version", 1)
    positive_int(secret["threshold"], "secret threshold", 2)
    positive_int(secret["approvals_required"], "secret approvals_required", 1)
    holders = secret["holders"]
    if not isinstance(holders, list) or not holders or any(not isinstance(h, str) for h in holders):
        raise ValidationError("secret holders must be a non-empty array of holder identifiers")
    if len(set(holders)) != len(holders):
        raise ValidationError("secret holders must not repeat the same holder")
    _hash_text(secret["secret_digest"], "secret_digest")
    positive_int(secret["secret_length"], "secret_length", 1)
    if secret["status"] not in ("active", "frozen"):
        raise ValidationError("secret status must be active or frozen")
    _optional_text(secret["status_reason"], "status_reason")
    epoch = secret["status_epoch"]
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise ValidationError("status_epoch must be a non-negative integer")
    _non_empty_text(secret["status_changed_at"], "status_changed_at")
    _non_empty_text(secret["created_at"], "created_at")
    _non_empty_text(secret["updated_at"], "updated_at")
    return secret


def _parse_share(raw: Any) -> dict[str, Any]:
    share = _require_object(raw, SHARE_FIELDS, "share")
    identifier(share["share_id"], "share_id", limit=250)
    identifier(share["secret_id"], "share secret_id")
    identifier(share["holder"], "share holder")
    positive_int(share["version"], "share version", 1)
    positive_int(share["coordinate"], "share coordinate", 1)
    value = share["value"]
    if not isinstance(value, str) or not SHARE_VALUE.match(value):
        raise ValidationError("share value must be lowercase hexadecimal of at most 132 characters")
    _hash_text(share["commitment"], "share commitment")
    _optional_text(share["distributed_at"], "distributed_at")
    _optional_text(share["invalidated_at"], "invalidated_at")
    return share


def _parse_approval(raw: Any) -> dict[str, Any]:
    approval = _require_object(raw, APPROVAL_FIELDS, "approval")
    identifier(approval["secret_id"], "approval secret_id")
    identifier(approval["approver"], "approver")
    positive_int(approval["version"], "approval version", 1)
    _non_empty_text(approval["created_at"], "created_at")
    _optional_text(approval["consumed_at"], "consumed_at")
    return approval


def _parse_event(raw: Any) -> dict[str, Any]:
    event = _require_object(raw, EVENT_FIELDS, "audit event")
    positive_int(event["sequence"], "event sequence", 1)
    _non_empty_text(event["type"], "event type")
    if not isinstance(event["payload"], dict):
        raise ValidationError("event payload must be an object")
    _non_empty_text(event["occurred_at"], "occurred_at")
    _hash_text(event["previous_hash"], "event previous_hash")
    _hash_text(event["hash"], "event hash")
    return event


def _parse(backup: Any) -> dict[str, Any]:
    if not isinstance(backup, dict):
        raise ValidationError("backup must be an object")
    version = backup.get("backup_version")
    if version == BACKUP_VERSION_V1:
        fields = TOP_LEVEL_FIELDS
    elif version == BACKUP_VERSION:
        fields = TOP_LEVEL_FIELDS_V2
    elif "backup_version" not in backup:
        raise ValidationError("backup is missing required fields: backup_version")
    else:
        raise ValidationError(f"backup_version must be {BACKUP_VERSION_V1} or {BACKUP_VERSION}")
    document = _require_object(backup, fields, "backup")
    if version == BACKUP_VERSION:
        # The policy is part of the v2 structure: a syntactically invalid
        # expression makes the document malformed, not merely inconsistent.
        parse_policy(document["authorization_policy"])
    _non_empty_text(document["generated_at"], "generated_at")
    _hash_text(document["checksum"], "checksum")
    shares = document["shares"]
    if not isinstance(shares, list):
        raise ValidationError("shares must be an array")
    approvals = document["approvals"]
    if not isinstance(approvals, list):
        raise ValidationError("approvals must be an array")
    events = document["audit_events"]
    if not isinstance(events, list):
        raise ValidationError("audit_events must be an array")
    return {
        "raw": document,
        "secret": _parse_secret(document["secret"]),
        "shares": [_parse_share(entry) for entry in shares],
        "approvals": [_parse_approval(entry) for entry in approvals],
        "audit_events": [_parse_event(entry) for entry in events],
    }


# ------------------------------------------------------------------ integrity
def _check_integrity(parsed: dict[str, Any]) -> None:
    raw = parsed["raw"]
    unsigned = {key: value for key, value in raw.items() if key != "checksum"}
    if raw["checksum"] != checksum(unsigned):
        raise BackupIntegrity("checksum does not match the backup contents")

    secret = parsed["secret"]
    secret_id = secret["id"]
    current = secret["version"]
    shares = parsed["shares"]
    for share in shares:
        if share["secret_id"] != secret_id:
            raise BackupIntegrity(f"share {share['share_id']} does not belong to secret {secret_id}")
        if share["share_id"] != f"{secret_id}.v{share['version']}.{share['holder']}":
            raise BackupIntegrity(
                f"share {share['share_id']} does not match its secret, version and holder"
            )
        expected = share_commitment(secret_id, share["version"], share["holder"], share["value"])
        if share["commitment"] != expected:
            raise BackupIntegrity(f"share {share['share_id']} value does not match its commitment")

    if {share["version"] for share in shares} != set(range(1, current + 1)):
        raise BackupIntegrity("shares do not cover every version from 1 to the current version")
    roster: dict[int, set[str]] = {}
    for share in shares:
        roster.setdefault(share["version"], set()).add(share["holder"])

    for approval in parsed["approvals"]:
        if approval["secret_id"] != secret_id:
            raise BackupIntegrity(f"approval by {approval['approver']} does not belong to secret {secret_id}")
        if not 1 <= approval["version"] <= current:
            raise BackupIntegrity(
                f"approval by {approval['approver']} targets a version outside 1..{current}"
            )
        if approval["approver"] not in roster[approval["version"]]:
            raise BackupIntegrity(
                f"approver {approval['approver']} is not a holder of version {approval['version']}"
            )

    previous = ZERO_HASH
    for index, event in enumerate(parsed["audit_events"], start=1):
        if event["sequence"] != index:
            raise BackupIntegrity("audit events are not an unbroken sequence starting at 1")
        expected = event_hash(
            event["previous_hash"], event["sequence"], event["type"],
            encode(event["payload"]), event["occurred_at"],
        )
        if event["previous_hash"] != previous or event["hash"] != expected:
            raise BackupIntegrity("audit chain hashes do not match the recorded events")
        previous = event["hash"]


def verify(backup: Any) -> dict[str, Any]:
    """Validate a backup document and return a summary of its contents.

    Pure: nothing is read from or written to any service state, and the
    document is either accepted as a whole or rejected as a whole.
    """
    parsed = _parse(backup)
    _check_integrity(parsed)
    secret = parsed["secret"]
    return {
        "valid": True,
        "secret_id": secret["id"],
        "version": secret["version"],
        "share_count": len(parsed["shares"]),
        "approval_count": len(parsed["approvals"]),
        "event_count": len(parsed["audit_events"]),
    }
