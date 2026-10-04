"""Ed25519 audit receipts and their independent verifier.

A receipt attests that one event of a secret's hash-linked audit stream was
anchored by the service at issuance time: the service appends an
``audit_receipt_issued`` event to the chain and signs a receipt naming the
target event, the caller-supplied nonce and the new chain head. The signing
key is generated once, persisted in the database (so every instance serving
the same database signs with the same key) and never leaves the service:
responses and backups carry only the public key and its ``key_id``.

``verify`` re-checks a receipt without touching any service state. Structural
or encoding problems raise :class:`ValidationError`; a well-formed receipt
whose contents or signature do not check out is reported as ``valid: false``
with a ``reason`` of ``receipt_integrity`` or ``signature_mismatch``.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .backup import HEX_HASH, encode as canonical_json, event_hash
from .errors import ValidationError
from .model import positive_int

ALGORITHM = "Ed25519"
B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
NONCE_MAX_BYTES = 128

RECEIPT_FIELDS = {
    "algorithm",
    "key_id",
    "secret_id",
    "event",
    "nonce",
    "head_sequence",
    "head_hash",
    "signature",
}
EVENT_FIELDS = {"sequence", "type", "payload", "occurred_at", "previous_hash", "hash"}


def b64url_encode(raw: bytes) -> str:
    """URL-safe Base64 without padding."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: Any, field: str, length: int) -> bytes:
    if not isinstance(value, str) or not value or not B64URL.match(value):
        raise ValidationError(f"{field} must be URL-safe Base64 without padding")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != length:
        raise ValidationError(f"{field} must decode to exactly {length} bytes")
    return raw


def key_id_of(public_key: bytes) -> str:
    """The receipt key id: SHA-256 of the raw public key, lowercase hex."""
    return hashlib.sha256(public_key).hexdigest()


# ------------------------------------------------------------------ signing key
class ReceiptKey:
    """The service's Ed25519 receipt signing key, persisted in the database."""

    def __init__(self, seed: bytes, public_key: bytes):
        self.seed = seed
        self.public_key = public_key
        self.key_id = key_id_of(public_key)

    @classmethod
    def generate(cls) -> "ReceiptKey":
        private = Ed25519PrivateKey.generate()
        seed = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(seed, public)

    @classmethod
    def load(cls, private_key: str, public_key: str, key_id: str) -> "ReceiptKey":
        seed = base64.urlsafe_b64decode(private_key + "=" * (-len(private_key) % 4))
        public = base64.urlsafe_b64decode(public_key + "=" * (-len(public_key) % 4))
        loaded = cls(seed, public)
        if loaded.key_id != key_id:
            raise ValidationError("stored receipt signing key does not match its key_id")
        return loaded

    def info(self) -> dict[str, Any]:
        """The public description of the key; the private seed is never exposed."""
        return {"algorithm": ALGORITHM, "key_id": self.key_id, "public_key": b64url_encode(self.public_key)}

    def sign(self, receipt: dict[str, Any]) -> str:
        """Sign every receipt field but the signature itself, as canonical JSON."""
        payload = canonical_json({key: value for key, value in receipt.items() if key != "signature"})
        signature = Ed25519PrivateKey.from_private_bytes(self.seed).sign(payload.encode("utf-8"))
        return b64url_encode(signature)


# ------------------------------------------------------------------ verification
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


def _hash_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX_HASH.match(value):
        raise ValidationError(f"{field} must be a lowercase hexadecimal SHA-256 digest")
    return value


def check_nonce(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > NONCE_MAX_BYTES:
        raise ValidationError(f"nonce must be a non-empty string of at most {NONCE_MAX_BYTES} UTF-8 bytes")
    return value


def _parse_event(raw: Any) -> dict[str, Any]:
    event = _require_object(raw, EVENT_FIELDS, "receipt event")
    positive_int(event["sequence"], "event sequence", 1)
    _non_empty_text(event["type"], "event type")
    if not isinstance(event["payload"], dict):
        raise ValidationError("event payload must be an object")
    _non_empty_text(event["occurred_at"], "event occurred_at")
    _hash_text(event["previous_hash"], "event previous_hash")
    _hash_text(event["hash"], "event hash")
    return event


def _parse_receipt(raw: Any) -> dict[str, Any]:
    receipt = _require_object(raw, RECEIPT_FIELDS, "receipt")
    if receipt["algorithm"] != ALGORITHM:
        raise ValidationError(f"receipt algorithm must be {ALGORITHM}")
    _hash_text(receipt["key_id"], "receipt key_id")
    _non_empty_text(receipt["secret_id"], "receipt secret_id")
    _parse_event(receipt["event"])
    check_nonce(receipt["nonce"])
    positive_int(receipt["head_sequence"], "receipt head_sequence", 1)
    _hash_text(receipt["head_hash"], "receipt head_hash")
    _b64url_decode(receipt["signature"], "receipt signature", 64)
    return receipt


def verify(raw: Any) -> dict[str, Any]:
    """Independently verify a receipt without touching service state.

    Pure: nothing is read from or written to any managed data. Structural or
    encoding problems raise :class:`ValidationError`; content mismatches are
    reported as ``valid: false`` with a distinguishing ``reason``.
    """
    if not isinstance(raw, dict) or set(raw) != {"receipt", "public_key"}:
        raise ValidationError("receipt verification body must contain exactly receipt and public_key")
    receipt = _parse_receipt(raw["receipt"])
    public_key = _b64url_decode(raw["public_key"], "public_key", 32)

    event = receipt["event"]
    expected = event_hash(
        event["previous_hash"], event["sequence"], event["type"],
        canonical_json(event["payload"]), event["occurred_at"],
    )
    if event["hash"] != expected:
        return {"valid": False, "reason": "receipt_integrity"}
    if key_id_of(public_key) != receipt["key_id"]:
        return {"valid": False, "reason": "receipt_integrity"}

    signature = _b64url_decode(receipt["signature"], "receipt signature", 64)
    payload = canonical_json({key: value for key, value in receipt.items() if key != "signature"})
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload.encode("utf-8"))
    except InvalidSignature:
        return {"valid": False, "reason": "signature_mismatch"}
    return {"valid": True}
