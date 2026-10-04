"""Ed25519 audit receipts: key handling, issuance payloads and verification.

A receipt is the service's signed statement that one audit event of one
secret stood at a particular position of the hash chain when the receipt was
issued. The service signs with a single Ed25519 key persisted in the
database (``receipt_keys``): the first process to open a database generates
the key inside one ``BEGIN IMMEDIATE`` transaction, so every later process
sharing the file — including processes that open a database written by an
older release — loads the same key. Only the public half is ever exposed;
the private half is stored in the database and appears in no response and
no backup.

``verify`` re-checks a receipt against a public key without touching any
service state: structural or encoding problems raise
:class:`ValidationError`, a well-formed receipt whose contents are
inconsistent answers ``{"valid": False, "reason": "receipt_integrity"}``,
and a bad Ed25519 signature answers ``{"valid": False, "reason":
"signature_mismatch"}``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .backup import encode, event_hash
from .errors import ValidationError
from .model import identifier, positive_int

ALGORITHM = "Ed25519"
NONCE_LIMIT = 128
PRIVATE_KEY_BYTES = 32
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64

B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
HEX_HASH = re.compile(r"^[0-9a-f]{64}$")

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


def b64encode(data: bytes) -> str:
    """URL-safe Base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64decode(value: Any, field: str, length: int) -> bytes:
    """Strict URL-safe unpadded Base64 decoding to exactly ``length`` bytes."""
    if not isinstance(value, str) or not B64URL.match(value) or len(value) % 4 == 1:
        raise ValidationError(f"{field} must be URL-safe base64 without padding")
    try:
        data = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValidationError(f"{field} must be URL-safe base64 without padding") from error
    if len(data) != length:
        raise ValidationError(f"{field} must decode to exactly {length} bytes")
    return data


def key_id_for(public_key: bytes) -> str:
    """The key identifier: SHA-256 of the raw public key, lowercase hex."""
    return hashlib.sha256(public_key).hexdigest()


class ReceiptKey:
    """The service's Ed25519 receipt-signing key.

    Only the public half ever leaves this class for a response; the private
    half is rendered solely for database persistence.
    """

    def __init__(self, private_bytes: bytes):
        self._private = Ed25519PrivateKey.from_private_bytes(private_bytes)
        self.public_bytes = self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key = b64encode(self.public_bytes)
        self.key_id = key_id_for(self.public_bytes)

    @classmethod
    def generate(cls) -> "ReceiptKey":
        private = Ed25519PrivateKey.generate().private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        return cls(private)

    @classmethod
    def load(cls, stored_private_key: str) -> "ReceiptKey":
        return cls(b64decode(stored_private_key, "private_key", PRIVATE_KEY_BYTES))

    @property
    def private_key(self) -> str:
        return b64encode(self._private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))

    def sign(self, message: bytes) -> str:
        return b64encode(self._private.sign(message))


def signing_payload(receipt: dict[str, Any]) -> bytes:
    """Canonical UTF-8 JSON of every receipt field except the signature."""
    return encode({field: value for field, value in receipt.items() if field != "signature"}).encode("utf-8")


def parse_request(raw: Any) -> tuple[int, str]:
    """The body of an issuance request: exactly ``sequence`` and ``nonce``."""
    if not isinstance(raw, dict) or set(raw) != {"sequence", "nonce"}:
        raise ValidationError("audit receipt body must contain exactly sequence and nonce")
    sequence = positive_int(raw["sequence"], "sequence", 1)
    nonce = raw["nonce"]
    if not isinstance(nonce, str) or not nonce:
        raise ValidationError("nonce must be a non-empty string")
    if len(nonce.encode("utf-8")) > NONCE_LIMIT:
        raise ValidationError(f"nonce must encode to at most {NONCE_LIMIT} UTF-8 bytes")
    return sequence, nonce


def _hash_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX_HASH.match(value):
        raise ValidationError(f"{field} must be a lowercase hexadecimal SHA-256 digest")
    return value


def _parse_event(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != EVENT_FIELDS:
        raise ValidationError(
            "receipt event must contain exactly sequence, type, payload, occurred_at, "
            "previous_hash and hash"
        )
    positive_int(raw["sequence"], "event sequence", 1)
    if not isinstance(raw["type"], str) or not raw["type"]:
        raise ValidationError("event type must be a non-empty string")
    if not isinstance(raw["payload"], dict):
        raise ValidationError("event payload must be an object")
    if not isinstance(raw["occurred_at"], str) or not raw["occurred_at"]:
        raise ValidationError("event occurred_at must be a non-empty string")
    _hash_text(raw["previous_hash"], "event previous_hash")
    _hash_text(raw["hash"], "event hash")
    return raw


def parse_receipt(raw: Any) -> dict[str, Any]:
    """Structural validation of a receipt; raises :class:`ValidationError`."""
    if not isinstance(raw, dict) or set(raw) != RECEIPT_FIELDS:
        raise ValidationError(
            "receipt must contain exactly algorithm, key_id, secret_id, event, nonce, "
            "head_sequence, head_hash and signature"
        )
    if raw["algorithm"] != ALGORITHM:
        raise ValidationError(f"receipt algorithm must be {ALGORITHM}")
    _hash_text(raw["key_id"], "receipt key_id")
    identifier(raw["secret_id"], "receipt secret_id")
    _parse_event(raw["event"])
    nonce = raw["nonce"]
    if not isinstance(nonce, str) or not nonce or len(nonce.encode("utf-8")) > NONCE_LIMIT:
        raise ValidationError(
            f"receipt nonce must be a non-empty string of at most {NONCE_LIMIT} UTF-8 bytes"
        )
    positive_int(raw["head_sequence"], "receipt head_sequence", 1)
    _hash_text(raw["head_hash"], "receipt head_hash")
    b64decode(raw["signature"], "receipt signature", SIGNATURE_BYTES)
    return raw


def verify(raw_receipt: Any, raw_public_key: Any) -> dict[str, Any]:
    """Independently verify a receipt against a public key.

    Pure: nothing is read from or written to any service state. Structural
    and encoding problems raise :class:`ValidationError`; content and
    signature mismatches answer ``valid: False`` with a reason.
    """
    receipt = parse_receipt(raw_receipt)
    public_key = b64decode(raw_public_key, "public_key", PUBLIC_KEY_BYTES)
    event = receipt["event"]
    expected = event_hash(
        event["previous_hash"], event["sequence"], event["type"],
        encode(event["payload"]), event["occurred_at"],
    )
    if event["hash"] != expected:
        return {"valid": False, "reason": "receipt_integrity"}
    # The issuance event is appended after the event it certifies, so the
    # head of a genuine receipt always sits above its target.
    if receipt["head_sequence"] <= event["sequence"]:
        return {"valid": False, "reason": "receipt_integrity"}
    if key_id_for(public_key) != receipt["key_id"]:
        return {"valid": False, "reason": "receipt_integrity"}
    signature = b64decode(receipt["signature"], "receipt signature", SIGNATURE_BYTES)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signing_payload(receipt))
    except InvalidSignature:
        return {"valid": False, "reason": "signature_mismatch"}
    return {"valid": True}
