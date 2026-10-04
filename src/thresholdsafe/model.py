from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .errors import ValidationError
from .policy import parse_policy
from .shamir import MAX_SECRET_BYTES

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHARE_VALUE = re.compile(r"^[0-9a-f]{1,132}$")

# Marks a rotation body that does not mention policy at all: the stored
# policy is then preserved, while an explicit null clears it.
UNSET: Any = object()


def identifier(value: Any, field: str, limit: int = 100) -> str:
    if not isinstance(value, str) or len(value) > limit or not IDENTIFIER.match(value):
        raise ValidationError(
            f"{field} must start with a letter or digit and contain only letters, digits, dot, "
            f"underscore or dash (at most {limit} characters)"
        )
    return value


def identifier_list(value: Any, field: str, noun: str = "holder") -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValidationError(f"{field} must be a non-empty array of {noun} identifiers")
    items = [identifier(entry, f"{field} entry") for entry in value]
    if len(set(items)) != len(items):
        raise ValidationError(f"{field} must not repeat the same {noun}")
    return items


def positive_int(value: Any, field: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError(f"{field} must be an integer greater than or equal to {minimum}")
    return value


def text(value: Any, field: str, limit: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValidationError(f"{field} must be a non-empty string of at most {limit} characters")
    return value


def seed_value(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63:
        raise ValidationError("seed must be an integer between 0 and 2**63")
    return value


def secret_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or value == "":
        raise ValidationError("secret must be a non-empty string")
    data = value.encode("utf-8")
    if len(data) > MAX_SECRET_BYTES:
        raise ValidationError(f"secret must encode to at most {MAX_SECRET_BYTES} bytes")
    return data


def single_field(raw: Any, field: str, description: str) -> str:
    if not isinstance(raw, dict) or set(raw) != {field}:
        raise ValidationError(f"{description} must contain exactly {field}")
    return identifier(raw[field], field)


def reason_field(raw: Any) -> str:
    if not isinstance(raw, dict) or set(raw) != {"reason"}:
        raise ValidationError("freeze request body must contain exactly reason")
    if not isinstance(raw["reason"], str):
        raise ValidationError("reason must be a non-empty string of at most 200 characters")
    reason = raw["reason"].strip()
    if not reason or len(reason) > 200:
        raise ValidationError("reason must be a non-empty string of at most 200 characters")
    return reason


def no_unknown_fields(raw: Any, allowed: set[str], description: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValidationError(f"{description} does not allow these fields: {', '.join(unknown)}")


@dataclass(frozen=True)
class ShareClaim:
    share_id: str
    value: str


def parse_share_claims(raw: Any) -> list[ShareClaim]:
    if not isinstance(raw, dict) or set(raw) != {"shares"}:
        raise ValidationError("reconstruct body must contain exactly shares")
    entries = raw["shares"]
    if not isinstance(entries, list) or not entries:
        raise ValidationError("shares must be a non-empty array")
    claims: list[ShareClaim] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"share_id", "value"}:
            raise ValidationError("each share must contain exactly share_id and value")
        value = entry["value"]
        if not isinstance(value, str) or not SHARE_VALUE.match(value):
            raise ValidationError("share value must be lowercase hexadecimal of at most 132 characters")
        claims.append(ShareClaim(identifier(entry["share_id"], "share_id", limit=250), value))
    if len({claim.share_id for claim in claims}) != len(claims):
        raise ValidationError("shares must not repeat the same share_id")
    return claims


def resolve_roles(
    threshold: int,
    holders: tuple[str, ...],
    approvals_required: int,
    approval_mode: str,
    approvers: tuple[str, ...],
) -> None:
    """Validate one version's custody configuration before it is stored.

    In ``legacy`` mode the approvers are the holders, so the quota is bounded
    by the roster. In ``separated`` mode the approver list must stand on its
    own: at least two distinct approvers, no overlap with the holders, and a
    quota that requires at least two of them.
    """
    if threshold > len(holders):
        raise ValidationError("threshold must not exceed the number of holders")
    if approval_mode == "separated":
        if len(approvers) < 2:
            raise ValidationError("separated approval mode requires at least two distinct approvers")
        overlap = sorted(set(approvers) & set(holders))
        if overlap:
            raise ValidationError(f"approvers must not overlap with holders: {', '.join(overlap)}")
        if not 2 <= approvals_required <= len(approvers):
            raise ValidationError("approvals_required must be between 2 and the number of approvers")
    elif approvals_required > len(holders):
        raise ValidationError("approvals_required must not exceed the number of holders")


@dataclass(frozen=True)
class SecretSpec:
    id: str
    name: str
    threshold: int
    holders: tuple[str, ...]
    approvals_required: int
    secret: bytes
    seed: int | None
    policy: dict[str, Any] | None
    approval_mode: str = "legacy"
    approvers: tuple[str, ...] = ()

    @classmethod
    def parse(cls, raw: Any) -> "SecretSpec":
        if not isinstance(raw, dict):
            raise ValidationError("secret definition must be an object")
        required = ["id", "name", "threshold", "holders", "approvals_required", "secret"]
        no_unknown_fields(raw, set(required) | {"seed", "policy", "approvers"}, "secret definition")
        missing = sorted(set(required) - set(raw))
        if missing:
            raise ValidationError(f"missing required fields: {', '.join(missing)}")
        holders = tuple(identifier_list(raw["holders"], "holders"))
        threshold = positive_int(raw["threshold"], "threshold", minimum=2)
        approvals_required = positive_int(raw["approvals_required"], "approvals_required", minimum=1)
        # Omitting approvers (or passing null) keeps the legacy mode in which
        # the holders approve; an explicit array enables separated mode.
        if raw.get("approvers") is not None:
            approval_mode = "separated"
            approvers = tuple(identifier_list(raw["approvers"], "approvers", noun="approver"))
        else:
            approval_mode = "legacy"
            approvers = holders
        resolve_roles(threshold, holders, approvals_required, approval_mode, approvers)
        return cls(
            identifier(raw["id"], "id"),
            text(raw["name"], "name"),
            threshold,
            holders,
            approvals_required,
            secret_bytes(raw["secret"]),
            seed_value(raw["seed"]) if "seed" in raw else None,
            parse_policy(raw["policy"]) if raw.get("policy") is not None else None,
            approval_mode,
            approvers,
        )


@dataclass(frozen=True)
class RotationSpec:
    """Optional overrides of a rotation; every field defaults to the current value.

    ``policy`` is UNSET when the body omits it (the stored policy is kept),
    None when the body clears it, and a validated expression otherwise.
    ``approvers`` follows the same shape: UNSET continues the current approval
    mode (legacy follows the final holders, separated keeps its roster), None
    switches back to legacy, and an array installs or updates separated mode.
    """

    secret: bytes | None
    threshold: int | None
    holders: tuple[str, ...] | None
    approvals_required: int | None
    seed: int | None
    policy: Any
    approvers: Any

    @classmethod
    def parse(cls, raw: Any) -> "RotationSpec":
        if not isinstance(raw, dict):
            raise ValidationError("rotation body must be an object")
        no_unknown_fields(
            raw,
            {"secret", "threshold", "holders", "approvals_required", "seed", "policy", "approvers"},
            "rotation body",
        )
        policy: Any = UNSET
        if "policy" in raw:
            policy = None if raw["policy"] is None else parse_policy(raw["policy"])
        approvers: Any = UNSET
        if "approvers" in raw:
            approvers = (
                None
                if raw["approvers"] is None
                else tuple(identifier_list(raw["approvers"], "approvers", noun="approver"))
            )
        return cls(
            secret_bytes(raw["secret"]) if "secret" in raw else None,
            positive_int(raw["threshold"], "threshold", minimum=2) if "threshold" in raw else None,
            tuple(identifier_list(raw["holders"], "holders")) if "holders" in raw else None,
            positive_int(raw["approvals_required"], "approvals_required", minimum=1)
            if "approvals_required" in raw
            else None,
            seed_value(raw["seed"]) if "seed" in raw else None,
            policy,
            approvers,
        )
