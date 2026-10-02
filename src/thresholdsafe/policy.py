"""Persistent authorization policies for reconstruction and rotation.

A policy is a strict JSON expression tree stored on the secret. Interior
nodes combine children with ``all``/``any``/``not``; leaf nodes are ``fact``
comparisons over the facts of one attempted action (``action``, ``version``,
``threshold``, ``approvals``, ``presented_shares``). Policies are validated
when attached to a secret — at creation, at rotation, or inside a v2 backup —
and evaluated only after every pre-existing check (request shape, status,
shares and approvals) has passed, so a secret without a policy behaves
exactly as before.
"""

from __future__ import annotations

from typing import Any

from .errors import ValidationError

ACTIONS = ("reconstruct", "rotate")
INTEGER_FACTS = ("version", "threshold", "approvals", "presented_shares")
FACTS = ("action",) + INTEGER_FACTS
EQUALITY_OPS = ("eq", "ne")
COMPARISON_OPS = EQUALITY_OPS + ("gte", "lte")


def parse_policy(raw: Any) -> dict[str, Any]:
    """Validate a policy expression and return it unchanged."""
    _node(raw, "policy")
    return raw


def _node(raw: Any, description: str) -> None:
    if not isinstance(raw, dict) or len(raw) != 1:
        raise ValidationError(
            f"{description} node must be an object with exactly one of all, any, not, fact"
        )
    operator, value = next(iter(raw.items()))
    if operator in ("all", "any"):
        if not isinstance(value, list) or not value:
            raise ValidationError(f"{operator} must be a non-empty array of policy nodes")
        for child in value:
            _node(child, operator)
    elif operator == "not":
        _node(value, "not")
    elif operator == "fact":
        _fact(value)
    else:
        raise ValidationError(f"policy node does not allow the field {operator}")


def _fact(raw: Any) -> None:
    if not isinstance(raw, dict) or set(raw) != {"fact", "op", "value"}:
        raise ValidationError("fact node must contain exactly fact, op and value")
    fact, op, value = raw["fact"], raw["op"], raw["value"]
    if fact not in FACTS:
        raise ValidationError(f"fact must be one of {', '.join(FACTS)}")
    if fact == "action":
        if op not in EQUALITY_OPS:
            raise ValidationError("action supports only the ops eq and ne")
        if value not in ACTIONS:
            raise ValidationError("action value must be reconstruct or rotate")
        return
    if op not in COMPARISON_OPS:
        raise ValidationError(f"{fact} supports the ops eq, ne, gte and lte")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError(f"{fact} value must be a non-negative integer")


def evaluate(policy: dict[str, Any], facts: dict[str, Any]) -> bool:
    """Evaluate a validated policy against the facts of one attempted action."""
    operator, value = next(iter(policy.items()))
    if operator == "all":
        return all(evaluate(child, facts) for child in value)
    if operator == "any":
        return any(evaluate(child, facts) for child in value)
    if operator == "not":
        return not evaluate(value, facts)
    leaf = value
    actual = facts[leaf["fact"]]
    op, expected = leaf["op"], leaf["value"]
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "gte":
        return actual >= expected
    return actual <= expected
