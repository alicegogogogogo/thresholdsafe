"""Persistent authorization policies for reconstruction and rotation.

A policy is a strict JSON expression stored on the secret. Each node is an
object with exactly one key:

- ``{"all": [node, ...]}`` — every child must hold (non-empty array);
- ``{"any": [node, ...]}`` — at least one child must hold (non-empty array);
- ``{"not": node}`` — the single child must not hold;
- ``{"fact": {"fact": name, "op": op, "value": value}}`` — compare one
  execution fact against a constant.

Facts are ``action`` (``"reconstruct"`` or ``"rotate"``, supporting only
``eq``/``ne``) and the non-negative integers ``version``, ``threshold``,
``approvals`` and ``presented_shares`` (supporting ``eq``, ``ne``, ``gte``,
``lte``). ``parse`` validates an expression and raises
:class:`ValidationError` on any structural or typing problem; ``evaluate``
assumes a validated expression.
"""

from __future__ import annotations

from typing import Any

from .errors import ValidationError

OPERATORS = ("all", "any", "not", "fact")
FACTS = ("action", "version", "threshold", "approvals", "presented_shares")
ACTIONS = ("reconstruct", "rotate")
EQUALITY_OPS = ("eq", "ne")
ORDERING_OPS = ("eq", "ne", "gte", "lte")


def parse(expression: Any) -> dict[str, Any] | None:
    """Validate a policy expression, returning it unchanged; null stays null."""
    if expression is None:
        return None
    _validate_node(expression, "policy")
    return expression


def _validate_node(node: Any, description: str) -> None:
    if not isinstance(node, dict) or len(node) != 1:
        raise ValidationError(f"{description} must be an object with exactly one of all, any, not, fact")
    operator = next(iter(node))
    value = node[operator]
    if operator in ("all", "any"):
        if not isinstance(value, list) or not value:
            raise ValidationError(f"{operator} must be a non-empty array of policy nodes")
        for child in value:
            _validate_node(child, f"{operator} child")
    elif operator == "not":
        _validate_node(value, "not child")
    elif operator == "fact":
        _validate_fact(value)
    else:
        raise ValidationError(f"unknown policy operator {operator!r}; expected one of all, any, not, fact")


def _validate_fact(node: Any) -> None:
    if not isinstance(node, dict) or set(node) != {"fact", "op", "value"}:
        raise ValidationError("fact must be an object with exactly fact, op and value")
    fact, op, value = node["fact"], node["op"], node["value"]
    if fact not in FACTS:
        raise ValidationError(f"unknown fact {fact!r}; expected one of {', '.join(FACTS)}")
    if fact == "action":
        if op not in EQUALITY_OPS:
            raise ValidationError("action supports only eq and ne")
        if value not in ACTIONS:
            raise ValidationError('action value must be "reconstruct" or "rotate"')
    else:
        if op not in ORDERING_OPS:
            raise ValidationError(f"{fact} supports only eq, ne, gte and lte")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValidationError(f"{fact} value must be a non-negative integer")


def evaluate(node: dict[str, Any], facts: dict[str, Any]) -> bool:
    """Evaluate a validated policy expression against the execution facts."""
    operator = next(iter(node))
    value = node[operator]
    if operator == "all":
        return all(evaluate(child, facts) for child in value)
    if operator == "any":
        return any(evaluate(child, facts) for child in value)
    if operator == "not":
        return not evaluate(value, facts)
    actual = facts[value["fact"]]
    op, expected = value["op"], value["value"]
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "gte":
        return actual >= expected
    return actual <= expected
