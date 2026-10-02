"""Integer-only Shamir (k, n) secret sharing.

Every operation in this module is plain Python integer arithmetic modulo a
fixed prime. There is no third-party dependency, no constant-time machinery,
and no attempt to resist side channels: read the security note in the README
before treating any of this as production cryptography.
"""

from __future__ import annotations

import random
import secrets
from typing import Protocol, Sequence

# Mersenne prime M521. Secrets are limited to MAX_SECRET_BYTES so that the
# secret integer is always strictly below the prime.
PRIME = (1 << 521) - 1
MAX_SECRET_BYTES = 64
SHARE_HEX_LENGTH = 132  # 66 bytes == ceil(521 / 8) bytes, as lowercase hex


class RandomSource(Protocol):
    """The only thing the sharing code needs from a randomness source."""

    def randbelow(self, bound: int) -> int:
        """Return a uniformly random integer in ``[0, bound)``."""


class SystemRandomSource:
    """Default source, backed by operating-system entropy."""

    def randbelow(self, bound: int) -> int:
        return secrets.randbelow(bound)


class SeededRandomSource:
    """Deterministic source used by tests and by explicit ``seed`` requests.

    Seeded output is reproducible but not unpredictable, so it must never be
    used to protect a real secret.
    """

    def __init__(self, seed: int):
        self._random = random.Random(seed)

    def randbelow(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError("bound must be positive")
        return self._random.randrange(bound)


def format_share(value: int) -> str:
    """Render a share value as fixed-width lowercase hexadecimal."""
    return value.to_bytes(SHARE_HEX_LENGTH // 2, "big").hex()


def split(secret: bytes, threshold: int, count: int, source: RandomSource) -> list[tuple[int, int]]:
    """Return ``count`` points ``(x, f(x))`` of a random degree ``threshold - 1`` polynomial.

    ``f(0)`` is the secret integer. Exactly ``threshold`` points determine
    ``f``; any smaller subset is consistent with every possible secret.
    """
    if not 1 <= threshold <= count:
        raise ValueError("threshold must be between 1 and the number of shares")
    value = int.from_bytes(secret, "big")
    if value >= PRIME:
        raise ValueError("secret does not fit in the sharing field")
    coefficients = [value] + [source.randbelow(PRIME - 1) + 1 for _ in range(threshold - 1)]
    points: list[tuple[int, int]] = []
    for coordinate in range(1, count + 1):
        accumulator = 0
        for coefficient in reversed(coefficients):
            accumulator = (accumulator * coordinate + coefficient) % PRIME
        points.append((coordinate, accumulator))
    return points


def combine(points: Sequence[tuple[int, int]]) -> int:
    """Recover ``f(0)`` from points by Lagrange interpolation at zero."""
    if not points:
        raise ValueError("at least one share is required")
    coordinates = [coordinate for coordinate, _ in points]
    if len(set(coordinates)) != len(coordinates):
        raise ValueError("share coordinates must be distinct")
    secret = 0
    for index, (coordinate, value) in enumerate(points):
        numerator = 1
        denominator = 1
        for other, (other_coordinate, _) in enumerate(points):
            if other == index:
                continue
            numerator = numerator * (-other_coordinate) % PRIME
            denominator = denominator * (coordinate - other_coordinate) % PRIME
        secret = (secret + value * numerator * pow(denominator, -1, PRIME)) % PRIME
    return secret
