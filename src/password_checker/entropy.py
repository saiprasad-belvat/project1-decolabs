"""
entropy.py
==========

Computes a THEORETICAL entropy estimate and an accompanying
theoretical brute-force time estimate.

IMPORTANT HONESTY NOTE
------------------------
This is a THEORETICAL estimate based on the classic formula:

    entropy_bits ≈ length * log2(character_set_size)

This formula assumes every character was chosen uniformly at random
from the detected character classes. Human-created passwords are
NOT random -- "Password123!" uses four character classes yet is
highly predictable, because humans favor dictionary words, names,
and predictable substitutions. Therefore:

  - This number must NEVER be presented as proof that a password is
    secure.
  - It must always be used as ONE input among several (see
    checker.py), alongside pattern detection and common-password
    checks, which catch exactly the kind of predictability that a
    pure entropy formula misses.
  - Crack-time estimates are similarly theoretical: they assume a
    configurable, assumed guesses-per-second rate against the full
    theoretical search space, not against real attacker behavior,
    which typically tries common/likely passwords first (much faster
    than a uniform random search would suggest).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .policy import EntropyPolicy, CrackTimePolicy


@dataclass(frozen=True)
class EntropyEstimate:
    bits: float
    character_set_size: int
    search_space: float  # 2 ** bits, as a float (can be astronomically large)


def estimate_entropy(
    password: str,
    has_uppercase: bool,
    has_lowercase: bool,
    has_digit: bool,
    has_symbol: bool,
    has_unicode: bool,
    entropy_policy: EntropyPolicy,
) -> EntropyEstimate:
    """
    Estimate theoretical entropy in bits using length * log2(pool size),
    where pool size is the sum of character-set sizes for every
    character class actually detected in the password.

    O(1): this function does not re-scan the password; it only uses
    the pre-computed length and character-class booleans (each of
    which was already computed once in O(n) by checker.py).
    """
    pool_size = 0
    if has_lowercase:
        pool_size += entropy_policy.lowercase_set_size
    if has_uppercase:
        pool_size += entropy_policy.uppercase_set_size
    if has_digit:
        pool_size += entropy_policy.digit_set_size
    if has_symbol:
        pool_size += entropy_policy.symbol_set_size
    if has_unicode:
        pool_size += entropy_policy.unicode_set_size

    length = len(password)

    if pool_size <= 0 or length == 0:
        return EntropyEstimate(bits=0.0, character_set_size=pool_size, search_space=0.0)

    bits = length * math.log2(pool_size)
    search_space = 2 ** bits if bits < 1024 else float("inf")  # guard float overflow
    return EntropyEstimate(bits=round(bits, 2), character_set_size=pool_size, search_space=search_space)


def estimate_crack_time_seconds(entropy: EntropyEstimate, crack_time_policy: CrackTimePolicy) -> float:
    """
    Theoretical brute-force time estimate = search_space / guess_rate.
    This is a rough order-of-magnitude figure, not a prediction of any
    specific real-world attack.
    """
    rate = crack_time_policy.assumed_guesses_per_second
    if rate <= 0 or entropy.search_space == float("inf"):
        return float("inf")
    return entropy.search_space / rate


def humanize_seconds(seconds: float) -> str:
    """Convert a seconds figure into a coarse, human-readable duration string."""
    if seconds == float("inf") or seconds != seconds:  # inf or NaN
        return "effectively unbounded (theoretical estimate)"
    if seconds < 1:
        return "less than 1 second (theoretical estimate)"

    units = [
        ("centuries", 60 * 60 * 24 * 365 * 100),
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            return f"~{value:,.1f} {name} (theoretical estimate)"
    return "less than 1 second (theoretical estimate)"
