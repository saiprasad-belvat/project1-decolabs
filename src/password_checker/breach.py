"""
breach.py
=========

OPTIONAL online breach check using the Have I Been Pwned (HIBP)
"Pwned Passwords" k-anonymity API.

PRIVACY DESIGN (critical)
---------------------------
- The plaintext password is NEVER transmitted.
- The password is hashed locally with SHA-1 (the algorithm HIBP's
  Pwned Passwords API is built around).
- Only the FIRST 5 CHARACTERS of the hex hash (the "prefix") are
  sent to the API. HIBP returns every suffix that shares that
  prefix, and the match is completed locally. This is the
  k-anonymity model: HIBP never sees enough of the hash to identify
  which exact password you checked.
- Nothing about the password or its hash is logged.
- This entire function is OPT-IN. It is never called unless the
  caller (the CLI, via --check-breach) explicitly requests it.
- Network failures are handled gracefully and never crash the
  analysis pipeline; the rest of the analysis does not depend on
  breach-check succeeding.

IMPORTANT HONESTY NOTE
------------------------
A password NOT found in this dataset is NOT proven safe. HIBP's
corpus, however large, is not exhaustive, and a password can still
be weak, guessable, or reused even if it has never appeared in a
breach that HIBP has ingested.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


@dataclass(frozen=True)
class BreachCheckResult:
    performed: bool
    breached: bool | None  # None if the check was not performed or failed
    error: str | None = None


def _sha1_hex_uppercase(password: str) -> str:
    """Locally hash the password with SHA-1 and return uppercase hex digest."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password_breach(password: str, timeout_seconds: float = 5.0) -> BreachCheckResult:
    """
    Perform the optional k-anonymity breach check.

    Only the 5-character SHA-1 prefix ever leaves this machine. The
    full hash and the plaintext password are used only locally and
    are discarded after this function returns.
    """
    try:
        import requests  # imported lazily: only needed for this optional feature
    except ImportError:
        return BreachCheckResult(
            performed=False,
            breached=None,
            error="The 'requests' package is not installed; breach check skipped.",
        )

    full_hash = _sha1_hex_uppercase(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    try:
        response = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            timeout=timeout_seconds,
            headers={"Add-Padding": "true"},  # mitigates response-size side channel
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        return BreachCheckResult(
            performed=False,
            breached=None,
            error=f"Breach check failed due to a network error: {exc.__class__.__name__}",
        )

    for line in response.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        returned_suffix, _count = parts
        if returned_suffix == suffix:
            return BreachCheckResult(performed=True, breached=True)

    return BreachCheckResult(performed=True, breached=False)
