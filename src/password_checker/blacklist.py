"""
blacklist.py
============

Loads the local common-password list (``data/common_passwords.txt``)
and checks whether a candidate password matches it.

LIMITATIONS (documented per project requirements)
--------------------------------------------------
This list is a small, hand-compiled, EDUCATIONAL sample of widely
publicized common passwords. It does NOT represent every password
ever leaked in a real-world breach, and a password's absence from
this list is not evidence that the password is safe or unique.
Real-world deployments would typically pair this kind of local
check with a much larger corpus and/or the optional online breach
check (see breach.py), which itself has its own documented limits.

DESIGN
------
The list is loaded once and cached in a set for O(1) average-case
membership testing, so checking a password against the blacklist
does not depend on the size of the wordlist at query time (only at
load time).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

DEFAULT_BLACKLIST_PATH = Path(__file__).resolve().parents[2] / "data" / "common_passwords.txt"


@lru_cache(maxsize=4)
def _load_blacklist(path_str: str) -> frozenset[str]:
    path = Path(path_str)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return frozenset()

    words = {
        line.strip().lower()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    }
    return frozenset(words)


def _strip_trailing_digits_and_symbols(password: str) -> str:
    """
    Strip a trailing run of digits and/or symbols, e.g. 'Password123!'
    -> 'Password'. This mirrors the well-known human habit of taking a
    common word and appending a year, a number, or '!' to satisfy
    character-class rules while keeping the guessable core unchanged.
    Bounded, single pass from the end of the string -- O(n).
    """
    end = len(password)
    while end > 0 and not password[end - 1].isalpha():
        end -= 1
    return password[:end]


def is_common_password(password: str, path: str | Path | None = None) -> bool:
    """
    Return True if `password` matches, or is a common-password-plus-
    trailing-digits/symbols variant of, an entry in the local
    common-password blacklist (e.g. 'password123!' is still flagged
    because its alphabetic core, 'password', is on the list).

    O(1) average-case lookup after the one-time O(m) load of the
    wordlist (m = wordlist size); the trailing-suffix strip is a
    single O(n) pass over the password.
    """
    target = str(path) if path is not None else str(DEFAULT_BLACKLIST_PATH)
    blacklist = _load_blacklist(target)

    lowered = password.lower()
    if lowered in blacklist:
        return True

    core = _strip_trailing_digits_and_symbols(lowered)
    if core and core != lowered and core in blacklist:
        return True

    return False
