"""
patterns.py
===========

Detects predictable, low-entropy structural patterns in a password:
sequential runs (1234, abcd), repeated-character runs (aaaa, !!!!),
common keyboard-walk substrings (qwerty, asdf), and short cyclic
repetition (abcabcabc).

WHY THIS MATTERS
-----------------
Character-class checks alone are easily fooled. "Qwerty123!" satisfies
uppercase/lowercase/digit/symbol requirements yet is one of the most
guessed strings in the world. Pattern detection catches structural
predictability that character-class counting cannot.

SAFETY NOTES
------------
- No regular expressions with nested quantifiers or ambiguous
  backtracking are used anywhere in this module, to avoid ReDoS.
  All detection is done with plain iteration / string membership,
  which is inherently linear and has no catastrophic-backtracking
  failure mode.
- Callers are expected to cap password length upstream (see
  checker.py / policy.maximum_length) before calling these functions,
  bounding worst-case work even though each function here is already
  linear or near-linear in the input length.
"""

from __future__ import annotations

from dataclasses import dataclass

# Small, fixed set of well-known keyboard walks / extremely common
# predictable substrings. This is intentionally short and explicit --
# a fixed set of substring checks, not a regex, so there is no
# ambiguity about performance or behavior.
_KEYBOARD_PATTERNS: tuple[str, ...] = (
    "qwerty",
    "qwertyuiop",
    "asdf",
    "asdfgh",
    "zxcv",
    "qazwsx",
    "1qaz2wsx",
    "wasd",
)

_ASCII_LOWER = "abcdefghijklmnopqrstuvwxyz"
_ASCII_DIGITS = "0123456789"


@dataclass(frozen=True)
class DetectedPattern:
    kind: str
    description: str
    fragment: str


def _find_sequential_runs(password: str, min_run: int) -> list[DetectedPattern]:
    """
    Detect ascending sequential runs of letters or digits, e.g. '1234',
    'abcd'. Runs through the string once (O(n)) tracking whether each
    character continues an ascending sequence from the previous one.
    """
    findings: list[DetectedPattern] = []
    lowered = password.lower()
    n = len(lowered)
    i = 0
    while i < n:
        run_start = i
        j = i + 1
        while j < n and (
            (lowered[j].isalpha() and lowered[j - 1].isalpha() and
             ord(lowered[j]) - ord(lowered[j - 1]) == 1) or
            (lowered[j].isdigit() and lowered[j - 1].isdigit() and
             ord(lowered[j]) - ord(lowered[j - 1]) == 1)
        ):
            j += 1
        run_length = j - run_start
        if run_length >= min_run:
            fragment = password[run_start:j]
            findings.append(
                DetectedPattern(
                    kind="sequential",
                    description=f"Sequential pattern detected: {fragment}",
                    fragment=fragment,
                )
            )
        i = j if j > i + 1 else i + 1
    return findings


def _find_repeated_runs(password: str, min_run: int) -> list[DetectedPattern]:
    """
    Detect runs of the same character repeated min_run+ times,
    e.g. 'aaaa', '1111', '!!!!'. Single linear pass (O(n)).
    """
    findings: list[DetectedPattern] = []
    n = len(password)
    i = 0
    while i < n:
        j = i + 1
        while j < n and password[j] == password[i]:
            j += 1
        run_length = j - i
        if run_length >= min_run:
            fragment = password[i:j]
            findings.append(
                DetectedPattern(
                    kind="repeated_character",
                    description="Repeated-character pattern detected: "
                                 f"'{password[i]}' x{run_length}",
                    fragment=fragment,
                )
            )
        i = j
    return findings


def _find_keyboard_patterns(password: str) -> list[DetectedPattern]:
    """
    Detect a small fixed set of well-known keyboard-walk substrings.
    Plain substring membership checks -- linear in password length per
    pattern, and the pattern list is small and constant-size, so this
    is O(n * k) with k a small constant.
    """
    findings: list[DetectedPattern] = []
    lowered = password.lower()
    for kb in _KEYBOARD_PATTERNS:
        if kb in lowered:
            findings.append(
                DetectedPattern(
                    kind="keyboard_walk",
                    description=f"Common keyboard pattern detected: {kb}",
                    fragment=kb,
                )
            )
    return findings


def _find_cyclic_repetition(password: str, min_total_length: int = 6) -> list[DetectedPattern]:
    """
    Detect short cyclic repetition such as 'abcabcabc' -- a small
    substring (length 1-4) repeated back-to-back to cover most of the
    password. This is bounded (cycle length is capped at 4) so it does
    not add meaningful asymptotic cost: O(n) per candidate cycle
    length, times a constant (4) candidate cycle lengths.
    """
    findings: list[DetectedPattern] = []
    n = len(password)
    if n < min_total_length:
        return findings

    for cycle_len in range(1, 5):
        if cycle_len >= n:
            break
        unit = password[:cycle_len]
        repeats = 1
        pos = cycle_len
        while password[pos:pos + cycle_len] == unit:
            repeats += 1
            pos += cycle_len
        covered = repeats * cycle_len
        if repeats >= 3 and covered >= min_total_length and covered >= n * 0.75:
            findings.append(
                DetectedPattern(
                    kind="cyclic_repetition",
                    description=f"Repeated-sequence pattern detected: '{unit}' x{repeats}",
                    fragment=unit * repeats,
                )
            )
            break  # smallest matching cycle is the most informative
    return findings


def detect_patterns(
    password: str,
    min_sequential_run: int = 4,
    min_repeated_run: int = 4,
) -> list[DetectedPattern]:
    """
    Run all pattern detectors against the password and return every
    finding. Overall complexity is linear in password length (each
    sub-detector is O(n) or O(n*k) for small constant k); see
    README.md "Algorithmic Complexity" for the full breakdown.
    """
    findings: list[DetectedPattern] = []
    findings.extend(_find_sequential_runs(password, min_sequential_run))
    findings.extend(_find_repeated_runs(password, min_repeated_run))
    findings.extend(_find_keyboard_patterns(password))
    findings.extend(_find_cyclic_repetition(password))
    return findings
