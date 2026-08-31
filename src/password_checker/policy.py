"""
policy.py
=========

Loads the configurable security policy from ``policy.json``.

WHY A CONFIGURABLE POLICY?
---------------------------
Security requirements are not universal constants. A banking application,
an internal admin tool, and a public forum may reasonably want different
minimum lengths, different scoring weights, or different guess-rate
assumptions for crack-time estimation. Hard-coding these values into the
Python source would force a code change (and a new deployment) every time
a security team wants to tighten or relax a rule.

By externalizing thresholds into ``policy.json`` we get:
  - auditability: a security reviewer can read the policy without reading code
  - safe tuning: non-developers can adjust thresholds
  - testability: tests can load alternate policies to verify behavior

This module is intentionally free of any password-handling logic --
it only loads and validates configuration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "policy.json"


@dataclass(frozen=True)
class ScoringPolicy:
    length_8: int = 1
    length_12: int = 1
    length_16: int = 1
    has_uppercase: int = 1
    has_lowercase: int = 1
    has_digit: int = 1
    has_symbol: int = 1
    no_common_password: int = 2
    no_pattern_detected: int = 1
    max_score: int = 10
    common_password_penalty: int = 5
    sequential_pattern_penalty: int = 2
    repeated_pattern_penalty: int = 2
    keyboard_pattern_penalty: int = 2


@dataclass(frozen=True)
class ClassificationThresholds:
    weak_below: int = 4
    medium_below: int = 7
    strong_below: int = 9
    very_strong_requires_no_issues: bool = True


@dataclass(frozen=True)
class EntropyPolicy:
    lowercase_set_size: int = 26
    uppercase_set_size: int = 26
    digit_set_size: int = 10
    symbol_set_size: int = 32
    unicode_set_size: int = 256


@dataclass(frozen=True)
class CrackTimePolicy:
    assumed_guesses_per_second: float = 1e10


@dataclass(frozen=True)
class PatternPolicy:
    min_sequential_run: int = 4
    min_repeated_run: int = 4


@dataclass(frozen=True)
class SecurityPolicy:
    """Immutable, validated representation of policy.json."""

    minimum_length: int = 8
    recommended_length: int = 12
    strong_length: int = 16
    maximum_length: int = 1000

    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_symbol: bool = True

    scoring: ScoringPolicy = field(default_factory=ScoringPolicy)
    classification_thresholds: ClassificationThresholds = field(
        default_factory=ClassificationThresholds
    )
    entropy: EntropyPolicy = field(default_factory=EntropyPolicy)
    crack_time: CrackTimePolicy = field(default_factory=CrackTimePolicy)
    pattern_detection: PatternPolicy = field(default_factory=PatternPolicy)

    def validate(self) -> None:
        """Raise ValueError if the policy is internally inconsistent."""
        if self.minimum_length < 1:
            raise ValueError("minimum_length must be >= 1")
        if self.maximum_length < self.minimum_length:
            raise ValueError("maximum_length must be >= minimum_length")
        if self.recommended_length < self.minimum_length:
            raise ValueError("recommended_length must be >= minimum_length")
        if self.strong_length < self.recommended_length:
            raise ValueError("strong_length must be >= recommended_length")
        if self.scoring.max_score <= 0:
            raise ValueError("scoring.max_score must be > 0")


def _strip_comments(data: dict[str, Any]) -> dict[str, Any]:
    """Remove any '_comment' documentation keys before dataclass construction."""
    return {k: v for k, v in data.items() if k != "_comment"}


def load_policy(path: str | Path | None = None) -> SecurityPolicy:
    """
    Load and validate a SecurityPolicy from a JSON file.

    Falls back to the default policy.json shipped with the project, and
    falls back further to built-in dataclass defaults if the file is
    missing or malformed (fail-safe: the analyzer should still function
    with sane defaults rather than crash).
    """
    target = Path(path) if path is not None else DEFAULT_POLICY_PATH

    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        policy = SecurityPolicy()
        policy.validate()
        return policy

    raw = _strip_comments(raw)

    scoring_raw = _strip_comments(raw.pop("scoring", {}))
    thresholds_raw = _strip_comments(raw.pop("classification_thresholds", {}))
    entropy_raw = _strip_comments(raw.pop("entropy", {}))
    crack_time_raw = _strip_comments(raw.pop("crack_time", {}))
    pattern_raw = _strip_comments(raw.pop("pattern_detection", {}))

    policy = SecurityPolicy(
        **{k: v for k, v in raw.items() if k in SecurityPolicy.__dataclass_fields__},
        scoring=ScoringPolicy(
            **{k: v for k, v in scoring_raw.items() if k in ScoringPolicy.__dataclass_fields__}
        ),
        classification_thresholds=ClassificationThresholds(
            **{
                k: v
                for k, v in thresholds_raw.items()
                if k in ClassificationThresholds.__dataclass_fields__
            }
        ),
        entropy=EntropyPolicy(
            **{k: v for k, v in entropy_raw.items() if k in EntropyPolicy.__dataclass_fields__}
        ),
        crack_time=CrackTimePolicy(
            **{
                k: v
                for k, v in crack_time_raw.items()
                if k in CrackTimePolicy.__dataclass_fields__
            }
        ),
        pattern_detection=PatternPolicy(
            **{k: v for k, v in pattern_raw.items() if k in PatternPolicy.__dataclass_fields__}
        ),
    )
    policy.validate()
    return policy
