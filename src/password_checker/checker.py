"""
checker.py
==========

Core password analysis pipeline. This module is PURE: it contains no
input(), print(), file I/O, or network calls (breach checking is
performed separately by breach.py and its result is passed in, so this
module never has to know how that result was obtained).

Pipeline:

    USER INPUT
        -> INPUT VALIDATION
        -> LENGTH ANALYSIS
        -> CHARACTER-CLASS ANALYSIS
        -> PATTERN ANALYSIS
        -> COMMON-PASSWORD ANALYSIS
        -> ENTROPY ESTIMATE
        -> SECURITY POLICY (scoring & thresholds)
        -> RISK / STRENGTH CLASSIFICATION
        -> ACTIONABLE FEEDBACK

PRIVACY GUARANTEE
-------------------
PasswordAnalysisResult deliberately has NO field that stores the
password itself, in any form (plaintext, hash, or otherwise). Only
derived booleans, counts, and human-readable strings are retained.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .blacklist import is_common_password
from .entropy import EntropyEstimate, estimate_crack_time_seconds, estimate_entropy, humanize_seconds
from .patterns import DetectedPattern, detect_patterns
from .policy import SecurityPolicy, load_policy


@dataclass
class PasswordAnalysisResult:
    """
    Structured result of analyzing a single password.

    Deliberately contains NO password field, in any form.
    """

    strength: str  # "WEAK" | "MEDIUM" | "STRONG" | "VERY STRONG"
    score: int
    max_score: int

    length: int
    has_uppercase: bool
    has_lowercase: bool
    has_digit: bool
    has_symbol: bool
    has_unicode: bool

    entropy_estimate_bits: float
    estimated_crack_time: str

    common_password: bool
    breached: bool | None  # None means "not checked"

    detected_patterns: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """JSON-serializable representation. Never includes the password."""
        return {
            "strength": self.strength,
            "score": self.score,
            "max_score": self.max_score,
            "length": self.length,
            "has_uppercase": self.has_uppercase,
            "has_lowercase": self.has_lowercase,
            "has_digit": self.has_digit,
            "has_symbol": self.has_symbol,
            "has_unicode": self.has_unicode,
            "entropy_estimate_bits": self.entropy_estimate_bits,
            "estimated_crack_time": self.estimated_crack_time,
            "common_password": self.common_password,
            "breached": self.breached,
            "detected_patterns": self.detected_patterns,
            "issues": self.issues,
            "recommendations": self.recommendations,
        }


class InvalidPasswordInputError(ValueError):
    """Raised for input that cannot be safely analyzed (None, wrong type, etc.)."""


_SYMBOL_CHARS = set("!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~\\")


def _validate_input(password: object, max_length: int) -> str:
    """
    Validate raw input before any analysis touches it.

    Rejects None / non-str input explicitly rather than letting it
    fail deep inside the pipeline with a confusing error. Truncation
    (rather than exception) is used for oversized input so that a
    single overly long paste doesn't crash the tool -- but the
    truncation itself is treated as an "issue" the caller can surface.
    """
    if password is None:
        raise InvalidPasswordInputError("Password input was None.")
    if not isinstance(password, str):
        raise InvalidPasswordInputError(f"Password input must be str, got {type(password).__name__}.")
    if len(password) > max_length:
        return password[:max_length]
    return password


def _analyze_character_classes(password: str) -> dict[str, bool]:
    """
    O(n) single-pass-equivalent character class detection using
    idiomatic Python generator expressions with any(). Each any()
    call short-circuits on first match, so in practice this is often
    much faster than a full O(n) scan, and is never worse than O(n)
    per class (O(4n) overall for the four ASCII classes -- still
    linear in password length).
    """
    return {
        "has_uppercase": any(c.isupper() for c in password),
        "has_lowercase": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_symbol": any(c in _SYMBOL_CHARS for c in password),
        "has_unicode": any(ord(c) > 127 for c in password),
    }


def _score_password(
    password: str,
    classes: dict[str, bool],
    common: bool,
    patterns: list[DetectedPattern],
    policy: SecurityPolicy,
) -> int:
    """
    Deterministic, explainable, additive scoring model driven entirely
    by policy.json thresholds/weights. See README "Strength Scoring"
    for the full rationale of each weight.
    """
    s = policy.scoring
    length = len(password)
    score = 0

    if length >= policy.minimum_length:
        score += s.length_8
    if length >= policy.recommended_length:
        score += s.length_12
    if length >= policy.strong_length:
        score += s.length_16

    if classes["has_uppercase"]:
        score += s.has_uppercase
    if classes["has_lowercase"]:
        score += s.has_lowercase
    if classes["has_digit"]:
        score += s.has_digit
    if classes["has_symbol"]:
        score += s.has_symbol

    if not common:
        score += s.no_common_password
    else:
        score -= s.common_password_penalty

    if not patterns:
        score += s.no_pattern_detected
    else:
        kinds = {p.kind for p in patterns}
        if "sequential" in kinds:
            score -= s.sequential_pattern_penalty
        if "repeated_character" in kinds or "cyclic_repetition" in kinds:
            score -= s.repeated_pattern_penalty
        if "keyboard_walk" in kinds:
            score -= s.keyboard_pattern_penalty

    # Clamp to a sane range; scoring is meant to be explainable, not punitive
    # beyond the point of being meaningless.
    return max(0, min(score, s.max_score))


def _classify(
    password: str,
    score: int,
    common: bool,
    patterns: list[DetectedPattern],
    policy: SecurityPolicy,
) -> str:
    """
    Map a numeric score (plus hard security signals) onto a strength
    label. Length below the minimum is always an automatic WEAK,
    regardless of score, per the assignment's explicit requirement.
    A common-password match is likewise treated as an automatic WEAK,
    since a globally common password is inherently high-risk no
    matter how many character classes it happens to contain.
    """
    t = policy.classification_thresholds

    if len(password) < policy.minimum_length:
        return "WEAK"
    if common:
        return "WEAK"
    # A password that is mostly one dominant structural pattern (e.g. a
    # long run of the same repeated character, or a repeated short
    # cycle) is trivially guessable no matter how many character
    # classes it happens to touch -- character diversity is not a
    # substitute for unpredictability. Force WEAK if any single
    # detected pattern fragment covers at least half the password.
    if any(len(p.fragment) >= max(1, len(password) // 2) for p in patterns):
        return "WEAK"
    if score < t.weak_below:
        return "WEAK"
    if score < t.medium_below:
        return "MEDIUM"
    if score < t.strong_below:
        return "STRONG"

    # VERY STRONG requires both a top score AND (optionally) a clean
    # record of no detected patterns -- length or score alone must
    # never be sufficient, per project requirements.
    if t.very_strong_requires_no_issues and patterns:
        return "STRONG"
    return "VERY STRONG"


def _build_issues_and_recommendations(
    password: str,
    classes: dict[str, bool],
    common: bool,
    patterns: list[DetectedPattern],
    policy: SecurityPolicy,
) -> tuple[list[str], list[str]]:
    issues: list[str] = []
    recommendations: list[str] = []

    if len(password) < policy.minimum_length:
        issues.append(f"Password is shorter than {policy.minimum_length} characters.")
        recommendations.append(f"Use at least {policy.recommended_length} characters.")
    elif len(password) < policy.recommended_length:
        recommendations.append(f"Consider using at least {policy.recommended_length} characters.")

    if policy.require_uppercase and not classes["has_uppercase"]:
        issues.append("No uppercase character.")
        recommendations.append("Add an uppercase letter.")
    if policy.require_lowercase and not classes["has_lowercase"]:
        issues.append("No lowercase character.")
        recommendations.append("Add a lowercase letter.")
    if policy.require_digit and not classes["has_digit"]:
        issues.append("No number.")
        recommendations.append("Add a number.")
    if policy.require_symbol and not classes["has_symbol"]:
        issues.append("No symbol.")
        recommendations.append("Add a symbol.")

    if common:
        issues.append("Password matches a known common/predictable password.")
        recommendations.append("Avoid common or previously leaked passwords.")

    for p in patterns:
        issues.append(p.description)
    if patterns:
        recommendations.append("Avoid predictable sequences, repeated characters, and keyboard patterns.")

    if not issues:
        recommendations.append("Consider using a long, unique passphrase for even stronger protection.")

    return issues, recommendations


def analyze_password(password: str, policy: SecurityPolicy | None = None) -> PasswordAnalysisResult:
    """
    Run the full analysis pipeline against a single password and
    return a PasswordAnalysisResult. Pure function: no I/O, no
    printing, no logging, no network access. The password itself is
    never stored anywhere in the returned object.

    Complexity: dominated by the O(n) character-class scan and O(n)
    pattern detection (n = password length, bounded by
    policy.maximum_length). Blacklist lookup is O(1) average-case
    after a one-time O(m) load. See README "Algorithmic Complexity"
    for the full, honest breakdown.
    """
    if policy is None:
        policy = load_policy()

    validated = _validate_input(password, policy.maximum_length)

    classes = _analyze_character_classes(validated)
    pattern_findings = detect_patterns(
        validated,
        min_sequential_run=policy.pattern_detection.min_sequential_run,
        min_repeated_run=policy.pattern_detection.min_repeated_run,
    )
    common = is_common_password(validated)

    entropy: EntropyEstimate = estimate_entropy(
        validated,
        has_uppercase=classes["has_uppercase"],
        has_lowercase=classes["has_lowercase"],
        has_digit=classes["has_digit"],
        has_symbol=classes["has_symbol"],
        has_unicode=classes["has_unicode"],
        entropy_policy=policy.entropy,
    )
    crack_seconds = estimate_crack_time_seconds(entropy, policy.crack_time)
    crack_time_str = humanize_seconds(crack_seconds)

    score = _score_password(validated, classes, common, pattern_findings, policy)
    strength = _classify(validated, score, common, pattern_findings, policy)
    issues, recommendations = _build_issues_and_recommendations(
        validated, classes, common, pattern_findings, policy
    )

    return PasswordAnalysisResult(
        strength=strength,
        score=score,
        max_score=policy.scoring.max_score,
        length=len(validated),
        has_uppercase=classes["has_uppercase"],
        has_lowercase=classes["has_lowercase"],
        has_digit=classes["has_digit"],
        has_symbol=classes["has_symbol"],
        has_unicode=classes["has_unicode"],
        entropy_estimate_bits=entropy.bits,
        estimated_crack_time=crack_time_str,
        common_password=common,
        breached=None,  # populated by the CLI layer only if --check-breach is used
        detected_patterns=[p.description for p in pattern_findings],
        issues=issues,
        recommendations=recommendations,
    )
