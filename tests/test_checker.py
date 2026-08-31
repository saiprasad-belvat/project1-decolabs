"""
test_checker.py

Covers the core analysis pipeline: input validation, length boundaries,
character classes, scoring/classification, JSON output shape, and the
critical privacy guarantee that no password ever appears in a result.
"""

import pytest

from password_checker.checker import InvalidPasswordInputError, analyze_password
from password_checker.policy import load_policy

POLICY = load_policy()


class TestInputValidation:
    def test_none_password_raises(self):
        with pytest.raises(InvalidPasswordInputError):
            analyze_password(None)

    def test_non_string_password_raises(self):
        with pytest.raises(InvalidPasswordInputError):
            analyze_password(12345678)  # type: ignore[arg-type]

    def test_empty_password_is_weak_not_a_crash(self):
        result = analyze_password("")
        assert result.strength == "WEAK"
        assert result.length == 0

    def test_extremely_long_password_is_truncated_safely(self):
        huge = "a" * 5000
        result = analyze_password(huge)
        assert result.length <= POLICY.maximum_length


class TestLengthBoundaries:
    def test_one_character_password(self):
        result = analyze_password("a")
        assert result.strength == "WEAK"

    def test_seven_character_password_is_weak(self):
        result = analyze_password("Abcdef1")
        assert result.strength == "WEAK"

    def test_exactly_eight_characters_passes_minimum(self):
        result = analyze_password("Abcdefg1")
        assert result.length == 8
        assert "shorter than" not in " ".join(result.issues)

    def test_long_password_scores_well(self):
        result = analyze_password("Correct-Horse-Battery-42!")
        assert result.strength in ("STRONG", "VERY STRONG")


class TestCharacterClasses:
    def test_lowercase_only(self):
        result = analyze_password("lowercaseonly")
        assert result.has_lowercase is True
        assert result.has_uppercase is False
        assert result.has_digit is False
        assert result.has_symbol is False

    def test_uppercase_only(self):
        result = analyze_password("UPPERCASEONLY")
        assert result.has_uppercase is True
        assert result.has_lowercase is False

    def test_numbers_only(self):
        result = analyze_password("13572468")
        assert result.has_digit is True
        assert result.has_uppercase is False

    def test_symbols_present(self):
        result = analyze_password("Abcdef1!")
        assert result.has_symbol is True

    def test_mixed_characters(self):
        result = analyze_password("Ab1!Cd2@")
        assert all([result.has_uppercase, result.has_lowercase, result.has_digit, result.has_symbol])

    def test_unicode_detected(self):
        result = analyze_password("Passwörd123!")
        assert result.has_unicode is True


class TestPatternAndCommonPassword:
    def test_repeated_characters_flagged(self):
        result = analyze_password("Aaaaaaaa1!")
        assert any("Repeated" in p for p in result.detected_patterns)

    def test_sequential_characters_flagged(self):
        result = analyze_password("Abcdefgh1!")
        assert any("Sequential" in p for p in result.detected_patterns)

    def test_keyboard_pattern_flagged(self):
        result = analyze_password("qwerty123!")
        assert any("keyboard" in p.lower() for p in result.detected_patterns)

    def test_common_password_detected(self):
        result = analyze_password("password123")
        assert result.common_password is True
        assert result.strength == "WEAK"

    def test_strong_password_has_no_common_flag(self):
        result = analyze_password("Violet-River-72!Moon")
        assert result.common_password is False


class TestClassificationLabels:
    def test_weak_medium_strong_labels_exist(self):
        weak = analyze_password("abc")
        medium = analyze_password("Abcd1234!")
        strong = analyze_password("Violet-River-72!Moon")
        assert weak.strength == "WEAK"
        assert medium.strength in ("WEAK", "MEDIUM")
        assert strong.strength in ("STRONG", "VERY STRONG")

    def test_password123_excl_is_not_automatically_very_strong(self):
        # Satisfies character classes but is predictable -- must not be top-rated.
        result = analyze_password("Password123!")
        assert result.strength != "VERY STRONG"

    def test_sixteen_chars_alone_is_not_automatically_strong(self):
        result = analyze_password("aaaaaaaaaaaaaaaa")  # 16 chars, all repeated
        assert result.strength == "WEAK"


class TestPrivacyGuarantee:
    def test_password_never_in_result_dict(self):
        secret = "SuperSecretUniqueTestValue!42"
        result = analyze_password(secret)
        serialized = str(result.to_dict())
        assert secret not in serialized

    def test_result_dataclass_has_no_password_field(self):
        result = analyze_password("Whatever1!")
        assert not hasattr(result, "password")
        field_names = result.to_dict().keys()
        assert "password" not in field_names


class TestJsonOutputShape:
    def test_to_dict_contains_expected_keys(self):
        result = analyze_password("Abcdef1!")
        d = result.to_dict()
        expected_keys = {
            "strength", "score", "max_score", "length",
            "has_uppercase", "has_lowercase", "has_digit", "has_symbol", "has_unicode",
            "entropy_estimate_bits", "estimated_crack_time",
            "common_password", "breached",
            "detected_patterns", "issues", "recommendations",
        }
        assert expected_keys.issubset(d.keys())

    def test_breached_defaults_to_none_when_not_checked(self):
        result = analyze_password("Abcdef1!")
        assert result.breached is None
