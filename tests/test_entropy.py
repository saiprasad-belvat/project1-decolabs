"""test_entropy.py -- entropy and crack-time estimation."""

from password_checker.entropy import estimate_crack_time_seconds, estimate_entropy, humanize_seconds
from password_checker.policy import load_policy

POLICY = load_policy()


class TestEntropyCalculation:
    def test_empty_password_has_zero_entropy(self):
        e = estimate_entropy("", False, False, False, False, False, POLICY.entropy)
        assert e.bits == 0.0

    def test_more_character_classes_increase_entropy(self):
        lower_only = estimate_entropy("abcdefgh", True, False, False, False, False, POLICY.entropy)
        mixed = estimate_entropy("abcdEFGH", True, True, False, False, False, POLICY.entropy)
        assert mixed.bits > lower_only.bits

    def test_longer_password_increases_entropy(self):
        short = estimate_entropy("abcdefgh", True, False, False, False, False, POLICY.entropy)
        longer = estimate_entropy("abcdefghabcdefgh", True, False, False, False, False, POLICY.entropy)
        assert longer.bits > short.bits

    def test_entropy_is_non_negative(self):
        e = estimate_entropy("x", True, False, False, False, False, POLICY.entropy)
        assert e.bits >= 0


class TestCrackTimeEstimation:
    def test_zero_entropy_gives_fast_crack_time(self):
        e = estimate_entropy("", False, False, False, False, False, POLICY.entropy)
        seconds = estimate_crack_time_seconds(e, POLICY.crack_time)
        assert seconds == 0.0

    def test_humanize_seconds_handles_small_values(self):
        assert "second" in humanize_seconds(0.5)

    def test_humanize_seconds_handles_large_values(self):
        text = humanize_seconds(10_000_000_000_000)
        assert "theoretical estimate" in text

    def test_humanize_seconds_handles_infinity(self):
        text = humanize_seconds(float("inf"))
        assert "unbounded" in text
