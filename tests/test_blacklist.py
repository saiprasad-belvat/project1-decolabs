"""test_blacklist.py -- common-password lookup behavior."""

from password_checker.blacklist import is_common_password


class TestCommonPasswordDetection:
    def test_known_common_password_detected(self):
        assert is_common_password("password") is True

    def test_known_common_password_case_insensitive(self):
        assert is_common_password("PaSsWoRd") is True

    def test_numeric_common_password_detected(self):
        assert is_common_password("123456") is True

    def test_qwerty_detected(self):
        assert is_common_password("qwerty") is True

    def test_unique_password_not_flagged(self):
        assert is_common_password("Violet-River-72!Moon") is False

    def test_common_word_with_trailing_digits_and_symbol_detected(self):
        # 'Password123!' satisfies character-class rules but its
        # alphabetic core ('password') is a known common password.
        assert is_common_password("Password123!") is True

    def test_missing_wordlist_file_does_not_crash(self):
        # Points at a nonexistent path; should safely return False, not raise.
        assert is_common_password("password", path="/nonexistent/path.txt") is False
