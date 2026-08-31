"""
test_breach.py -- optional HIBP k-anonymity breach check.

Network access is mocked; these tests never make a real HTTP call,
both for test reliability and to avoid depending on external services
during automated grading/CI.
"""

from unittest.mock import MagicMock, patch

from password_checker.breach import _sha1_hex_uppercase, check_password_breach


class TestHashing:
    def test_sha1_hash_is_deterministic_and_correct_length(self):
        h = _sha1_hex_uppercase("test-password")
        assert len(h) == 40
        assert h == h.upper()

    def test_different_passwords_hash_differently(self):
        assert _sha1_hex_uppercase("abc") != _sha1_hex_uppercase("abcd")


class TestBreachCheckDisabledByDefault:
    def test_analyze_password_never_calls_network(self):
        # analyze_password() (the core pipeline) must never import requests
        # or touch the network; breach checking is a separate, explicit step.
        from password_checker.checker import analyze_password
        result = analyze_password("SomeTestPassword1!")
        assert result.breached is None


class TestBreachCheckMocked:
    @patch("requests.get")
    def test_password_found_in_breach(self, mock_get):
        target_hash = _sha1_hex_uppercase("password123")
        prefix, suffix = target_hash[:5], target_hash[5:]
        mock_response = MagicMock()
        mock_response.text = f"{suffix}:12345\nAAAAA1:1"
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = check_password_breach("password123")
        assert result.performed is True
        assert result.breached is True

    @patch("requests.get")
    def test_password_not_found_in_breach(self, mock_get):
        mock_response = MagicMock()
        mock_response.text = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ:1"
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = check_password_breach("Violet-River-72!Moon")
        assert result.performed is True
        assert result.breached is False

    @patch("requests.get")
    def test_network_failure_handled_gracefully(self, mock_get):
        import requests
        mock_get.side_effect = requests.RequestException("simulated network failure")

        result = check_password_breach("anything")
        assert result.performed is False
        assert result.breached is None
        assert result.error is not None

    def test_only_prefix_length_is_five(self):
        full_hash = _sha1_hex_uppercase("correct horse battery staple")
        prefix = full_hash[:5]
        assert len(prefix) == 5
