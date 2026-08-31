"""test_patterns.py -- structural pattern detection."""

from password_checker.patterns import detect_patterns


class TestSequentialPatterns:
    def test_ascending_digits_detected(self):
        findings = detect_patterns("xx1234xx")
        assert any(f.kind == "sequential" for f in findings)

    def test_ascending_letters_detected(self):
        findings = detect_patterns("xxabcdxx")
        assert any(f.kind == "sequential" for f in findings)

    def test_no_false_positive_on_random_text(self):
        findings = detect_patterns("Kj8#mQ2z")
        assert not any(f.kind == "sequential" for f in findings)


class TestRepeatedCharacterPatterns:
    def test_repeated_letters_detected(self):
        findings = detect_patterns("xxaaaaxx")
        assert any(f.kind == "repeated_character" for f in findings)

    def test_repeated_digits_detected(self):
        findings = detect_patterns("xx1111xx")
        assert any(f.kind == "repeated_character" for f in findings)

    def test_repeated_symbols_detected(self):
        findings = detect_patterns("xx!!!!xx")
        assert any(f.kind == "repeated_character" for f in findings)


class TestKeyboardPatterns:
    def test_qwerty_detected(self):
        findings = detect_patterns("myqwertypass")
        assert any(f.kind == "keyboard_walk" for f in findings)

    def test_asdf_detected(self):
        findings = detect_patterns("asdf1234")
        assert any(f.kind == "keyboard_walk" for f in findings)

    def test_random_password_has_no_keyboard_pattern(self):
        findings = detect_patterns("Kj8#mQ2zR!")
        assert not any(f.kind == "keyboard_walk" for f in findings)


class TestCyclicRepetition:
    def test_abcabcabc_detected(self):
        findings = detect_patterns("abcabcabc")
        assert any(f.kind == "cyclic_repetition" for f in findings)


class TestNoRegexPerformanceIssue:
    def test_long_password_completes_quickly(self):
        import time
        long_pw = "aB1!" * 250  # 1000 chars, repetitive on purpose
        start = time.time()
        detect_patterns(long_pw)
        elapsed = time.time() - start
        assert elapsed < 1.0  # generous bound; should be near-instant
