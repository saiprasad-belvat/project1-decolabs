"""
Password Strength & Security Analyzer
======================================

A privacy-conscious cybersecurity tool that analyzes password strength
using length, character diversity, pattern detection, common-password
checks, policy evaluation, and theoretical entropy estimation.

Design principle: "Analyze, don't store."
This package never logs, prints, saves, or transmits plaintext passwords.
Only derived, non-reversible metadata (booleans, counts, labels) leaves
the core analysis functions.

Public API:
    analyze_password(password, policy=None) -> PasswordAnalysisResult
"""

from .checker import analyze_password, PasswordAnalysisResult

__all__ = ["analyze_password", "PasswordAnalysisResult"]
__version__ = "1.0.0"
