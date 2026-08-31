"""
cli.py
======

Command-line interface for the Password Strength & Security Analyzer.

PRIVACY: password input uses getpass.getpass() so the password is
never echoed to the terminal, and this module never prints, logs, or
writes the plaintext password anywhere. Only the PasswordAnalysisResult
(which contains no password data) is ever displayed or serialized.

Usage:
    python -m password_checker
    python -m password_checker --json
    python -m password_checker --check-breach
    python -m password_checker --password-stdin   (for scripted testing only)
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from .breach import check_password_breach
from .checker import InvalidPasswordInputError, PasswordAnalysisResult, analyze_password
from .policy import load_policy

BANNER = "=" * 50
PRIVACY_NOTICE = "Your password is analyzed locally and is not stored by this application."


def _read_password(use_stdin: bool) -> str:
    """
    Read the password. Defaults to getpass (no terminal echo, not
    stored in shell history). --password-stdin is provided ONLY for
    automated testing/piping where no TTY is available; it is
    documented as less private and is opt-in.
    """
    if use_stdin:
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Enter password: ")


def _render_human(result: PasswordAnalysisResult, breach_note: str) -> str:
    lines = [
        BANNER,
        "PASSWORD STRENGTH & SECURITY ANALYZER",
        BANNER,
        "",
        f"Strength: {result.strength}",
        f"Score: {result.score}/{result.max_score}",
        "",
        "Security Checks",
        "-" * 50,
        f"{'Length:':<20}{result.length:<16}{'✓' if result.length >= 8 else '✗'}",
        f"{'Uppercase:':<20}{('Yes' if result.has_uppercase else 'No'):<16}"
        f"{'✓' if result.has_uppercase else '✗'}",
        f"{'Lowercase:':<20}{('Yes' if result.has_lowercase else 'No'):<16}"
        f"{'✓' if result.has_lowercase else '✗'}",
        f"{'Digit:':<20}{('Yes' if result.has_digit else 'No'):<16}"
        f"{'✓' if result.has_digit else '✗'}",
        f"{'Symbol:':<20}{('Yes' if result.has_symbol else 'No'):<16}"
        f"{'✓' if result.has_symbol else '✗'}",
        f"{'Common password:':<20}{('Yes' if result.common_password else 'No'):<16}"
        f"{'✗' if result.common_password else '✓'}",
        f"{'Pattern detected:':<20}{('Yes' if result.detected_patterns else 'No'):<16}"
        f"{'✗' if result.detected_patterns else '✓'}",
        "",
        "Theoretical entropy estimate:",
        f"{result.entropy_estimate_bits} bits",
        "",
        "Estimated brute-force time (theoretical estimate only):",
        result.estimated_crack_time,
        "",
        breach_note,
        "",
    ]

    if result.issues:
        lines.append("Issues:")
        lines.extend(f"- {issue}" for issue in result.issues)
        lines.append("")

    lines.append("Recommendations:")
    if result.recommendations:
        lines.extend(f"- {rec}" for rec in result.recommendations)
    else:
        lines.append("✓ No major issues detected.")
    lines.append("")
    lines.append(BANNER)
    lines.append(f"Privacy: {PRIVACY_NOTICE}")
    lines.append(BANNER)
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_checker",
        description="Analyze password strength using length, character diversity, "
                    "pattern detection, common-password checks, and theoretical entropy.",
    )
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of the human report.")
    parser.add_argument(
        "--check-breach",
        action="store_true",
        help="Optionally check the password's SHA-1 prefix against the HIBP k-anonymity "
             "API. Off by default; no network request is made unless this flag is set.",
    )
    parser.add_argument(
        "--policy",
        type=str,
        default=None,
        help="Path to an alternate policy.json (defaults to the project's own policy.json).",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password from stdin instead of an interactive, non-echoing prompt. "
             "Intended for scripted testing only -- less private than the default prompt.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    policy = load_policy(args.policy)

    try:
        password = _read_password(args.password_stdin)
        result = analyze_password(password, policy=policy)
    except InvalidPasswordInputError as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return 1
    finally:
        # Best-effort: drop our only local reference to the plaintext
        # password as soon as analysis is complete. Python strings are
        # immutable and this does not guarantee memory erasure -- see
        # docs/security-review.md "Memory Security" for the honest
        # limitations of this approach.
        password = None  # noqa: F841

    breach_note = "Breach check not performed."
    if args.check_breach:
        # NOTE: analyze_password() above never saw args.check_breach and
        # never made a network call. The breach check is deliberately a
        # separate, explicit step so that "no flag => no network request"
        # is trivially true by construction.
        breach_note = "Optional breach check enabled."
        # We need the password again only for this opt-in step; re-prompt
        # rather than holding it in memory any longer than necessary.
        password = _read_password(args.password_stdin) if args.password_stdin else getpass.getpass(
            "Re-enter password to run optional breach check: "
        )
        breach_result = check_password_breach(password)
        password = None  # noqa: F841
        if breach_result.error:
            breach_note = f"Breach check not completed: {breach_result.error}"
        elif breach_result.performed:
            result.breached = breach_result.breached
            if breach_result.breached:
                result.issues.append("Password appears in a known public breach dataset.")
                result.recommendations.append("Change this password immediately; it is publicly compromised.")
                breach_note = "Breach check enabled: password WAS found in the checked breach dataset."
            else:
                breach_note = (
                    "Breach check enabled: password was not found in the checked dataset "
                    "(this does not guarantee the password is safe)."
                )

    if args.json:
        print(json.dumps(result.to_dict(), indent=4))
    else:
        print(_render_human(result, breach_note))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
