# Demo Script (3–5 minutes)

Goal: demonstrate security reasoning, not just UI. Use only the safe,
fictional demo passwords below — never a real personal password.

| Purpose        | Example password         |
|-----------------|---------------------------|
| Weak            | `abc`                     |
| Common          | `password123`             |
| Pattern-based   | `Abcd1234!`                |
| Strong          | `Violet-River-72!Moon`     |

## Flow

**1. Introduce the project (30s)**
"This is a password strength analyzer built for the DecodeLabs
cybersecurity internship. It doesn't just check four boxes and print
'Strong' — it runs a small analysis pipeline: length, character
classes, structural patterns, common-password matching, and a
theoretical entropy estimate, all combined into an explainable score."

**2. Show the architecture (30s)**
Open `src/password_checker/` and point out that `checker.py` is a
pure function with no I/O — `cli.py` and `web/app.py` both call the
exact same `analyze_password()`, so the scoring logic exists in
exactly one place.

**3. Enter a weak password — `abc` (30s)**
```
python -m password_checker
```
Show the WEAK result. Explain: fails the minimum-length policy from
`policy.json` before anything else is even scored.

**4. Enter a common password — `password123` (30s)**
Show that it's flagged `common_password: true` and forced to WEAK
even though it has letters and digits. Explain the blacklist lookup
in `blacklist.py` and that it also catches "Password123!"-style
variants by stripping trailing digits/symbols.

**5. Enter a pattern-based password — `Abcd1234!` (30s)**
Show the detected patterns: `Sequential pattern detected: Abcd` and
`...1234`. Explain that character diversity alone (upper, lower,
digit, symbol are all present here) isn't enough — structure matters.

**6. Enter a strong password — `Violet-River-72!Moon` (30s)**
Show VERY STRONG, full score, and no detected issues. Point out the
theoretical entropy estimate and crack-time figure, and read the
"theoretical estimate" label out loud — this is intentional, not
decorative.

**7. Show the optional breach-check concept (20s)**
```
python -m password_checker --check-breach
```
Explain the k-anonymity design from `breach.py`: only a 5-character
hash prefix is ever sent over the network, and the flag is required —
without it, zero network calls happen.

**8. Show JSON output (20s)**
```
python -m password_checker --json
```
Point out there's no "password" key anywhere in the output.

**9. Show tests (30s)**
```
pytest -v
```
Mention the count and call out `test_password_never_in_result_dict`
specifically as the privacy guarantee being tested, not just asserted
in a docstring.

**10. Show the GitHub repository (20s)**
Walk through README sections: Security Concepts, Algorithmic
Complexity, Security Limitations.

**11. Explain security limitations honestly (20s)**
"The common-password list is a small educational sample, not a full
breach corpus. Entropy is theoretical, not a guarantee. Python
strings can't be reliably zeroed in memory. These are documented, not
hidden."
