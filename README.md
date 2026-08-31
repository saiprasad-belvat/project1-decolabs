# Password Strength & Security Analyzer

A privacy-conscious cybersecurity tool that analyzes password strength
using length, character diversity, pattern detection, common-password
checks, policy evaluation, and theoretical entropy estimation.

Built as Project 1 for a cybersecurity internship. Designed to be a
small, honest, explainable security-analysis utility — not a toy that
checks four boxes and prints "Strong."

---

## Overview

Most beginner password checkers do this:

```
password -> check 4 conditions -> print "Strong"
```

This project instead runs a small analysis **pipeline**, where each
stage exists for a specific, explainable reason:

```
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
```

No single stage is trusted in isolation. A password can satisfy every
character-class rule (`Password123!`) and still be classified WEAK,
because the common-password and pattern stages catch what character
counting alone cannot.

## Problem Statement

Character-class-only password checkers give a false sense of
security: they reward `Password123!` and `Qwerty123!` just as highly
as a genuinely unpredictable password, because they never look at
*structure* or *predictability* — only presence of character types.
This project addresses that gap with dedicated pattern detection and
common-password matching, while being explicit and honest about the
limits of every signal it uses (see **Security Limitations**).

## Project Objectives

- Implement all ten original assignment requirements (see checklist
  at the bottom of this document).
- Go beyond character counting: detect structural predictability.
- Never store, log, or display the plaintext password anywhere.
- Keep every scoring decision transparent, deterministic, and
  configurable — no machine learning, no black-box scoring.
- Document real, honest limitations rather than overselling the tool.

## Features

- Length, character-class, pattern, and common-password analysis
- Deterministic, policy-driven strength scoring (WEAK / MEDIUM /
  STRONG / VERY STRONG)
- Theoretical entropy estimate and brute-force time estimate
- Optional HIBP k-anonymity breach check (opt-in, never sends the
  plaintext password or full hash)
- Professional CLI with human-readable and `--json` output
- Optional Flask web interface reusing the exact same core analyzer
- Configurable security policy (`policy.json`) — no hard-coded rules
- 59 automated tests covering boundaries, privacy, and edge cases

## Security Concepts

This project is a vehicle for demonstrating real security thinking,
not just Python syntax:

- **Analyze, don't store** — the guiding privacy principle behind
  every design decision.
- **k-anonymity** — used in the optional breach check so a third
  party never sees enough information to identify your password.
- **ReDoS avoidance** — pattern detection uses zero regular
  expressions, using bounded iteration instead.
- **Timing-attack awareness** — documented where it would and
  wouldn't apply to this codebase.
- **Honest uncertainty** — entropy and crack-time are always labeled
  as theoretical estimates, never as guarantees.

## Architecture

```
password-strength-security-analyzer/
├── src/password_checker/
│   ├── checker.py     # pure core pipeline (no I/O)
│   ├── entropy.py      # theoretical entropy + crack-time estimate
│   ├── patterns.py     # regex-free structural pattern detection
│   ├── blacklist.py    # common-password lookup
│   ├── breach.py        # optional HIBP k-anonymity check
│   ├── policy.py         # loads/validates policy.json
│   └── cli.py             # command-line interface
├── web/                     # optional Flask UI (reuses checker.py)
├── tests/                     # pytest suite
├── data/common_passwords.txt   # local educational blacklist
├── docs/                        # security review, demo, viva prep
└── policy.json                    # externalized security policy
```

The core analyzer (`checker.py`) never imports the CLI, Flask, or
`requests` — it has zero knowledge of how it's being invoked. The CLI
and web backend both call the same `analyze_password()` function, so
scoring logic exists in exactly one place.

## Installation

```bash
git clone https://github.com/saiprasad-belvat/project1-decolabs
cd password-strength-security-analyzer
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Core analysis has **zero required dependencies** beyond the standard
library; `requirements.txt` packages are only needed for testing,
optional CLI color, the optional breach check, and the optional web UI.

## Usage

```bash
# Interactive, non-echoing prompt
python -m password_checker

# Machine-readable output
python -m password_checker --json

# Optional online breach check (opt-in; see Privacy section)
python -m password_checker --check-breach

# Use an alternate policy file
python -m password_checker --policy ./my-policy.json
```

## CLI Examples

```
==================================================
PASSWORD STRENGTH & SECURITY ANALYZER
==================================================

Strength: STRONG
Score: 8/10

Security Checks
--------------------------------------------------
Length:             15              ✓
Uppercase:          Yes             ✓
Lowercase:          Yes             ✓
Digit:              Yes             ✓
Symbol:              Yes             ✓
Common password:    No              ✓
Pattern detected:   No              ✓

Theoretical entropy estimate:
78.66 bits

Estimated brute-force time (theoretical estimate only):
~15,091.3 centuries (theoretical estimate)

Breach check not performed.

Recommendations:
- Consider using a long, unique passphrase for even stronger protection.

==================================================
Privacy: Your password is analyzed locally and is not stored by this application.
==================================================
```

## Web UI

An optional Flask interface (`web/app.py`) reuses the exact same
core analyzer — no scoring logic is duplicated. Run it with:

```bash
pip install flask
python web/app.py
# then open http://127.0.0.1:5000
```

The UI is a dark, diagnostic-panel-styled console with a live,
equalizer-style strength meter, per-check readouts, and the same
privacy notice shown in the CLI.

## Strength Scoring

Scoring is additive, deterministic, and fully driven by
`policy.json` — see that file for every weight and threshold. In
summary:

| Signal | Effect |
|---|---|
| Length ≥ 8 / 12 / 16 | +1 each tier |
| Each character class present | +1 |
| Not a common password | +2 |
| No detected pattern | +1 |
| Common password match | large penalty, **forces WEAK** |
| Sequential / repeated / keyboard pattern | penalty |
| A single pattern covering ≥50% of the password | **forces WEAK** |

`VERY STRONG` additionally requires zero detected issues — a high
score from length alone is never sufficient.

## Entropy Estimation

Estimated as `length × log2(character_set_size)`, where the pool
size sums the assumed size of every character class actually present
(configurable in `policy.json`). **This is a theoretical estimate,
not a measurement of a human-created password's real randomness.** A
password can have respectable computed entropy and still be
predictable — that's why entropy is only one input into the overall
score, alongside pattern and common-password checks.

## Pattern Detection

Detects, without any regular expressions (see `patterns.py`):

- Sequential runs (`1234`, `abcd`)
- Repeated-character runs (`aaaa`, `1111`, `!!!!`)
- A small fixed set of keyboard walks (`qwerty`, `asdf`, …)
- Short cyclic repetition (`abcabcabc`)

All detectors use bounded, linear iteration specifically to avoid
ReDoS — see `docs/security-review.md` §7.

## Common Password Detection

`data/common_passwords.txt` is a small, hand-compiled **educational**
sample of widely publicized common passwords. The checker matches
both the exact password and its alphabetic "core" after stripping
trailing digits/symbols (so `Password123!` is still caught via
`password`). **This list is not exhaustive** and does not represent
every password ever leaked in a real breach.

## Optional Breach Checking

`--check-breach` uses the HIBP Pwned Passwords **k-anonymity** API:
the password is hashed locally (SHA-1) and only the first 5 hex
characters of the hash are ever sent over the network. Off by
default — with no flag, zero network requests are made. A password
**not** found in the checked dataset is **not** proof it's safe; it
only means it wasn't found in that particular dataset.

## Privacy

**Your password is analyzed locally and is not stored by this
application.** Concretely:

- No plaintext password is ever printed, logged, saved to a file, put
  in JSON output, stored in a database, or sent to an external API.
- CLI input uses `getpass.getpass()` (no terminal echo).
- The optional breach check sends only a 5-character hash prefix,
  never the password or the full hash.
- The web UI sends the password only to its own local backend, which
  runs the same core analyzer and returns no password data.

## Timing Attack Considerations

This project's own comparisons don't involve two secret values, so
`hmac.compare_digest()` isn't exercised here — see
`docs/security-review.md` §6 and `docs/viva.md` Q9–10 for exactly why,
and where it *would* matter.

## Memory Security Considerations

Python strings are immutable; a variable can be reassigned to `None`,
but the original character data isn't guaranteed to be zeroed and may
remain in memory until garbage-collected and reused. This project
drops its references to the password as soon as analysis is complete,
but this is a best-effort mitigation, **not** a guarantee of secure
memory erasure.

## Algorithmic Complexity

Honest, per-component breakdown (n = password length, bounded by
`policy.maximum_length`; m = size of the common-password wordlist):

| Component | Complexity | Notes |
|---|---|---|
| Character-class analysis | O(n) | Each `any()` call is at most O(n); 5 classes checked |
| Pattern detection | O(n) | Sequential/repeated runs are single linear passes; keyboard-walk check is O(n·k) for a small constant k; cyclic-repetition check is O(n) bounded by a fixed max cycle length of 4 |
| Common-password lookup | O(1) average-case per query, after a one-time O(m) file load | Backed by a Python `set` |
| Entropy calculation | O(1) | Reuses already-computed character-class booleans; does not re-scan the password |
| Overall `analyze_password()` | O(n) | Dominated by the linear scans above |

**Not everything in the application is O(n).** The blacklist's
one-time load is O(m); network I/O in the optional breach check has
its own, non-algorithmic latency profile that isn't meaningfully
described by Big-O at all.

## Testing

```bash
pip install pytest requests
PYTHONPATH=src pytest -v
```

59 tests across 5 files cover: empty/None/non-string input, every
length boundary (0, 1, 7, 8, extremely long), every character-class
combination, Unicode, all pattern types, common-password matching
(including trailing-suffix variants), JSON output shape, policy
loading, mocked breach-check success/failure/disabled paths, and the
core privacy guarantee that no password ever appears in a result
object.

## Security Limitations

Documented plainly, not hidden:

- The common-password list is a small educational sample, not a
  comprehensive breach corpus.
- Entropy and crack-time figures are theoretical estimates based on a
  uniform-random-selection assumption; they do not model real human
  password-choice patterns or real attacker strategies.
- Pattern detection is heuristic and pattern-list-based; it will not
  catch every form of predictability (e.g. patterns specific to a
  language or culture not represented in the fixed keyboard-pattern
  list).
- Python cannot guarantee secure memory erasure of string data.
- The HIBP breach check reveals a 5-character hash prefix to a third
  party, even though it cannot identify the specific password from
  that prefix alone.

## Project Structure

See **Architecture** above and the repository tree for full detail.

## Screenshots
## Screenshots

### WEEK PASSWORD
![ WEEK PASSWORD ](screenshots/Screenshot%202026-08-31%20081316.png)

### STRONG PASSWROD
![STRONG PASSWORD](screenshots/Screenshot%202026-08-31%20081357.png)

See `screenshots/` for CLI runs against the WEAK / MEDIUM / STRONG
demo passwords below, pattern detection, common-password detection,
`--json` output, and the web interface. All screenshots use the
fictional demo passwords only — never a real password.

## Future Improvements

- Passphrase generator (Diceware-style) as a companion feature
- Larger, licensed common-password corpus with documented provenance
- Localization of feedback strings
- Exportable PDF/HTML security report

## Disclaimer

> This tool is an educational password-analysis utility. Its strength
> classification is a heuristic assessment and does not guarantee that
> a password cannot be guessed, cracked, or compromised. Real-world
> security depends on password generation, uniqueness, reuse,
> authentication controls, rate limiting, multi-factor authentication,
> password storage practices, and other factors.

---

## Demo Data

Safe, fictional examples only — see `docs/demo.md` for the full walkthrough.

| Type | Example |
|---|---|
| Weak | `abc` |
| Common | `password123` |
| Pattern-based | `Abcd1234!` |
| Strong | `Violet-River-72!Moon` |

## Requirements Checklist

| # | Requirement | Status |
|---|---|---|
| 1 | Check password length | ✅ |
| 2 | Check uppercase letters | ✅ |
| 3 | Check lowercase letters | ✅ |
| 4 | Check numbers/digits | ✅ |
| 5 | Check symbols | ✅ |
| 6 | Display strength result | ✅ |
| 7 | Use string handling | ✅ |
| 8 | Use conditional logic | ✅ |
| 9 | Demonstrate cybersecurity/security basics | ✅ |
| 10 | Core analysis in O(n) where practical | ✅ (see Algorithmic Complexity) |
| — | WEAK / MEDIUM / STRONG classifications | ✅ |
| — | VERY STRONG enhanced classification | ✅ |
| — | <8 chars treated as failing | ✅ |
