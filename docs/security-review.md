# Security Review

This document is a self-conducted security review of the Password
Strength & Security Analyzer, written the way a security engineer
would review their own tool before it ships. For each threat: what
it is, its impact if unaddressed, how this project mitigates it, and
what limitation remains even after mitigation.

---

## 1. Password leakage via logs, files, or output

**Threat:** The plaintext password is accidentally written to a log
file, terminal history, a JSON export, or an exception traceback.

**Impact:** Anyone with access to logs, disk, or shell history gains
the user's actual password.

**Mitigation:**
- The CLI reads input with `getpass.getpass()`, which never echoes
  input to the terminal and is not recorded in shell history the way
  a typed command-line argument would be.
- `PasswordAnalysisResult` (`checker.py`) has **no field** that
  stores the password in any form — not plaintext, not a hash. It is
  structurally impossible to serialize the password from this object
  because the object never receives it.
- Core analysis functions (`checker.py`, `patterns.py`, `entropy.py`,
  `blacklist.py`) contain no `print()`, `input()`, file I/O, or
  logging calls of any kind.
- Automated test `test_password_never_in_result_dict` asserts that a
  known unique test password never appears anywhere in the
  serialized result.

**Remaining limitation:** This protects the *application's own*
handling of the password. It cannot protect against OS-level swap
files, crash dumps, shell history if a user pipes a password via
`--password-stdin` in an interactive shell, or a compromised terminal
emulator. See also §6, Memory Security.

---

## 2. Accidental password storage

**Threat:** A password is saved to disk (database, cache file, temp
file) "just for debugging" and forgotten.

**Impact:** Persistent plaintext password storage, the single worst
outcome for a password tool to cause.

**Mitigation:** The project has no database, no cache layer, and no
file-write path anywhere in the core analyzer, CLI, or web backend.
`.gitignore` also excludes patterns like `*.pwtxt` and
`password_dump*` as a defense-in-depth guardrail against future
regressions.

**Remaining limitation:** None identified for the current codebase;
this is an architectural guarantee, not just a policy.

---

## 3. Predictable / common passwords

**Threat:** A password satisfies character-class rules
("Password123!") but is still trivially guessable because it is a
known common password or a common word with a predictable suffix.

**Impact:** False sense of security if only character diversity is
checked.

**Mitigation:** `blacklist.py` checks both the exact password and its
alphabetic "core" (after stripping trailing digits/symbols) against a
local common-password list. A match forces an automatic `WEAK`
classification regardless of character diversity score
(`checker.py::_classify`).

**Remaining limitation:** The bundled list
(`data/common_passwords.txt`) is a small, hand-compiled educational
sample — it is **not** exhaustive and does not represent every
password that has ever appeared in a real-world breach. See
`README.md` → "Common Password Detection" for the same disclaimer
surfaced to end users.

---

## 4. Pattern-based guessing (sequences, repeats, keyboard walks)

**Threat:** A password like `aaaaaaaaaaaaaaaa` or `qwerty123!` is
long and/or character-diverse but structurally trivial to guess.

**Impact:** Same false-sense-of-security risk as §3, from a different
angle.

**Mitigation:** `patterns.py` detects sequential runs, repeated-
character runs, keyboard-walk substrings, and short cyclic repetition.
`checker.py::_classify` forces `WEAK` when a single detected pattern
covers at least half the password, since such a password is
dominated by a low-entropy structure no matter what else it contains.

**Remaining limitation:** Detection is pattern-based, not
comprehension-based — it will not catch, for example, a password that
is a predictable phrase in a specific person's native language, or a
pattern outside the fixed keyboard-walk list in `patterns.py`.

---

## 5. Brute-force risk and misleading confidence

**Threat:** Presenting an entropy number or crack-time estimate in a
way that implies mathematical certainty about real-world attack
resistance.

**Impact:** Users over-trust a "good" number and skip other basic
precautions (uniqueness, MFA, etc.).

**Mitigation:** Every surface that shows entropy or crack-time
(CLI, JSON output, web UI, README) is explicitly labeled a
*theoretical estimate*. `entropy.py`'s docstring and `humanize_seconds()`
both state this is not a prediction of real attacker behavior, which
typically tries likely passwords first rather than searching the full
space uniformly at random.

**Remaining limitation:** The label depends on the user actually
reading it. No UI can force genuine comprehension of a caveat.

---

## 6. Timing attacks

**Threat:** A secret-to-secret comparison (e.g. comparing a supplied
hash suffix to a stored one) takes measurably different time
depending on how many leading characters match, letting an attacker
infer the secret via repeated timing measurements.

**Impact:** Could leak secret material bit-by-bit over many requests.

**Mitigation:** This project's actual data flows do not require a
secret-to-secret comparison: the HIBP breach check (`breach.py`)
compares a *locally computed hash suffix* against suffixes returned
by a *public* API for a *shared, non-secret prefix* — no side of that
comparison is confidential, so a timing side channel there leaks
nothing. `docs/viva.md` documents `hmac.compare_digest()` and where
it *would* matter (e.g. comparing a user-supplied token against a
server-side secret) so this is understood even though it is not
exercised by this specific codebase.

**Remaining limitation:** If this project is extended to add actual
secret comparisons (e.g. a stored API key check), `compare_digest()`
must be introduced at that point — it is not retrofitted here because
doing so would be a security theater, not a fix, for the current code.

---

## 7. Malicious oversized input / ReDoS

**Threat:** An attacker-controlled password string is extremely long,
or is crafted specifically to trigger catastrophic regex backtracking,
causing high CPU usage or denial of service.

**Impact:** The analyzer becomes unresponsive or crashes the process.

**Mitigation:**
- `policy.json` sets `maximum_length` (default 1000); `checker.py`
  truncates any longer input before any analysis touches it.
- `patterns.py` uses **no regular expressions** at all for its core
  detectors — sequential runs, repeated runs, and cyclic repetition
  are all found with plain, bounded iteration, which has no
  catastrophic-backtracking failure mode by construction. Keyboard-
  pattern detection uses plain substring membership against a small,
  fixed list.
- `test_patterns.py::TestNoRegexPerformanceIssue` asserts a 1000-
  character adversarial-looking password is analyzed in well under a
  second.

**Remaining limitation:** None identified for pattern detection
specifically; general Python-level resource exhaustion (e.g. extreme
memory pressure from a hostile caller bypassing the length cap
entirely) is outside this tool's threat model.

---

## 8. Breach-check privacy (HIBP k-anonymity)

**Threat:** Checking a password against an online breach database
could itself leak the password to that service.

**Impact:** Defeats the purpose of a privacy-conscious tool.

**Mitigation:** `breach.py` implements the k-anonymity model: the
password is hashed locally with SHA-1, and only the **first 5 hex
characters** of the hash are sent to the Pwned Passwords API. The
API returns all suffixes sharing that prefix, and the match is
completed locally — the full hash and the plaintext password never
leave the machine. The check is strictly opt-in (`--check-breach`);
with no flag, `breach.py` is never imported and no network call is
ever made, which `test_breach.py::TestBreachCheckDisabledByDefault`
verifies directly against the core pipeline.

**Remaining limitation:** A 5-character hash prefix is still
information disclosed to a third party, even if it cannot identify
the specific password among the (typically hundreds of) hashes
sharing that prefix. Users who want a zero-network guarantee should
simply not pass `--check-breach`.

---

## Threats considered but out of scope

- **Authentication/session security** — this tool does not
  authenticate anyone or manage sessions; that threat surface does
  not exist here.
- **Storage of passwords by other systems** — this tool explicitly
  does not store passwords, so hashing-for-storage (bcrypt/Argon2 etc.)
  is not implemented, because there is nothing being stored.
- **Multi-factor authentication, rate limiting, account lockout** —
  these are properties of an authentication system, not a standalone
  strength-analysis utility, and are called out in the README
  disclaimer as factors real-world security depends on beyond this
  tool's scope.
