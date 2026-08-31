# Viva / Interview Preparation

Concise, technically accurate answers you should be able to give in
your own words.

**1. Why do passwords need a minimum length?**
Search space grows exponentially with length for a fixed character
set, so length is the single biggest lever against brute-force
guessing. This project enforces `minimum_length` (default 8) as a
hard floor in `policy.json` — anything shorter is automatically WEAK.

**2. What is password entropy?**
A measure, in bits, of how unpredictable a value is. Roughly, `2^bits`
possible values must be tried, on average, to guess it by brute
force. This project estimates it as `length × log2(character_set_size)`.

**3. Is entropy alone enough to determine password strength?**
No. The formula assumes uniformly random character selection.
"Password123!" touches four character classes and has non-trivial
computed entropy, yet is highly predictable to a human attacker. This
is why entropy is only one signal among several (pattern detection
and common-password checks catch what entropy misses).

**4. What is brute force?**
An attack that tries possible passwords systematically (often
starting with likely ones, not a uniform random search) until one
succeeds.

**5. Why does character variety matter?**
It increases the size of the pool an attacker must search per
character position, increasing entropy for a given length.

**6. Why can a long password still be weak?**
If it's structured predictably — e.g. `aaaaaaaaaaaaaaaa` or
`abcabcabcabc` — its effective unpredictability is far lower than its
length suggests. This project's pattern detector specifically forces
a WEAK classification when a single repeated/sequential pattern
dominates the password, regardless of length.

**7. What is O(n)?**
Big-O notation describing how an algorithm's work scales with input
size `n`. O(n) means work grows linearly — double the input, roughly
double the work, with no worse blow-up.

**8. Why use `any()`?**
`any(condition for c in password)` is idiomatic, readable, and
short-circuits on the first match — often faster in practice than a
full manual index-based scan, and never worse than O(n).

**9. What is a timing attack?**
An attack that infers secret information from how long an operation
takes, when the time taken depends on the secret value (e.g. a naive
string comparison that returns early on the first mismatched
character).

**10. Why use `hmac.compare_digest()`?**
It performs a constant-time comparison, so equal-length inputs take
the same time regardless of where they first differ, closing that
timing side channel. This project doesn't need it anywhere in its own
comparisons (see `docs/security-review.md` §6) but documents where it
would apply.

**11. Why use `getpass`?**
It reads terminal input without echoing it to the screen and without
placing it in shell history, unlike a plain `input()` or a
command-line argument.

**12. Why should passwords never be logged?**
Logs often persist far longer than intended, are frequently backed
up, and are read by more people/systems than the original
application — logging a password turns a transient secret into a
long-lived, widely-accessible one.

**13. What is the Python string immutability issue?**
Python strings can't be modified in place; "clearing" a string
variable just drops a reference — the original character data may
remain in memory (and could persist in swap, core dumps, or be
copied by the interpreter) until garbage collected and the memory
reused. This project documents this limitation rather than claiming
a fix it can't actually provide.

**14. What is k-anonymity?**
A privacy technique where you reveal only enough information to place
your query in a group ("anonymity set") of indistinguishable
possibilities, rather than the exact value. HIBP's Pwned Passwords
API implements this: you send a 5-character hash prefix and get back
every suffix sharing it, so the server can't tell which one you
actually have.

**15. Why does the breach check use only a hash prefix?**
So the plaintext password and even the full hash never leave the
local machine — the server only ever sees a prefix shared by
(typically) hundreds of different passwords, not enough to identify
which one you're checking.

**16. Why should breach checking be optional?**
Because it requires a network request to a third party, which some
users won't want to make regardless of the privacy design, and
because the tool should be fully usable offline.

**17. Why should passwords not be stored?**
Every stored copy of a password is a new place it can be stolen from.
"Analyze, don't store" eliminates that risk category entirely for
this tool rather than trying to secure a store that doesn't need to
exist.

**18. What is the limitation of theoretical entropy?**
It assumes random character selection; it cannot detect that a
character-diverse password is still a predictable word-plus-suffix
pattern. That's precisely why this project also runs independent
pattern and common-password checks.

**19. Why use a configurable policy?**
Security requirements vary by context and change over time.
Externalizing thresholds into `policy.json` lets them be reviewed,
audited, and adjusted without a code change or redeploy.

**20. What security limitations does this project have?**
The common-password list is a small educational sample, not
comprehensive. Entropy and crack-time are theoretical estimates, not
guarantees. Memory can't be reliably wiped in Python. Pattern
detection is heuristic, not exhaustive. None of these are hidden —
they're documented in the README and `docs/security-review.md`.
