# Screenshots

This folder is where portfolio/demo screenshots should live before you
push to GitHub. They were **not** auto-generated here because this
development sandbox has no GUI and no network access to a browser
binary (Playwright/Chromium downloads are blocked by the sandbox's
network allowlist) — this is being reported honestly rather than
faked with placeholder or mocked-up images.

Capture these locally (2 minutes, using only the safe fictional demo
passwords from `docs/demo.md` — never a real password):

1. `weak-result.png` — CLI or web output for `abc`
2. `medium-result.png` — CLI or web output for `Abcd1234!`
3. `strong-result.png` — CLI or web output for `Violet-River-72!Moon`
4. `pattern-detection.png` — CLI output for `Abcd1234!` showing the
   "Sequential pattern detected" lines
5. `common-password-detection.png` — CLI output for `password123`
6. `json-output.png` — output of `python -m password_checker --json`
7. `web-interface.png` — the Flask UI at `http://127.0.0.1:5000`
   after typing `Violet-River-72!Moon`

Quick capture commands:

```bash
# CLI screenshots: just run and screenshot your terminal
python -m password_checker --password-stdin <<< "abc"
python -m password_checker --password-stdin <<< "Abcd1234!"
python -m password_checker --password-stdin <<< "Violet-River-72!Moon"
python -m password_checker --json --password-stdin <<< "Violet-River-72!Moon"

# Web screenshot
python web/app.py
# then open http://127.0.0.1:5000 in a browser and screenshot it
```

Never use `--password-stdin` outside of scripted testing like this —
the default `getpass` prompt is the private option for real use.
