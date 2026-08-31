"""
web/app.py
==========

Optional Flask web interface for the Password Strength & Security
Analyzer. Reuses the exact same core analyzer used by the CLI --
no scoring logic is duplicated here.

PRIVACY DESIGN
---------------
The password is typed into the browser and analyzed via a POST to
this local Flask server, which calls the SAME pure `analyze_password`
function as the CLI and returns only the resulting
PasswordAnalysisResult JSON -- never the password itself.

The password is:
  - never written to a Flask/Werkzeug access log line (Flask's
    default access log only records the request path, not the body)
  - never stored in a session, cookie, database, or file
  - discarded by Python's garbage collector once the request
    handler returns

If you want a stricter, fully offline guarantee, see
static/analyzer.js for a client-side-only port of the same scoring
rules that never sends the password anywhere -- the templates use
that by default, with this Flask endpoint kept for demonstration /
as a fallback and for the docs/demo.md walkthrough.
"""

from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request

# Make the core package importable without requiring installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from password_checker.checker import InvalidPasswordInputError, analyze_password  # noqa: E402
from password_checker.policy import load_policy  # noqa: E402

app = Flask(__name__)
_POLICY = load_policy()


@app.after_request
def _no_cache(response):
    # Defense in depth: make sure nothing about this response (which
    # could theoretically be cached at the wrong layer) sticks around.
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    password = payload.get("password")

    try:
        result = analyze_password(password, policy=_POLICY)
    except InvalidPasswordInputError as exc:
        return jsonify({"error": str(exc)}), 400

    # result.to_dict() never includes the password itself (see checker.py).
    return jsonify(result.to_dict())


if __name__ == "__main__":
    # debug=False in any non-local scenario: Flask's debugger can
    # expose a Python console over the network if left on in
    # production, which is a serious risk far beyond password privacy.
    app.run(debug=False, port=5000)
