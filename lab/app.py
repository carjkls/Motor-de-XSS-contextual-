"""Intentionally vulnerable Flask app for exercising xss-contextual-scanner
locally. Every route below reflects its `q` query param unescaped into a
different syntactic context — do not deploy this anywhere reachable from
outside your own machine.

    pip install -e .[lab]
    python lab/app.py
"""

from __future__ import annotations

import html

from flask import Flask, request

app = Flask(__name__)


@app.get("/")
def index() -> str:
    links = "".join(
        f'<li><a href="/{route}?q=x">/{route}</a></li>'
        for route in ("text", "attribute", "attribute-encoded", "js-string", "js-template")
    )
    return f"<html><body><h1>xss-contextual-scanner lab</h1><ul>{links}</ul></body></html>"


@app.get("/text")
def text_route() -> str:
    q = request.args.get("q", "")
    return f"<html><body><p>{q}</p></body></html>"


@app.get("/attribute")
def attribute_route() -> str:
    q = request.args.get("q", "")
    return f'<html><body><input value="{q}"></body></html>'


@app.get("/attribute-encoded")
def attribute_encoded_route() -> str:
    q = html.escape(request.args.get("q", ""), quote=True)
    return f'<html><body><input value="{q}"></body></html>'


@app.get("/js-string")
def js_string_route() -> str:
    q = request.args.get("q", "")
    return f'<html><body><script>var x="{q}";</script></body></html>'


@app.get("/js-template")
def js_template_route() -> str:
    q = request.args.get("q", "")
    return "<html><body><script>var x=`hi " + q + "`;</script></body></html>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
