# xss-contextual-scanner lab

A small, intentionally vulnerable Flask app for exercising the scanner's
full pipeline — including browser confirmation — against a real (but
harmless, localhost-only) target.

## Run it

```bash
pip install -e .[lab]
python lab/app.py
# listening on http://127.0.0.1:5002
```

Routes (all take `?q=`):

- `GET /` — links to every route below
- `GET /text` — reflects into HTML text (`<p>{q}</p>`)
- `GET /attribute` — reflects into an attribute value, unescaped
- `GET /attribute-encoded` — same attribute, but HTML-entity-encoded —
  the false-positive control case
- `GET /js-string` — reflects into a `<script>` string
- `GET /js-template` — reflects into a `<script>` template literal

## Try the scanner against it

```bash
xsscan -u "http://127.0.0.1:5002/text?q=x" -p q
xsscan -u "http://127.0.0.1:5002/attribute?q=x" -p q
xsscan -u "http://127.0.0.1:5002/js-string?q=x" -p q
xsscan -u "http://127.0.0.1:5002/js-template?q=x" -p q

# must NOT come back "confirmed" — quotes are HTML-encoded on output
xsscan -u "http://127.0.0.1:5002/attribute-encoded?q=x" -p q

# static-only mode: same targets, never reports "confirmed"
xsscan -u "http://127.0.0.1:5002/text?q=x" -p q --no-browser
```

Expect one `confirmed` finding per vulnerable route, and `likely` at most
(never `confirmed`) for `/attribute-encoded` and any `--no-browser` run.
