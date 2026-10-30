# xss-contextual-scanner

Reflected-XSS scanner that parses the real HTML/JS context a parameter
reflects into and generates a payload that's syntactically valid for that
exact context — instead of firing a fixed list of generic payloads
(`<script>alert(1)</script>` everywhere) and hoping one sticks. Execution is
then confirmed for real in a headless browser, not inferred from text.

> **Only scan systems you are authorized to test.** This tool injects
> script-executing payloads and loads the target's responses in a real
> (headless) browser.

## Install

```bash
pip install -e .
playwright install chromium   # one-time: installs the browser binary
```

Python 3.10+. Core dependencies: `httpx`, `beautifulsoup4`, `playwright`.

## Usage

```bash
# scan a query parameter, context detected + browser-confirmed
xsscan -u "https://target.example/search?q=hello"

# test one specific parameter
xsscan -u "https://target.example/search?q=hello" -p q

# POST with a JSON body
xsscan -u "https://target.example/api/preview" --method POST \
  --data '{"comment": "hi"}' -p '$.comment'

# static-only (no browser): reports "likely" context matches, never "confirmed"
xsscan -u "https://target.example/search?q=hello" --no-browser

# save a JSON report
xsscan -u "https://target.example/search?q=hello" -o report.json
```

Run `xsscan --help` for the full flag list.

## How it works

1. **Discovery** — harvests candidate parameters from the query string,
   HTML forms, and JSON body fields (same approach as `ssrf-scanner`).
2. **Static context triage** — injects a plain marker token, re-fetches,
   and parses the response to find exactly where and in what syntactic
   context the token reflects: HTML text, an HTML attribute, a URL
   attribute (`href`/`src`), an HTML comment, or inside a `<script>`
   block's string / template literal.
3. **Context-specific payload** — generates one payload per distinct
   context that closes out of that exact syntax (matching quote char,
   comment-terminating the rest of a JS line, `${}` for template
   literals, etc.) and sets a unique global marker when it runs.
4. **Browser confirmation** — re-injects the payload, loads the real
   response in headless Chromium, and reads the marker back. Only a
   marker that actually fired is reported as `confirmed`; everything else
   is `likely` at most.
5. **Reporting** — colored console output and optional JSON export.

## Testing against a local target

See [`lab/`](lab/) for a small intentionally-vulnerable Flask app with one
route per context type, for trying the full pipeline (including the
browser confirmation step) end to end on localhost.

## Known limitations (v1)

- **Reflected XSS only.** DOM-based (client-side sinks) and stored
  (persist-then-revisit) XSS are not covered yet.
- **CSS context is out of scope.** It's recognized by the classifier but
  never gets a payload — CSS doesn't execute JavaScript in modern
  browsers.
- The JS context classifier is a lightweight regex-based state machine,
  not a full parser/AST — it can misjudge minified JS or unusual
  automatic-semicolon-insertion edge cases. If that proves to be a real
  problem on real targets, swapping in a proper JS tokenizer is the next
  step.
- `url_attribute` findings (`href`/`src` with a `javascript:` payload)
  require a user click and are always reported as `likely`, never
  `confirmed` — the headless browser never clicks anything.
