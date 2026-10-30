# Motor de XSS Contextual Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reflected-XSS scanner that parses the real HTML/JS context a parameter reflects into, generates a syntactically correct payload for that exact context, and proves exploitation by executing it in a real headless browser.

**Architecture:** Static httpx-based triage (reused from `ssrf-scanner`) discovers candidate parameters and the syntactic context each one reflects into; a context-to-payload generator builds one payload per distinct context; a Playwright-driven confirmation step re-injects each payload and reads back a global JS marker to prove real execution instead of inferring it from text.

**Tech Stack:** Python 3.10+, `httpx` (async HTTP), `beautifulsoup4` (HTML parsing), `playwright` (headless browser confirmation), stdlib `unittest` (no pytest dependency, matching `ssrf-scanner`).

**Spec:** `docs/superpowers/specs/2026-10-29-xss-contextual-engine-design.md`

**Git:** the user commits from their own terminal — no task includes a commit step. After each task's tests pass, stop and let the user commit before the next task starts.

## Global Constraints

- v1 covers **reflected XSS only** — no DOM-based, no stored.
- **CSS context is out of scope** — recognized by the classifier but never gets a payload (CSS can't execute JS in modern browsers).
- New, independent repo (`xss-contextual-scanner`) — no shared package extracted from `ssrf-scanner`; modules are copied and adapted.
- Confirmation uses a **global marker** (`window.__xss_<token>__`), never an `alert`/`dialog` hook.
- Context detection is the hybrid approach: static parse decides context AND does the first triage; the browser is only used to confirm payloads for contexts that were actually found.
- `--no-browser` must still run (static-only); it reports `likely` at most, **never** `confirmed`.
- `url_attribute` (`href`/`src`) payloads require a user click and are **always** `verdict="likely"`, never auto-confirmed.

## Review Focus

- A single response reflecting the probe token into two *different* context types (e.g. once in HTML text, once inside a `<script>` string) must produce a finding for each — not just the first match. → Task 5
- An attribute whose value is HTML-entity-encoded on output (quotes become `&quot;`) must never reach `verdict="confirmed"` even though the plain token still reflects — the breakout payload fails to execute and confirmation must report that honestly. → Task 12
- A parameter where the probe token isn't reflected at all must be skipped silently (no payload generated, no browser call wasted) rather than producing a false/empty finding. → Task 5, Task 8
- A payload reflected into a POST/JSON body (not a GET-navigable URL) must still be confirmable — `browser_confirm.py` has to accept a response body directly, not only a URL. → Task 7, Task 8
- Running without Playwright installed, and without `--no-browser`, must fail with one clear actionable message (not a raw traceback) telling the user to install it or pass `--no-browser`. → Task 10

---

## File Structure

```
xss-contextual-scanner/
  pyproject.toml
  requirements.txt
  .gitignore
  LICENSE
  README.md
  xss_scanner/
    __init__.py
    __main__.py
    cli.py
    core/
      __init__.py
      http_client.py        # adapted from ssrf-scanner
      discovery.py           # adapted from ssrf-scanner
      findings.py            # Finding dataclass + dedupe
      context.py              # ReflectionContext + find_reflection_contexts
      browser_confirm.py      # BrowserConfirmer (Playwright)
      scanner.py               # XSSScanner orchestrator
    payloads/
      __init__.py
      context_payloads.py     # ContextPayload + generate_payload
    reporting/
      __init__.py
      report.py                # console + JSON output
  lab/
    app.py                    # one Flask route per context type
    README.md
  tests/
    __init__.py
    test_discovery.py
    test_findings.py
    test_context.py
    test_context_payloads.py
    test_browser_confirm.py
    test_scanner.py
```

---

### Task 1: Project scaffold

**Files:**
- Create: `pyproject.toml`, `requirements.txt`, `.gitignore`, `LICENSE`, `README.md`
- Create: `xss_scanner/__init__.py`, `xss_scanner/__main__.py`
- Create: `xss_scanner/core/__init__.py`, `xss_scanner/payloads/__init__.py`, `xss_scanner/reporting/__init__.py`
- Create: `tests/__init__.py`

**Interfaces:**
- Produces: installable package `xss_scanner` with `__version__ = "0.1.0"`; console entrypoint `xsscan` (wired now, implemented in Task 10).

- [ ] **Step 1: Write `pyproject.toml`**

Mirror `ssrf-scanner`'s structure: `[build-system]` setuptools, `[project]` name `xss-contextual-scanner`, `requires-python = ">=3.10"`, `dependencies = ["httpx>=0.27,<1.0", "beautifulsoup4>=4.12", "playwright>=1.40,<2.0"]`, `[project.optional-dependencies] lab = ["flask>=3.0"]`, `[project.scripts] xsscan = "xss_scanner.cli:main"`, `[tool.setuptools.packages.find] include = ["xss_scanner*"]`.

- [ ] **Step 2: Write `requirements.txt`**

`httpx>=0.27,<1.0`, `beautifulsoup4>=4.12`, `playwright>=1.40,<2.0`, and a comment noting `flask>=3.0` is only for `lab/`.

- [ ] **Step 3: Write `.gitignore`**

Copy `ssrf-scanner`'s `.gitignore` verbatim (`__pycache__/`, `*.py[cod]`, `*.egg-info/`, `build/`, `dist/`, `.venv/`, `venv/`, `.pytest_cache/`, `reports/`, `*.json.report`, `.DS_Store`).

- [ ] **Step 4: Write `LICENSE`**

Same MIT license as `ssrf-scanner`.

- [ ] **Step 5: Write `README.md`**

Cover: what the tool does and why ("contextual" — parses the real reflection context instead of firing a fixed payload list), the authorized-use-only disclaimer (same wording style as `ssrf-scanner`'s), install instructions including `pip install -e .` **and** `playwright install chromium` (required once for the browser confirmation step), usage examples for `-u`, `--method POST --data`, `-p`, `--no-browser`, `-o`, a short "how it works" section matching the spec's pipeline (discovery → static context triage → context-specific payload → browser confirmation → report), and a pointer to `lab/README.md` for local end-to-end testing. Note the v1 scope limits from the spec's "Fora de escopo" section explicitly (no DOM-based/stored XSS, no CSS context).

- [ ] **Step 6: Write package skeleton**

`xss_scanner/__init__.py`: `"""xss-contextual-scanner: reflected XSS scanner with context-aware payload generation."""` + `__version__ = "0.1.0"` + `__all__ = ["__version__"]`. `xss_scanner/__main__.py`: `from .cli import main` + `if __name__ == "__main__": raise SystemExit(main())`. Empty docstring-only `__init__.py` for `core/`, `payloads/`, `reporting/` (one-line module docstring each, same style as `ssrf-scanner`). `tests/__init__.py` empty.

- [ ] **Step 7: Verify the package installs**

Run: `pip install -e .`
Expected: succeeds with no errors (confirms `pyproject.toml` is well-formed and `README.md` exists, since `readme = "README.md"` would otherwise break the build — this was the exact bug found and fixed in `ssrf-scanner`).


---

### Task 2: `core/http_client.py`

**Files:**
- Create: `xss_scanner/core/http_client.py`
- Test: `tests/test_http_client.py`

**Interfaces:**
- Produces: `HTTPResult` dataclass (`url: str`, `status_code: int = 0`, `body: str = ""`, `headers: dict[str, str]`, `elapsed: float = 0.0`, `error: str | None = None`, property `ok`), `AsyncHTTPClient` async-context-manager class with `.get(url, params=None, headers=None)` and `.post(url, data=None, json_body=None, headers=None)`, both returning `HTTPResult`.

- [ ] **Step 1: Copy `ssrf-scanner`'s `core/http_client.py` verbatim into `xss_scanner/core/http_client.py`**

No behavioral changes — same async `httpx` wrapper, same bounded concurrency via `asyncio.Semaphore`, same transport-error-to-`HTTPResult.error` capture. Only change: default `user_agent="xsscan/0.1"`.

- [ ] **Step 2: Write a smoke test**

```python
class HTTPResultTest(unittest.IsolatedAsyncioTestCase):
    async def test_get_returns_result_with_body(self):
        async with AsyncHTTPClient() as client:
            result = await client.get("https://example.com")
        self.assertTrue(result.ok)
        self.assertIn("Example Domain", result.body)
```

(Network-dependent, same tradeoff `ssrf-scanner` never needed to test since it had no dedicated `http_client` test — this one test exists here only to prove the copy wires correctly end-to-end.)

- [ ] **Step 3: Run test to verify it passes**

Run: `python -m unittest tests.test_http_client -v`
Expected: PASS (requires network access; if offline, skip this test with `@unittest.skipUnless` on a reachability check — implementer's call)


---

### Task 3: `core/discovery.py`

**Files:**
- Create: `xss_scanner/core/discovery.py`
- Test: `tests/test_discovery.py`

**Interfaces:**
- Produces: `CandidateParam` dataclass (`location: str`, `name: str`, `original_value: str`, `method: str`, `priority: int`), `discover_candidates(target_url, html_body=None, json_body=None) -> list[CandidateParam]`, `inject_query_param(url, name, value) -> str`, `inject_json_path(body, path, value) -> str`.

- [ ] **Step 1: Copy `ssrf-scanner`'s `core/discovery.py` verbatim into `xss_scanner/core/discovery.py`**

No behavioral changes — same `URL_PARAM_HINTS`-based ranking, same query/HTML-form/JSON-body harvesting. This module doesn't need SSRF-specific knowledge; parameter discovery is identical for XSS.

- [ ] **Step 2: Write tests covering the three discovery sources**

```python
def test_from_query_string_finds_params(self):
    candidates = from_query_string("https://t/x?q=hi&id=1")
    self.assertEqual({c.name for c in candidates}, {"q", "id"})

def test_inject_query_param_replaces_value(self):
    url = inject_query_param("https://t/x?q=hi", "q", "PAYLOAD")
    self.assertIn("q=PAYLOAD", url)

def test_from_json_body_tracks_json_path(self):
    candidates = from_json_body('{"a": {"b": "hi"}}')
    self.assertEqual(candidates[0].name, "$.a.b")
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `python -m unittest tests.test_discovery -v`
Expected: PASS


---

### Task 4: `core/findings.py`

**Files:**
- Create: `xss_scanner/core/findings.py`
- Test: `tests/test_findings.py`

**Interfaces:**
- Produces:
  ```python
  @dataclass
  class Finding:
      title: str
      severity: str        # "critical" | "medium" | "low"
      verdict: str          # "confirmed" | "likely" | "info"
      request_url: str
      param_name: str
      param_location: str
      context_type: str
      payload_value: str
      evidence: str = ""
      def sort_key(self) -> tuple[int, str]: ...

  def dedupe(findings: list[Finding]) -> list[Finding]: ...
  ```
- Severity mapping fixed by this task (not in the spec, decided here for consistency): `verdict="confirmed"` → `severity="critical"`; `verdict="likely"` → `severity="medium"`; `verdict="info"` → `severity="low"`. `SEVERITY_ORDER = {"critical": 2, "medium": 1, "low": 0}` drives `sort_key`.

- [ ] **Step 1: Write failing tests**

```python
def test_sort_key_orders_critical_first(self):
    confirmed = Finding(title="a", severity="critical", verdict="confirmed",
                         request_url="u", param_name="p", param_location="query",
                         context_type="html_text", payload_value="x")
    likely = Finding(title="b", severity="medium", verdict="likely",
                      request_url="u", param_name="p", param_location="query",
                      context_type="html_attribute", payload_value="y")
    ordered = sorted([likely, confirmed], key=lambda f: f.sort_key())
    self.assertEqual(ordered[0].verdict, "confirmed")

def test_dedupe_collapses_same_param_and_context(self):
    make = lambda payload: Finding(title="t", severity="critical", verdict="confirmed",
                                    request_url="u" + payload, param_name="q",
                                    param_location="query", context_type="html_text",
                                    payload_value=payload)
    findings = [make("<script>a</script>"), make("<script>b</script>")]
    self.assertEqual(len(dedupe(findings)), 1)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_findings -v`
Expected: FAIL (`Finding`/`dedupe` not defined)

- [ ] **Step 3: Implement `Finding` and `dedupe(findings: list[Finding]) -> list[Finding]` in `xss_scanner/core/findings.py`**

`dedupe` keys on `(severity, context_type, param_name, param_location)` — same param reflecting the same context type twice (e.g. two near-identical payload variants) collapses to one finding, same pattern as `ssrf-scanner`'s `detector.dedupe`. Keep the first finding seen per key, return sorted by `sort_key()`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_findings -v`
Expected: PASS


---

### Task 5: `core/context.py`

**Files:**
- Create: `xss_scanner/core/context.py`
- Test: `tests/test_context.py`

**Interfaces:**
- Produces:
  ```python
  @dataclass(frozen=True)
  class ReflectionContext:
      context_type: str   # "html_text" | "html_attribute" | "url_attribute" |
                            # "html_comment" | "css" | "js_string" |
                            # "js_template_literal" | "unknown"
      tag_name: str | None = None
      attribute_name: str | None = None
      quote_char: str | None = None   # '"' | "'" | "`" | None (unquoted attr)

  def find_reflection_contexts(html: str, token: str) -> list[ReflectionContext]: ...
  ```
- Consumes: nothing from earlier tasks (pure function over HTML text + a token string).

- [ ] **Step 1: Write failing tests, one per context type**

```python
def test_html_text_context(self):
    ctx = find_reflection_contexts("<p>hello TOK world</p>", "TOK")
    self.assertEqual(ctx, [ReflectionContext("html_text", tag_name="p")])

def test_html_attribute_double_quote(self):
    ctx = find_reflection_contexts('<input value="TOK">', "TOK")
    self.assertEqual(ctx, [ReflectionContext("html_attribute", tag_name="input",
                                              attribute_name="value", quote_char='"')])

def test_html_attribute_single_quote(self):
    ctx = find_reflection_contexts("<input value='TOK'>", "TOK")
    self.assertEqual(ctx[0].quote_char, "'")

def test_html_attribute_unquoted(self):
    ctx = find_reflection_contexts("<input value=TOK>", "TOK")
    self.assertIsNone(ctx[0].quote_char)

def test_url_attribute_href(self):
    ctx = find_reflection_contexts('<a href="TOK">x</a>', "TOK")
    self.assertEqual(ctx[0].context_type, "url_attribute")

def test_html_comment(self):
    ctx = find_reflection_contexts("<!-- TOK -->", "TOK")
    self.assertEqual(ctx[0].context_type, "html_comment")

def test_css_style_tag_is_recognized_but_out_of_scope(self):
    ctx = find_reflection_contexts("<style>body{color:TOK}</style>", "TOK")
    self.assertEqual(ctx[0].context_type, "css")

def test_css_style_attribute(self):
    ctx = find_reflection_contexts('<div style="color:TOK">x</div>', "TOK")
    self.assertEqual(ctx[0].context_type, "css")

def test_js_string_double_quote(self):
    ctx = find_reflection_contexts('<script>var x="TOK";</script>', "TOK")
    self.assertEqual(ctx[0], ReflectionContext("js_string", quote_char='"'))

def test_js_string_single_quote(self):
    ctx = find_reflection_contexts("<script>var x='TOK';</script>", "TOK")
    self.assertEqual(ctx[0].quote_char, "'")

def test_js_template_literal(self):
    ctx = find_reflection_contexts("<script>var x=`hi TOK`;</script>", "TOK")
    self.assertEqual(ctx[0].context_type, "js_template_literal")

def test_js_unknown_for_raw_code_position(self):
    ctx = find_reflection_contexts("<script>var TOK = 1;</script>", "TOK")
    self.assertEqual(ctx[0].context_type, "unknown")

def test_js_token_inside_comment_is_unknown(self):
    ctx = find_reflection_contexts("<script>// TOK\nvar x=1;</script>", "TOK")
    self.assertEqual(ctx[0].context_type, "unknown")

def test_token_not_found_returns_empty_list(self):
    self.assertEqual(find_reflection_contexts("<p>hello</p>", "TOK"), [])

def test_token_in_two_distinct_contexts_returns_both(self):
    html = '<p>TOK</p><script>var x="TOK";</script>'
    types = {c.context_type for c in find_reflection_contexts(html, "TOK")}
    self.assertEqual(types, {"html_text", "js_string"})

def test_identical_contexts_are_deduped(self):
    html = "<p>TOK</p><p>TOK again</p>"
    self.assertEqual(len(find_reflection_contexts(html, "TOK")), 1)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_context -v`
Expected: FAIL (`find_reflection_contexts` not defined)

- [ ] **Step 3: Implement `find_reflection_contexts` in `xss_scanner/core/context.py`**

Parse `html` with `BeautifulSoup(html, "html.parser")`.

*HTML/text/comment/attribute pass* (walk the parsed tree):
- For every `bs4.Comment` node containing `token`: emit `("html_comment", tag_name=None, attribute_name=None, quote_char=None)`.
- For every other `NavigableString` containing `token` whose parent tag is not `script`/`style`: if the parent is `style`, emit `context_type="css"`; otherwise emit `"html_text"` with `tag_name=parent.name`.
- For every tag's attribute whose value (handle both plain strings and the list form BeautifulSoup uses for multi-valued attributes like `class`) contains `token`: `attribute_name` is lowercased; `context_type` is `"css"` if `attribute_name == "style"`, `"url_attribute"` if `attribute_name in {"href", "src"}`, else `"html_attribute"`. Determine `quote_char` by regex-searching the **raw `html` string** (not the parsed tree — BeautifulSoup normalizes away the original quoting) for `rf'{attribute_name}\s*=\s*(["\']?){re.escape(token)}'`; group 1 is `'"'`, `"'"`, or `''` (empty → unquoted, store `None`).

*Script pass* (for every `<script>` tag whose text contains `token`): scan the script text as a single pass character state machine with states `NONE, SINGLE, DOUBLE, TEMPLATE, LINE_COMMENT, BLOCK_COMMENT`. From `NONE`: `//` → `LINE_COMMENT` (exits on `\n`); `/*` → `BLOCK_COMMENT` (exits on `*/`); `'` → `SINGLE`; `"` → `DOUBLE`; `` ` `` → `TEMPLATE`. Inside `SINGLE`/`DOUBLE`/`TEMPLATE`, a `\` escapes the next character (skip it without changing state); the matching quote char returns to `NONE`. For every occurrence of `token` in the script text (`str.find` in a loop, advancing past each match), record the state active at that occurrence's start index. Map state → context: `SINGLE`/`DOUBLE` → `"js_string"` with `quote_char` = that quote; `TEMPLATE` → `"js_template_literal"` with `quote_char="`"`; anything else → `"unknown"`.

*Dedupe*: collapse entries with identical `(context_type, tag_name, attribute_name, quote_char)`, keeping the first occurrence found, preserving discovery order.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_context -v`
Expected: PASS


---

### Task 6: `payloads/context_payloads.py`

**Files:**
- Create: `xss_scanner/payloads/context_payloads.py`
- Test: `tests/test_context_payloads.py`

**Interfaces:**
- Consumes: `ReflectionContext` from Task 5 (`xss_scanner.core.context`).
- Produces:
  ```python
  @dataclass(frozen=True)
  class ContextPayload:
      context_type: str
      value: str        # exact string to inject into the parameter
      token: str          # the unique marker embedded in `value`
      auto_fires: bool    # False only for "url_attribute"

  def generate_payload(context: ReflectionContext) -> ContextPayload | None: ...
  ```

- [ ] **Step 1: Write failing tests, one per context type plus the `None` cases**

```python
def test_html_text_payload(self):
    p = generate_payload(ReflectionContext("html_text", tag_name="p"))
    self.assertEqual(p.value, f"<script>window.__xss_{p.token}__=1</script>")
    self.assertTrue(p.auto_fires)

def test_html_attribute_double_quote_payload(self):
    ctx = ReflectionContext("html_attribute", attribute_name="value", quote_char='"')
    p = generate_payload(ctx)
    self.assertEqual(p.value, f'" autofocus onfocus="window.__xss_{p.token}__=1')

def test_html_attribute_single_quote_payload(self):
    ctx = ReflectionContext("html_attribute", attribute_name="value", quote_char="'")
    p = generate_payload(ctx)
    self.assertEqual(p.value, f"' autofocus onfocus='window.__xss_{p.token}__=1")

def test_html_attribute_unquoted_payload(self):
    ctx = ReflectionContext("html_attribute", attribute_name="value", quote_char=None)
    p = generate_payload(ctx)
    self.assertEqual(p.value, f" onfocus=window.__xss_{p.token}__=1 autofocus")

def test_url_attribute_payload_does_not_auto_fire(self):
    p = generate_payload(ReflectionContext("url_attribute", attribute_name="href"))
    self.assertEqual(p.value, f"javascript:window.__xss_{p.token}__=1")
    self.assertFalse(p.auto_fires)

def test_html_comment_payload(self):
    p = generate_payload(ReflectionContext("html_comment"))
    self.assertEqual(p.value, f"--><script>window.__xss_{p.token}__=1</script><!--")

def test_js_string_payload(self):
    ctx = ReflectionContext("js_string", quote_char='"')
    p = generate_payload(ctx)
    self.assertEqual(p.value, f'";window.__xss_{p.token}__=1;//')

def test_js_template_literal_payload(self):
    p = generate_payload(ReflectionContext("js_template_literal"))
    self.assertEqual(p.value, "${(window.__xss_" + p.token + "__=1,'')}")

def test_css_and_unknown_return_none(self):
    self.assertIsNone(generate_payload(ReflectionContext("css")))
    self.assertIsNone(generate_payload(ReflectionContext("unknown")))

def test_token_is_unique_per_call(self):
    p1 = generate_payload(ReflectionContext("html_text"))
    p2 = generate_payload(ReflectionContext("html_text"))
    self.assertNotEqual(p1.token, p2.token)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_context_payloads -v`
Expected: FAIL (`generate_payload` not defined)

- [ ] **Step 3: Implement `generate_payload` in `xss_scanner/payloads/context_payloads.py`**

Generate `token = uuid.uuid4().hex[:12]` (same pattern as `ssrf-scanner`'s `_token()`), then dispatch on `context.context_type` to the exact templates fixed by the tests above. `auto_fires=False` only for `"url_attribute"`; `True` for every other generated payload; `None` for `"css"` and `"unknown"` (and any other unrecognized `context_type`, defensively).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_context_payloads -v`
Expected: PASS


---

### Task 7: `core/browser_confirm.py`

**Files:**
- Create: `xss_scanner/core/browser_confirm.py`
- Test: `tests/test_browser_confirm.py`

**Interfaces:**
- Consumes: nothing from earlier tasks directly (takes a URL or raw HTML body + a token string).
- Produces:
  ```python
  class BrowserConfirmer:
      def __init__(self, timeout: float = 5.0, grace_period: float = 0.5) -> None: ...
      async def __aenter__(self) -> "BrowserConfirmer": ...
      async def __aexit__(self, *exc_info) -> None: ...
      async def confirm(self, *, token: str, url: str | None = None,
                         html_body: str | None = None) -> bool: ...
  class BrowserUnavailableError(RuntimeError): ...
  ```
  Exactly one of `url`/`html_body` is required; `confirm` raises `ValueError` if both or neither are given. `BrowserUnavailableError` is raised from `__aenter__` when Playwright's browser binaries aren't installed, with a message telling the user to run `playwright install chromium` or pass `--no-browser`.

- [ ] **Step 1: Write a prerequisite note, then failing tests**

Document in the test file header: these tests require `playwright install chromium` to have been run once; `pip install -e .` alone is not enough (Playwright ships the Python bindings but not the browser binary).

```python
class BrowserConfirmerTest(unittest.IsolatedAsyncioTestCase):
    async def test_confirm_detects_marker_from_html_body(self):
        async with BrowserConfirmer() as confirmer:
            html = '<script>window.__xss_abc123__=1</script>'
            self.assertTrue(await confirmer.confirm(token="abc123", html_body=html))

    async def test_confirm_returns_false_when_marker_absent(self):
        async with BrowserConfirmer() as confirmer:
            html = "<p>no payload here</p>"
            self.assertFalse(await confirmer.confirm(token="abc123", html_body=html))

    async def test_confirm_detects_marker_triggered_by_autofocus(self):
        async with BrowserConfirmer() as confirmer:
            html = '<input autofocus onfocus="window.__xss_abc123__=1">'
            self.assertTrue(await confirmer.confirm(token="abc123", html_body=html))

    async def test_confirm_requires_exactly_one_of_url_or_html_body(self):
        async with BrowserConfirmer() as confirmer:
            with self.assertRaises(ValueError):
                await confirmer.confirm(token="abc123")
            with self.assertRaises(ValueError):
                await confirmer.confirm(token="abc123", url="http://x", html_body="<p></p>")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_browser_confirm -v`
Expected: FAIL (`BrowserConfirmer` not defined)

- [ ] **Step 3: Implement `BrowserConfirmer` in `xss_scanner/core/browser_confirm.py`**

`__aenter__` starts `playwright.async_api.async_playwright()`, launches `chromium.launch(headless=True)`; wrap the launch in `try/except` and raise `BrowserUnavailableError` with the install hint if it fails with Playwright's "executable doesn't exist" error. `__aexit__` closes the browser and stops the Playwright driver. `confirm()`: validate exactly one of `url`/`html_body`; open a fresh `browser.new_context()` + `context.new_page()` (isolation per call); `page.goto(url, timeout=self.timeout*1000)` or `page.set_content(html_body, timeout=self.timeout*1000)`; `await page.wait_for_timeout(self.grace_period*1000)` to let `autofocus`/`onfocus`-style payloads fire; read back with `await page.evaluate("t => window['__xss_' + t + '__'] === 1", token)` (pass `token` as an argument rather than string-building the JS, even though the token is already a safe hex string); close the context; return the boolean. Catch navigation/timeout exceptions and return `False` rather than propagating (a probe that fails to load is not a confirmed XSS).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_browser_confirm -v`
Expected: PASS


---

### Task 8: `core/scanner.py`

**Files:**
- Create: `xss_scanner/core/scanner.py`
- Test: `tests/test_scanner.py`

**Interfaces:**
- Consumes: `discover_candidates`, `CandidateParam`, `inject_query_param`, `inject_json_path` (Task 3); `AsyncHTTPClient`, `HTTPResult` (Task 2); `find_reflection_contexts`, `ReflectionContext` (Task 5); `generate_payload`, `ContextPayload` (Task 6); `BrowserConfirmer`, `BrowserUnavailableError` (Task 7); `Finding`, `dedupe` (Task 4).
- Produces:
  ```python
  @dataclass
  class ScanConfig:
      target_url: str
      method: str = "GET"
      body: str | None = None
      content_type: str | None = None
      explicit_param: str | None = None
      timeout: float = 10.0
      concurrency: int = 10
      max_params: int = 12
      grace_period: float = 0.5
      no_browser: bool = False
      insecure_tls: bool = False
      verbose: bool = False

  class XSSScanner:
      def __init__(self, config: ScanConfig) -> None: ...
      async def run(self) -> list[Finding]: ...
  ```

- [ ] **Step 1: Write failing integration tests against a tiny in-process HTTP server**

Use `tests/helpers.py` (new, trivial `http.server`-based fixture) to serve pages that reflect input unescaped, so tests don't depend on `lab/` (built in Task 11) or network access.

```python
class XSSScannerTest(unittest.IsolatedAsyncioTestCase):
    async def test_confirmed_finding_for_reflected_html_text(self):
        with start_echo_server() as base_url:  # helpers.py: GET /?q=... echoes q into <p>
            config = ScanConfig(target_url=f"{base_url}/?q=x", max_params=1)
            scanner = XSSScanner(config)
            findings = await scanner.run()
        self.assertTrue(any(f.verdict == "confirmed" for f in findings))

    async def test_no_browser_mode_never_confirms(self):
        with start_echo_server() as base_url:
            config = ScanConfig(target_url=f"{base_url}/?q=x", max_params=1, no_browser=True)
            scanner = XSSScanner(config)
            findings = await scanner.run()
        self.assertTrue(all(f.verdict != "confirmed" for f in findings))

    async def test_non_reflecting_param_produces_no_finding(self):
        with start_static_server() as base_url:  # helpers.py: GET /?q=... ignores q, static body
            config = ScanConfig(target_url=f"{base_url}/?q=x", max_params=1)
            scanner = XSSScanner(config)
            findings = await scanner.run()
        self.assertEqual(findings, [])

    async def test_confirmed_finding_for_post_json_reflected_into_script(self):
        # helpers.py: POST / with {"q": "..."} echoes q unescaped into
        # <script>var x="{q}";</script> in the response body.
        with start_json_echo_server() as base_url:
            config = ScanConfig(
                target_url=base_url, method="POST", body='{"q": "x"}',
                content_type="application/json", explicit_param="$.q",
            )
            scanner = XSSScanner(config)
            findings = await scanner.run()
        self.assertTrue(any(f.verdict == "confirmed" for f in findings))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_scanner -v`
Expected: FAIL (`XSSScanner` not defined)

- [ ] **Step 3: Implement `tests/helpers.py`'s `start_echo_server`/`start_static_server`/`start_json_echo_server`**

Small context managers wrapping `http.server.HTTPServer` + `BaseHTTPRequestHandler` on a background thread, bound to `127.0.0.1:0` (OS-assigned free port), yielding the base URL. `start_echo_server` reflects the `q` query param unescaped into `<p>{q}</p>`; `start_static_server` returns a fixed body ignoring query params; `start_json_echo_server` handles `POST /` with a JSON body, reads `q` from it, and reflects it unescaped into `<script>var x="{q}";</script>`.

- [ ] **Step 4: Implement `XSSScanner.run()` in `xss_scanner/core/scanner.py`**

Per the spec's data-flow section: construct `AsyncHTTPClient(timeout=config.timeout, concurrency=config.concurrency, verify_tls=not config.insecure_tls)` and use it for every fetch in this run. Fetch baseline (GET, or POST with `config.body`/`config.content_type` if `method == "POST"`); call `discover_candidates` (filtered to `config.explicit_param` if set, capped at `config.max_params`, same pattern as `ssrf-scanner`'s scanner); for each candidate, build a request with a plain alnum probe token injected (`uuid.uuid4().hex[:12]`, via `inject_query_param`/`inject_json_path`/form data depending on `candidate.location`), fetch it, run `find_reflection_contexts(result.body, probe_token)` — skip the candidate entirely if the list is empty; for each distinct `ReflectionContext`, call `generate_payload`; skip `None` results (css/unknown); re-inject `payload.value` into the same parameter and fetch again to get the real request URL (GET) or response body (POST/JSON); if `config.no_browser` or `context_type == "url_attribute"`, emit a `Finding` with `verdict="likely"` directly (no browser call); otherwise call `BrowserConfirmer.confirm(token=payload.token, url=<GET url> or html_body=<POST response body>)` and set `verdict="confirmed"` if `True` else `"likely"`. Open one `BrowserConfirmer` for the whole run (not one per payload) when browser confirmation is needed at all. If Playwright raises `BrowserUnavailableError` and `no_browser` is `False`, propagate it (Task 10 turns it into the CLI's clear error message).

Build each `Finding` with `title=f"Reflected XSS ({context.context_type})"`, `request_url` = the URL/endpoint the confirming request was sent to, `param_name`/`param_location` from the candidate, `context_type` from the `ReflectionContext`, `payload_value=payload.value`, and `evidence` naming what was checked, e.g. `f"attribute={context.attribute_name!r} tag={context.tag_name!r} quote={context.quote_char!r}; browser marker window.__xss_{payload.token}__ {'fired' if confirmed else 'did not fire'}"` (adapt wording for the `no_browser`/`url_attribute` likely-without-browser cases, where no marker check happened at all). Return `dedupe(findings)`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m unittest tests.test_scanner -v`
Expected: PASS


---

### Task 9: `reporting/report.py`

**Files:**
- Create: `xss_scanner/reporting/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `Finding` (Task 4).
- Produces: `print_findings(findings: list[Finding], target: str) -> None`, `findings_to_json(findings: list[Finding]) -> str`, `save_json(findings: list[Finding], path: str) -> None`.

- [ ] **Step 1: Copy `ssrf-scanner`'s `reporting/report.py`, adapted to this `Finding` shape**

Same console layout (colored severity badge, one block per finding) and same `json.dumps(dataclasses.asdict(...))` JSON export, but the printed fields are `context` (was `payload category`/`provider`) and `payload` instead of the SSRF-specific `baseline_status`/`result_status`/`elapsed` fields, which this `Finding` doesn't have.

- [ ] **Step 2: Write a smoke test**

```python
def test_findings_to_json_round_trips(self):
    finding = Finding(title="t", severity="critical", verdict="confirmed",
                       request_url="u", param_name="q", param_location="query",
                       context_type="html_text", payload_value="<script>x</script>")
    data = json.loads(findings_to_json([finding]))
    self.assertEqual(data[0]["context_type"], "html_text")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m unittest tests.test_report -v`
Expected: FAIL

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_report -v`
Expected: PASS


---

### Task 10: `cli.py`

**Files:**
- Create: `xss_scanner/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `ScanConfig`, `XSSScanner` (Task 8); `BrowserUnavailableError` (Task 7); `print_findings`, `save_json` (Task 9); `__version__` (Task 1).
- Produces: `build_parser() -> argparse.ArgumentParser`, `main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1: Write failing tests for argument parsing**

```python
def test_build_parser_requires_url(self):
    with self.assertRaises(SystemExit):
        build_parser().parse_args([])

def test_build_parser_defaults(self):
    args = build_parser().parse_args(["-u", "http://t/?q=1"])
    self.assertEqual(args.method, "GET")
    self.assertFalse(args.no_browser)
    self.assertEqual(args.max_params, 12)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_cli -v`
Expected: FAIL (`build_parser` not defined)

- [ ] **Step 3: Implement `build_parser()` and `main()` in `xss_scanner/cli.py`**

Flags mirroring `ssrf-scanner`'s `cli.py`: `-u/--url` (required), `--method` (`GET`/`POST`, default `GET`), `--data` (dest `body`), `--content-type`, `-p/--param`, `--timeout` (default `10.0`), `--concurrency` (default `10`), `--max-params` (default `12`), `--grace-period` (default `0.5`), `--no-browser` (`store_true`), `--insecure` (`store_true`), `-o/--output`, `--verbose/-v`, `--version`. `main()` builds `ScanConfig` from the parsed args, runs `asyncio.run(XSSScanner(config).run())` inside a `try/except BrowserUnavailableError as exc`, printing `str(exc)` (which already carries the `playwright install chromium` / `--no-browser` hint from Task 7) to `stderr` and returning `2` instead of letting the traceback surface. Prints findings via `print_findings`, writes `-o` JSON via `save_json`, returns `0` if findings exist else `1` (matching `ssrf-scanner`'s convention), `130` on `KeyboardInterrupt`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_cli -v`
Expected: PASS

- [ ] **Step 5: Manually verify the `BrowserUnavailableError` path reads clearly**

Run: `xsscan -u "http://127.0.0.1:1/?q=1"` in an environment where `playwright install chromium` has **not** been run.
Expected: a one- or two-line message naming `playwright install chromium` and `--no-browser`, exit code `2` — no raw traceback.


---

### Task 11: `lab/app.py`

**Files:**
- Create: `lab/app.py`, `lab/README.md`
- Test: `tests/test_lab_app.py`

**Interfaces:**
- Produces: a Flask app with one route per context type, each reflecting its query param **unescaped** in that exact context, plus one route that **does** HTML-entity-encode quotes (for the Review Focus false-positive check in Task 12).

- [ ] **Step 1: Write failing tests using Flask's test client (no live server needed)**

```python
class LabAppTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_text_route_reflects_unescaped(self):
        resp = self.client.get("/text?q=<mark>")
        self.assertIn(b"<mark>", resp.data)

    def test_attribute_route_reflects_unescaped(self):
        resp = self.client.get('/attribute?q="')
        self.assertIn(b'value="\"', resp.data)  # raw quote breaks the attribute

    def test_js_string_route_reflects_unescaped(self):
        resp = self.client.get("/js-string?q=');alert(1);//")
        self.assertIn(b"');alert(1);//", resp.data)

    def test_attribute_encoded_route_escapes_quotes(self):
        resp = self.client.get('/attribute-encoded?q="')
        self.assertNotIn(b'value="\"', resp.data)
        self.assertIn(b"&#34;", resp.data)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m unittest tests.test_lab_app -v`
Expected: FAIL (`app` not defined / routes missing)

- [ ] **Step 3: Implement `lab/app.py`**

Flask app, `host="127.0.0.1", port=5002`. Routes, each taking `?q=`:
- `GET /text` → `f"<p>{q}</p>"` built with raw string formatting (not Jinja autoescaping — the point is to be deliberately unescaped), reflecting into HTML text context.
- `GET /attribute` → `f'<input value="{q}">'`, HTML attribute context.
- `GET /attribute-encoded` → uses `html.escape(q, quote=True)` before interpolating into the same `value="{q}"` template — the control case for the Review Focus false-positive test.
- `GET /js-string` → `f'<script>var x="{q}";</script>'`, JS string context.
- `GET /js-template` → `` f'<script>var x=`hi {q}`;</script>' ``, JS template literal context.
- `GET /` → links to all of the above (same pattern as `ssrf-scanner`'s lab index, useful for manual poking).

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_lab_app -v`
Expected: PASS

- [ ] **Step 5: Write `lab/README.md`**

Same shape as `ssrf-scanner`'s `lab/README.md`: how to run it (`pip install -e .[lab]`, `python lab/app.py`), the route list, and the exact `xsscan` commands to try against each one (including `-u "http://127.0.0.1:5002/attribute-encoded?q=x" -p q` as the "must NOT confirm" case).


---

### Task 12: End-to-end verification against the lab

**Files:**
- Modify: none (manual + scripted verification pass; any bug found gets fixed in the task/file it belongs to, same as the `ssrf-scanner` false-positive fix found during its own end-to-end pass)

**Interfaces:**
- Consumes: everything (Tasks 1–11).

- [ ] **Step 1: Install the Playwright browser binary**

Run: `playwright install chromium`
Expected: succeeds (one-time setup, documented in `README.md` from Task 1)

- [ ] **Step 2: Start the lab app**

Run: `python lab/app.py` (background)
Expected: listening on `http://127.0.0.1:5002`

- [ ] **Step 3: Run `xsscan` against each context route and verify `confirmed` verdicts**

Run, for each of `/text`, `/attribute`, `/js-string`, `/js-template`:
`xsscan -u "http://127.0.0.1:5002/<route>?q=x" -p q`
Expected: one finding per route, `verdict=confirmed`, `context_type` matching the route's context.

- [ ] **Step 4: Verify the encoded-attribute false-positive guard (Review Focus item)**

Run: `xsscan -u "http://127.0.0.1:5002/attribute-encoded?q=x" -p q`
Expected: either no finding, or a finding with `verdict="likely"` — **never** `verdict="confirmed"`.

- [ ] **Step 5: Verify `--no-browser` never confirms**

Run: `xsscan -u "http://127.0.0.1:5002/text?q=x" -p q --no-browser`
Expected: a `likely` finding (context detected, no execution proof), not `confirmed`.

- [ ] **Step 6: Verify the full automated suite passes**

Run: `python -m unittest discover -s tests -v`
Expected: all tests pass (network-dependent `test_http_client` aside)

- [ ] **Step 7: Fix any discrepancy found in Steps 3–6 in the task/file it belongs to, re-run that task's tests, then re-run Steps 3–6**

- [ ] **Step 8: Stop the lab app**
