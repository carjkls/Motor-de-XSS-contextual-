"""Classifies the syntactic context a probe token reflects into.

The static pass here only answers *where* and *in what kind of syntax* a
value landed (HTML text, an attribute, inside a `<script>` string, ...). It
never decides exploitability — that's left to the payload generator and the
browser confirmation step.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bs4 import BeautifulSoup, Comment

# JS scanner states
_NONE, _SINGLE, _DOUBLE, _TEMPLATE, _LINE_COMMENT, _BLOCK_COMMENT = range(6)
_CLOSE_CHAR = {_SINGLE: "'", _DOUBLE: '"', _TEMPLATE: "`"}


@dataclass(frozen=True)
class ReflectionContext:
    context_type: str   # "html_text" | "html_attribute" | "url_attribute" |
                          # "html_comment" | "css" | "js_string" |
                          # "js_template_literal" | "unknown"
    tag_name: str | None = None
    attribute_name: str | None = None
    quote_char: str | None = None   # '"' | "'" | "`" | None (unquoted attr)


def _scan_js_states(text: str) -> list[int]:
    """State active *before* processing each character index."""
    n = len(text)
    state_at = [_NONE] * n
    state = _NONE
    i = 0
    while i < n:
        state_at[i] = state
        ch = text[i]
        if state == _NONE:
            if ch == "/" and i + 1 < n and text[i + 1] == "/":
                state = _LINE_COMMENT
                i += 2
                continue
            if ch == "/" and i + 1 < n and text[i + 1] == "*":
                state = _BLOCK_COMMENT
                i += 2
                continue
            if ch == "'":
                state = _SINGLE
            elif ch == '"':
                state = _DOUBLE
            elif ch == "`":
                state = _TEMPLATE
            i += 1
            continue
        if state in (_SINGLE, _DOUBLE, _TEMPLATE):
            if ch == "\\":
                if i + 1 < n:
                    state_at[i + 1] = state
                i += 2
                continue
            if ch == _CLOSE_CHAR[state]:
                state = _NONE
            i += 1
            continue
        if state == _LINE_COMMENT:
            if ch == "\n":
                state = _NONE
            i += 1
            continue
        if state == _BLOCK_COMMENT:
            if ch == "*" and i + 1 < n and text[i + 1] == "/":
                state = _NONE
                i += 2
                continue
            i += 1
            continue
    return state_at


def _classify_js_positions(text: str, token: str) -> list[ReflectionContext]:
    if not token:
        return []
    state_at = _scan_js_states(text)
    results: list[ReflectionContext] = []
    start = 0
    while True:
        idx = text.find(token, start)
        if idx == -1:
            break
        state = state_at[idx] if idx < len(state_at) else _NONE
        if state == _DOUBLE:
            results.append(ReflectionContext("js_string", quote_char='"'))
        elif state == _SINGLE:
            results.append(ReflectionContext("js_string", quote_char="'"))
        elif state == _TEMPLATE:
            results.append(ReflectionContext("js_template_literal", quote_char="`"))
        else:
            results.append(ReflectionContext("unknown"))
        start = idx + len(token)
    return results


def _attribute_quote_char(html: str, attribute_name: str, token: str) -> str | None:
    pattern = rf'{re.escape(attribute_name)}\s*=\s*(["\']?){re.escape(token)}'
    match = re.search(pattern, html, re.IGNORECASE)
    if not match:
        return None
    quote = match.group(1)
    return quote or None


def _dedupe(contexts: list[ReflectionContext]) -> list[ReflectionContext]:
    seen: set[tuple[str, str | None, str | None, str | None]] = set()
    result: list[ReflectionContext] = []
    for ctx in contexts:
        key = (ctx.context_type, ctx.tag_name, ctx.attribute_name, ctx.quote_char)
        if key not in seen:
            seen.add(key)
            result.append(ctx)
    return result


def find_reflection_contexts(html: str, token: str) -> list[ReflectionContext]:
    """Locate every distinct syntactic context ``token`` reflects into."""
    if not token:
        return []

    soup = BeautifulSoup(html, "html.parser")
    contexts: list[ReflectionContext] = []

    # <script> contents: classified by the JS state-machine scanner.
    for script in soup.find_all("script"):
        text = script.get_text()
        if text and token in text:
            contexts.extend(_classify_js_positions(text, token))

    # HTML comments.
    for node in soup.find_all(string=lambda s: isinstance(s, Comment)):
        if token in node:
            contexts.append(ReflectionContext("html_comment"))

    # Plain text nodes (everything else, excluding <script> handled above).
    for node in soup.find_all(string=True):
        if isinstance(node, Comment):
            continue
        parent = node.parent
        parent_name = parent.name if parent is not None else None
        if parent_name == "script":
            continue
        if token not in node:
            continue
        if parent_name == "style":
            contexts.append(ReflectionContext("css"))
        else:
            contexts.append(ReflectionContext("html_text", tag_name=parent_name))

    # Attribute values.
    for tag in soup.find_all(True):
        for attr_name, attr_val in tag.attrs.items():
            value_str = " ".join(attr_val) if isinstance(attr_val, list) else str(attr_val)
            if token not in value_str:
                continue
            attr_lower = attr_name.lower()
            if attr_lower == "style":
                contexts.append(ReflectionContext("css"))
                continue
            context_type = "url_attribute" if attr_lower in {"href", "src"} else "html_attribute"
            quote_char = _attribute_quote_char(html, attr_name, token)
            contexts.append(
                ReflectionContext(
                    context_type, tag_name=tag.name, attribute_name=attr_lower,
                    quote_char=quote_char,
                )
            )

    return _dedupe(contexts)
