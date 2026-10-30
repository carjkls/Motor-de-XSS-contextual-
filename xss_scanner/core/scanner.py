"""Scan orchestrator: discovery -> context classification -> context payload
-> browser confirmation -> findings."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

from . import discovery as param_discovery
from .browser_confirm import BrowserConfirmer
from .context import find_reflection_contexts
from .findings import Finding, dedupe
from .http_client import AsyncHTTPClient, HTTPResult
from ..payloads.context_payloads import generate_payload

_SEVERITY_FOR_VERDICT = {"confirmed": "critical", "likely": "medium", "info": "low"}


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
    """Coordinates discovery, context classification, payload generation and
    browser confirmation for one target."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._log_buffer: list[str] = []

    # ------------------------------------------------------------------ util
    def _log(self, message: str) -> None:
        if self.config.verbose:
            self._log_buffer.append(message)
            print(f"[*] {message}")

    def _body_is_json(self) -> bool:
        body = self.config.body
        if not body:
            return False
        content_type = self.config.content_type
        if content_type and "json" in content_type.lower():
            return True
        try:
            json.loads(body)
            return True
        except (json.JSONDecodeError, TypeError):
            return False

    def _is_get_request(self, candidate: param_discovery.CandidateParam) -> bool:
        return self.config.method.upper() == "GET" or candidate.location == "query"

    async def _send_with_param(
        self,
        client: AsyncHTTPClient,
        candidate: param_discovery.CandidateParam | None,
        value: str | None,
    ) -> HTTPResult:
        """Send the configured request, optionally with one param replaced."""
        cfg = self.config

        if candidate is None or self._is_get_request(candidate):
            url = cfg.target_url
            if candidate is not None:
                url = param_discovery.inject_query_param(url, candidate.name, value or "")
            return await client.get(url)

        if candidate.location == "json" and cfg.body:
            injected = param_discovery.inject_json_path(cfg.body, candidate.name, value or "")
            return await client.post(
                cfg.target_url,
                data=injected,
                headers={"Content-Type": cfg.content_type or "application/json"},
            )

        # form POST
        try:
            data = dict(pair.split("=", 1) for pair in (cfg.body or "").split("&") if pair)
        except ValueError:
            data = {}
        data[candidate.name] = value or ""
        return await client.post(
            cfg.target_url,
            data=data,
            headers={"Content-Type": cfg.content_type or "application/x-www-form-urlencoded"},
        )

    def _candidates(self, html_body: str | None) -> list[param_discovery.CandidateParam]:
        cfg = self.config
        candidates = param_discovery.discover_candidates(
            cfg.target_url,
            html_body=html_body,
            json_body=cfg.body if self._body_is_json() else None,
        )
        if cfg.explicit_param:
            matches = [c for c in candidates if c.name == cfg.explicit_param]
            if matches:
                return matches[: cfg.max_params]
            location = "json" if self._body_is_json() else ("form" if cfg.method.upper() == "POST" else "query")
            return [
                param_discovery.CandidateParam(
                    location=location, name=cfg.explicit_param, original_value="",
                    method=cfg.method.upper(), priority=0,
                )
            ]
        return candidates[: cfg.max_params]

    # ------------------------------------------------------------------ main
    async def run(self) -> list[Finding]:
        cfg = self.config
        findings: list[Finding] = []

        async with AsyncHTTPClient(
            timeout=cfg.timeout, concurrency=cfg.concurrency, verify_tls=not cfg.insecure_tls,
        ) as client:
            baseline = await client.get(cfg.target_url)
            candidates = self._candidates(baseline.body if not baseline.error else None)
            if not candidates:
                self._log("no injectable parameters discovered")
                return findings
            self._log("candidate parameters: " + ", ".join(f"{c.location}:{c.name}" for c in candidates))

            browser_confirmer: BrowserConfirmer | None = None
            if not cfg.no_browser:
                browser_confirmer = BrowserConfirmer(timeout=cfg.timeout, grace_period=cfg.grace_period)
                await browser_confirmer.__aenter__()  # BrowserUnavailableError propagates

            try:
                for candidate in candidates:
                    findings.extend(
                        await self._probe_candidate(client, candidate, browser_confirmer)
                    )
            finally:
                if browser_confirmer is not None:
                    await browser_confirmer.__aexit__(None, None, None)

        return dedupe(findings)

    # ------------------------------------------------------------------ internals
    async def _probe_candidate(
        self,
        client: AsyncHTTPClient,
        candidate: param_discovery.CandidateParam,
        browser_confirmer: BrowserConfirmer | None,
    ) -> list[Finding]:
        cfg = self.config
        findings: list[Finding] = []

        probe_token = uuid.uuid4().hex[:12]
        probe_result = await self._send_with_param(client, candidate, probe_token)
        if probe_result.error:
            return findings

        contexts = find_reflection_contexts(probe_result.body, probe_token)
        self._log(f"probe {candidate.location}:{candidate.name} -> {len(contexts)} context(s)")
        if not contexts:
            return findings

        for context in contexts:
            payload = generate_payload(context)
            if payload is None:
                continue  # css / unknown: not safely payload-able

            result = await self._send_with_param(client, candidate, payload.value)
            if result.error:
                continue

            if cfg.no_browser or context.context_type == "url_attribute":
                verdict = "likely"
                reason = "static-only mode" if cfg.no_browser else "requires a user click"
                evidence = (
                    f"attribute={context.attribute_name!r} tag={context.tag_name!r} "
                    f"quote={context.quote_char!r}; no browser check performed ({reason})"
                )
            else:
                assert browser_confirmer is not None
                is_get = self._is_get_request(candidate)
                confirmed = await browser_confirmer.confirm(
                    token=payload.token,
                    url=result.url if is_get else None,
                    html_body=None if is_get else result.body,
                )
                verdict = "confirmed" if confirmed else "likely"
                evidence = (
                    f"attribute={context.attribute_name!r} tag={context.tag_name!r} "
                    f"quote={context.quote_char!r}; browser marker "
                    f"window.__xss_{payload.token}__ {'fired' if confirmed else 'did not fire'}"
                )

            findings.append(
                Finding(
                    title=f"Reflected XSS ({context.context_type})",
                    severity=_SEVERITY_FOR_VERDICT[verdict],
                    verdict=verdict,
                    request_url=result.url,
                    param_name=candidate.name,
                    param_location=candidate.location,
                    context_type=context.context_type,
                    payload_value=payload.value,
                    evidence=evidence,
                )
            )

        return findings
