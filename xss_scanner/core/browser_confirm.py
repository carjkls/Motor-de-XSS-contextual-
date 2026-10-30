"""Confirms a context payload actually executed, via a real headless browser.

The confirmed/likely distinction in the rest of the scanner rests entirely
on this module: a `confirmed` finding means the marker it set really fired
in a real browser, not that the payload merely looked plausible.
"""

from __future__ import annotations

from playwright.async_api import async_playwright


class BrowserUnavailableError(RuntimeError):
    """Playwright's browser binary isn't installed."""


class BrowserConfirmer:
    """Owns one headless browser for the whole scan; isolates each check in
    its own browser context."""

    def __init__(self, timeout: float = 5.0, grace_period: float = 0.5) -> None:
        self.timeout = timeout
        self.grace_period = grace_period
        self._playwright = None
        self._browser = None

    async def __aenter__(self) -> "BrowserConfirmer":
        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.launch(headless=True)
        except Exception as exc:
            await self._playwright.stop()
            self._playwright = None
            if "executable doesn't exist" in str(exc) or "playwright install" in str(exc).lower():
                raise BrowserUnavailableError(
                    "Playwright's Chromium binary isn't installed. Run "
                    "'playwright install chromium', or pass --no-browser to "
                    "run static-only (likely-only, never confirmed)."
                ) from exc
            raise
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def confirm(
        self, *, token: str, url: str | None = None, html_body: str | None = None,
    ) -> bool:
        if (url is None) == (html_body is None):
            raise ValueError("pass exactly one of 'url' or 'html_body'")

        context = await self._browser.new_context()
        try:
            page = await context.new_page()
            try:
                if url is not None:
                    await page.goto(url, timeout=self.timeout * 1000)
                else:
                    await page.set_content(html_body, timeout=self.timeout * 1000)
            except Exception:
                return False
            await page.wait_for_timeout(self.grace_period * 1000)
            return bool(
                await page.evaluate(
                    "t => window['__xss_' + t + '__'] === 1", token
                )
            )
        finally:
            await context.close()
