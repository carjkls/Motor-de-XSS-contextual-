"""Playwright-based marker confirmation.

Requires `playwright install chromium` to have been run once; `pip install
-e .` alone installs the Python bindings but not the browser binary.
"""

import unittest

from xss_scanner.core.browser_confirm import BrowserConfirmer


class BrowserConfirmerTest(unittest.IsolatedAsyncioTestCase):
    async def test_confirm_detects_marker_from_html_body(self):
        async with BrowserConfirmer() as confirmer:
            html = "<script>window.__xss_abc123__=1</script>"
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


if __name__ == "__main__":
    unittest.main()
