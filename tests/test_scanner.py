"""End-to-end orchestration against a tiny in-process HTTP server (no
network, no dependency on lab/)."""

import unittest

from xss_scanner.core.scanner import ScanConfig, XSSScanner
from .helpers import start_echo_server, start_json_echo_server, start_static_server


class XSSScannerTest(unittest.IsolatedAsyncioTestCase):
    async def test_confirmed_finding_for_reflected_html_text(self):
        with start_echo_server() as base_url:
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
        with start_static_server() as base_url:
            config = ScanConfig(target_url=f"{base_url}/?q=x", max_params=1)
            scanner = XSSScanner(config)
            findings = await scanner.run()
        self.assertEqual(findings, [])

    async def test_confirmed_finding_for_post_json_reflected_into_script(self):
        with start_json_echo_server() as base_url:
            config = ScanConfig(
                target_url=base_url, method="POST", body='{"q": "x"}',
                content_type="application/json", explicit_param="$.q",
            )
            scanner = XSSScanner(config)
            findings = await scanner.run()
        self.assertTrue(any(f.verdict == "confirmed" for f in findings))


if __name__ == "__main__":
    unittest.main()
