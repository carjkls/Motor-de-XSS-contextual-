"""Smoke test for the async HTTP client wrapper."""

import socket
import unittest

from xss_scanner.core.http_client import AsyncHTTPClient


def _network_reachable() -> bool:
    try:
        socket.create_connection(("example.com", 443), timeout=3).close()
        return True
    except OSError:
        return False


@unittest.skipUnless(_network_reachable(), "no network access")
class HTTPResultTest(unittest.IsolatedAsyncioTestCase):
    async def test_get_returns_result_with_body(self):
        async with AsyncHTTPClient() as client:
            result = await client.get("https://example.com")
        self.assertTrue(result.ok)
        self.assertIn("Example Domain", result.body)


if __name__ == "__main__":
    unittest.main()
