"""Parameter discovery: query string, HTML forms, JSON body."""

import unittest

from xss_scanner.core.discovery import (
    from_json_body,
    from_query_string,
    inject_query_param,
)


class DiscoveryTest(unittest.TestCase):
    def test_from_query_string_finds_params(self):
        candidates = from_query_string("https://t/x?q=hi&id=1")
        self.assertEqual({c.name for c in candidates}, {"q", "id"})

    def test_inject_query_param_replaces_value(self):
        url = inject_query_param("https://t/x?q=hi", "q", "PAYLOAD")
        self.assertIn("q=PAYLOAD", url)

    def test_from_json_body_tracks_json_path(self):
        candidates = from_json_body('{"a": {"b": "hi"}}')
        self.assertEqual(candidates[0].name, "$.a.b")


if __name__ == "__main__":
    unittest.main()
