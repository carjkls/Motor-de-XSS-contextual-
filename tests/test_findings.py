"""Finding dataclass and dedupe."""

import unittest

from xss_scanner.core.findings import Finding, dedupe


class FindingsTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
