"""Console and JSON reporting."""

import json
import unittest

from xss_scanner.core.findings import Finding
from xss_scanner.reporting.report import findings_to_json


class ReportTest(unittest.TestCase):
    def test_findings_to_json_round_trips(self):
        finding = Finding(title="t", severity="critical", verdict="confirmed",
                           request_url="u", param_name="q", param_location="query",
                           context_type="html_text", payload_value="<script>x</script>")
        data = json.loads(findings_to_json([finding]))
        self.assertEqual(data[0]["context_type"], "html_text")


if __name__ == "__main__":
    unittest.main()
