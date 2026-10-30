"""Context-specific payload generation."""

import unittest

from xss_scanner.core.context import ReflectionContext
from xss_scanner.payloads.context_payloads import generate_payload


class ContextPayloadsTest(unittest.TestCase):
    def test_html_text_payload(self):
        p = generate_payload(ReflectionContext("html_text", tag_name="p"))
        self.assertEqual(p.value, f"<script>window.__xss_{p.token}__=1</script>")
        self.assertTrue(p.auto_fires)

    def test_html_attribute_double_quote_payload(self):
        ctx = ReflectionContext("html_attribute", attribute_name="value", quote_char='"')
        p = generate_payload(ctx)
        self.assertEqual(p.value, f'" autofocus onfocus="window.__xss_{p.token}__=1')

    def test_html_attribute_single_quote_payload(self):
        ctx = ReflectionContext("html_attribute", attribute_name="value", quote_char="'")
        p = generate_payload(ctx)
        self.assertEqual(p.value, f"' autofocus onfocus='window.__xss_{p.token}__=1")

    def test_html_attribute_unquoted_payload(self):
        ctx = ReflectionContext("html_attribute", attribute_name="value", quote_char=None)
        p = generate_payload(ctx)
        self.assertEqual(p.value, f" onfocus=window.__xss_{p.token}__=1 autofocus")

    def test_url_attribute_payload_does_not_auto_fire(self):
        p = generate_payload(ReflectionContext("url_attribute", attribute_name="href"))
        self.assertEqual(p.value, f"javascript:window.__xss_{p.token}__=1")
        self.assertFalse(p.auto_fires)

    def test_html_comment_payload(self):
        p = generate_payload(ReflectionContext("html_comment"))
        self.assertEqual(p.value, f"--><script>window.__xss_{p.token}__=1</script><!--")

    def test_js_string_payload(self):
        ctx = ReflectionContext("js_string", quote_char='"')
        p = generate_payload(ctx)
        self.assertEqual(p.value, f'";window.__xss_{p.token}__=1;//')

    def test_js_template_literal_payload(self):
        p = generate_payload(ReflectionContext("js_template_literal"))
        self.assertEqual(p.value, "${(window.__xss_" + p.token + "__=1,'')}")

    def test_css_and_unknown_return_none(self):
        self.assertIsNone(generate_payload(ReflectionContext("css")))
        self.assertIsNone(generate_payload(ReflectionContext("unknown")))

    def test_token_is_unique_per_call(self):
        p1 = generate_payload(ReflectionContext("html_text"))
        p2 = generate_payload(ReflectionContext("html_text"))
        self.assertNotEqual(p1.token, p2.token)


if __name__ == "__main__":
    unittest.main()
