"""Reflection-context classification: HTML text/attribute/comment/css and
JS string/template-literal/unknown positions."""

import unittest

from xss_scanner.core.context import ReflectionContext, find_reflection_contexts


class ContextTest(unittest.TestCase):
    def test_html_text_context(self):
        ctx = find_reflection_contexts("<p>hello TOK world</p>", "TOK")
        self.assertEqual(ctx, [ReflectionContext("html_text", tag_name="p")])

    def test_html_attribute_double_quote(self):
        ctx = find_reflection_contexts('<input value="TOK">', "TOK")
        self.assertEqual(ctx, [ReflectionContext("html_attribute", tag_name="input",
                                                  attribute_name="value", quote_char='"')])

    def test_html_attribute_double_quote_with_text_before_token(self):
        # Regression: a real app rarely reflects the value as the whole
        # attribute, usually with a prefix (e.g. "search: TOK"). The quote
        # must still be detected, not silently misreported as unquoted.
        ctx = find_reflection_contexts('<input value="search: TOK">', "TOK")
        self.assertEqual(ctx[0].context_type, "html_attribute")
        self.assertEqual(ctx[0].quote_char, '"')

    def test_html_attribute_single_quote(self):
        ctx = find_reflection_contexts("<input value='TOK'>", "TOK")
        self.assertEqual(ctx[0].quote_char, "'")

    def test_html_attribute_unquoted(self):
        ctx = find_reflection_contexts("<input value=TOK>", "TOK")
        self.assertIsNone(ctx[0].quote_char)

    def test_url_attribute_href(self):
        ctx = find_reflection_contexts('<a href="TOK">x</a>', "TOK")
        self.assertEqual(ctx[0].context_type, "url_attribute")

    def test_html_comment(self):
        ctx = find_reflection_contexts("<!-- TOK -->", "TOK")
        self.assertEqual(ctx[0].context_type, "html_comment")

    def test_css_style_tag_is_recognized_but_out_of_scope(self):
        ctx = find_reflection_contexts("<style>body{color:TOK}</style>", "TOK")
        self.assertEqual(ctx[0].context_type, "css")

    def test_css_style_attribute(self):
        ctx = find_reflection_contexts('<div style="color:TOK">x</div>', "TOK")
        self.assertEqual(ctx[0].context_type, "css")

    def test_js_string_double_quote(self):
        ctx = find_reflection_contexts('<script>var x="TOK";</script>', "TOK")
        self.assertEqual(ctx[0], ReflectionContext("js_string", quote_char='"'))

    def test_js_string_single_quote(self):
        ctx = find_reflection_contexts("<script>var x='TOK';</script>", "TOK")
        self.assertEqual(ctx[0].quote_char, "'")

    def test_js_template_literal(self):
        ctx = find_reflection_contexts("<script>var x=`hi TOK`;</script>", "TOK")
        self.assertEqual(ctx[0].context_type, "js_template_literal")

    def test_js_unknown_for_raw_code_position(self):
        ctx = find_reflection_contexts("<script>var TOK = 1;</script>", "TOK")
        self.assertEqual(ctx[0].context_type, "unknown")

    def test_js_token_inside_comment_is_unknown(self):
        ctx = find_reflection_contexts("<script>// TOK\nvar x=1;</script>", "TOK")
        self.assertEqual(ctx[0].context_type, "unknown")

    def test_token_not_found_returns_empty_list(self):
        self.assertEqual(find_reflection_contexts("<p>hello</p>", "TOK"), [])

    def test_token_in_two_distinct_contexts_returns_both(self):
        html = '<p>TOK</p><script>var x="TOK";</script>'
        types = {c.context_type for c in find_reflection_contexts(html, "TOK")}
        self.assertEqual(types, {"html_text", "js_string"})

    def test_identical_contexts_are_deduped(self):
        html = "<p>TOK</p><p>TOK again</p>"
        self.assertEqual(len(find_reflection_contexts(html, "TOK")), 1)


if __name__ == "__main__":
    unittest.main()
