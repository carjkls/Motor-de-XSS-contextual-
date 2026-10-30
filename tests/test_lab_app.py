"""Sanity checks that the lab app is actually vulnerable the way each route claims."""

import unittest


class LabAppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from lab.app import app
        cls.client = app.test_client()

    def test_text_route_reflects_unescaped(self):
        resp = self.client.get("/text?q=<mark>")
        self.assertIn(b"<mark>", resp.data)

    def test_attribute_route_reflects_unescaped(self):
        resp = self.client.get('/attribute?q="')
        self.assertIn(b'value="""', resp.data)  # closing quote + raw quote breaks the attribute

    def test_js_string_route_reflects_unescaped(self):
        resp = self.client.get("/js-string?q=');alert(1);//")
        self.assertIn(b"');alert(1);//", resp.data)

    def test_attribute_encoded_route_escapes_quotes(self):
        resp = self.client.get('/attribute-encoded?q="')
        self.assertNotIn(b'value="""', resp.data)
        self.assertIn(b"&quot;", resp.data)


if __name__ == "__main__":
    unittest.main()
