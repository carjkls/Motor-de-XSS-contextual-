"""CLI argument parsing."""

import unittest

from xss_scanner.cli import build_parser


class CliTest(unittest.TestCase):
    def test_build_parser_requires_url(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args([])

    def test_build_parser_defaults(self):
        args = build_parser().parse_args(["-u", "http://t/?q=1"])
        self.assertEqual(args.method, "GET")
        self.assertFalse(args.no_browser)
        self.assertEqual(args.max_params, 12)


if __name__ == "__main__":
    unittest.main()
