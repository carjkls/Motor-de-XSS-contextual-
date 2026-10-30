"""Command-line interface for xss-contextual-scanner."""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .core.browser_confirm import BrowserUnavailableError
from .core.scanner import ScanConfig, XSSScanner
from .reporting.report import print_findings, save_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xsscan",
        description=(
            "Reflected XSS scanner with context-aware payload generation and "
            "headless-browser execution confirmation. Only scan systems you "
            "are authorized to test."
        ),
    )
    parser.add_argument("-u", "--url", required=True, help="target URL (include query params)")
    parser.add_argument(
        "--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)"
    )
    parser.add_argument(
        "--data", dest="body", default=None,
        help="request body for POST (form-encoded string or raw JSON)",
    )
    parser.add_argument(
        "--content-type", default=None,
        help="Content-Type for the body (default: auto-detect)",
    )
    parser.add_argument(
        "-p", "--param", dest="param", default=None,
        help="test only this parameter (name or JSON path like $.comment)",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request/page timeout (s)")
    parser.add_argument("--concurrency", type=int, default=10, help="parallel HTTP requests")
    parser.add_argument("--max-params", type=int, default=12, help="max parameters to test")
    parser.add_argument(
        "--grace-period", type=float, default=0.5,
        help="seconds to wait in-browser for autofocus/onfocus-style payloads to fire",
    )
    parser.add_argument(
        "--no-browser", action="store_true",
        help="static-only mode: report context matches as 'likely', never 'confirmed'",
    )
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("-o", "--output", default=None, help="write JSON report to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    config = ScanConfig(
        target_url=args.url,
        method=args.method,
        body=args.body,
        content_type=args.content_type,
        explicit_param=args.param,
        timeout=args.timeout,
        concurrency=args.concurrency,
        max_params=args.max_params,
        grace_period=args.grace_period,
        no_browser=args.no_browser,
        insecure_tls=args.insecure,
        verbose=args.verbose,
    )

    scanner = XSSScanner(config)
    try:
        findings = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130
    except BrowserUnavailableError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print_findings(findings, args.url)
    if args.output:
        save_json(findings, args.output)
        print(f"[+] JSON report saved to {args.output}")
    return 0 if findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
