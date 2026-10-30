"""In-process HTTP server fixtures for scanner tests (no network needed)."""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


def _serve_in_thread(handler_cls) -> tuple[HTTPServer, threading.Thread]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@contextlib.contextmanager
def start_echo_server():
    """GET /?q=... reflects q unescaped into <p>...</p>."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            params = parse_qs(urlsplit(self.path).query)
            q = params.get("q", [""])[0]
            body = f"<html><body><p>{q}</p></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server, thread = _serve_in_thread(Handler)
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


@contextlib.contextmanager
def start_static_server():
    """GET /?q=... ignores q, always returns a fixed body."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body><p>static</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server, thread = _serve_in_thread(Handler)
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


@contextlib.contextmanager
def start_json_echo_server():
    """POST / with {"q": "..."} reflects q unescaped into a <script> string."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = {}
            q = data.get("q", "")
            body = f'<html><body><script>var x="{q}";</script></body></html>'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server, thread = _serve_in_thread(Handler)
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join()
