"""
Test of the HAR capture with Playwright, against a local web server (no
internet). Skipped if Playwright or its browser is not installed
(python -m playwright install chromium).
Run from src/: python -m pytest ../tests
"""

import http.server
import io
import contextlib
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import harcapture
import harutilities


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        port = self.server.server_address[1]
        if self.path == "/":
            # a second host name for the same server, as a page with
            # third-party content would have
            body = (
                '<html><body><img src="http://localhost:{:}/pixel.gif">'
                "</body></html>".format(port)
            ).encode()
            ctype = "text/html"
        else:
            body = b"GIF89a"
            ctype = "image/gif"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "fixture=1")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:{:}/".format(httpd.server_address[1])
    httpd.shutdown()


def test_capture(server, tmp_path):
    pytest.importorskip("playwright")
    harfile = str(tmp_path / "capture.har")
    try:
        # twice, as generatemap.py -n 2 does
        harcapture.capture([server, server], harfile)
    except Exception as e:
        if "Executable doesn't exist" in str(e):
            pytest.skip("Playwright's browser is not installed")
        raise

    checker = harutilities.CheckHAR()
    with contextlib.redirect_stdout(io.StringIO()):
        checker.Load(harfile)
    result = checker.GetResult()
    assert set(result.hosts) == {"127.0.0.1", "localhost"}
    # page and image, twice: the cache is off, so nothing is left out
    assert result.requests == 4
    assert result.start
    # chrome-har-capturer no longer records these
    assert len(result.cookies) >= 4
    assert all(h.size > 0 for h in result.hosts.values())
