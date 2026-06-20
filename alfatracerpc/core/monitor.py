"""
Network Monitor – intercepts outgoing data, scans it for PII, and
replaces sensitive values before the data leaves the machine.

Implementation strategy
-----------------------
Rather than deep packet inspection (which requires OS-level privileges and
kernel hooks), the monitor exposes a *proxy layer* that wraps Python's
``http.server`` / ``urllib`` stack.  Applications configured to use the
local proxy benefit from automatic PII scrubbing without needing to be
aware of it.

Additionally the module provides:
  - ``OutboundFilter`` – a callable that can be inserted into any data
    pipeline to mask PII before the data is written to a socket.
  - ``ProxyServer`` – a lightweight HTTP proxy that scrubs request bodies.
"""

from __future__ import annotations

import logging
import socketserver
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler
from typing import Callable, Optional

from alfatracerpc.core.masker import DataMasker
from alfatracerpc.core.scanner import PrivacyScanner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Outbound filter – thin functional wrapper
# ---------------------------------------------------------------------------


class OutboundFilter:
    """
    Wraps a data source and scrubs PII before data is passed downstream.

    Usage::

        filt = OutboundFilter()
        safe_payload = filt.scrub("Hello, my email is user@example.com")
    """

    def __init__(
        self,
        session_key: Optional[str] = None,
        randomise: bool = False,
    ) -> None:
        self._scanner = PrivacyScanner()
        self._masker = DataMasker(session_key=session_key, randomise=randomise)

    def scrub(self, data: str) -> str:
        """Return *data* with all detected PII replaced by synthetic values."""
        result = self._scanner.scan(data)
        if not result.has_pii:
            return data
        masked = self._masker.mask_text(result)
        if masked != data:
            n = len(result.matches)
            logger.info("Scrubbed %d PII item(s) from outbound data.", n)
        return masked

    def scrub_bytes(self, data: bytes, encoding: str = "utf-8") -> bytes:
        """Bytes-level wrapper around :meth:`scrub`."""
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            return data  # binary payload – skip
        return self.scrub(text).encode(encoding)


# ---------------------------------------------------------------------------
# Simple HTTP proxy with PII scrubbing
# ---------------------------------------------------------------------------


class _ScrubHandler(BaseHTTPRequestHandler):
    """Internal request handler for the scrubbing proxy."""

    # Set by ProxyServer before starting
    filter: OutboundFilter

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D102
        logger.debug(fmt, *args)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length)
        return b""

    def do_POST(self) -> None:  # noqa: N802
        body = self._read_body()
        clean_body = self.filter.scrub_bytes(body)

        parsed = urllib.parse.urlparse(self.path)
        host = parsed.hostname or self.headers.get("Host", "")
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        try:
            import http.client
            conn = http.client.HTTPConnection(host, port, timeout=10)
            headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in ("content-length", "host")
            }
            headers["Content-Length"] = str(len(clean_body))
            conn.request("POST", path, body=clean_body, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status)
            for header, value in resp.getheaders():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(resp.read())
            conn.close()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Proxy error forwarding to %s: %s", host, exc)
            self.send_error(502, f"Bad gateway: {exc}")

    def do_GET(self) -> None:  # noqa: N802
        # GET forwarding (no body to scrub)
        self._forward_simple("GET")

    def do_PUT(self) -> None:  # noqa: N802
        body = self._read_body()
        clean_body = self.filter.scrub_bytes(body)
        self._forward_with_body("PUT", clean_body)

    def _forward_simple(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        host = parsed.hostname or self.headers.get("Host", "")
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            import http.client
            conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request(method, path, headers=dict(self.headers))
            resp = conn.getresponse()
            self.send_response(resp.status)
            for h, v in resp.getheaders():
                self.send_header(h, v)
            self.end_headers()
            self.wfile.write(resp.read())
            conn.close()
        except Exception as exc:  # noqa: BLE001
            self.send_error(502, str(exc))

    def _forward_with_body(self, method: str, body: bytes) -> None:
        parsed = urllib.parse.urlparse(self.path)
        host = parsed.hostname or self.headers.get("Host", "")
        port = parsed.port or 80
        path = parsed.path or "/"
        try:
            import http.client
            conn = http.client.HTTPConnection(host, port, timeout=10)
            headers = dict(self.headers)
            headers["Content-Length"] = str(len(body))
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status)
            for h, v in resp.getheaders():
                self.send_header(h, v)
            self.end_headers()
            self.wfile.write(resp.read())
            conn.close()
        except Exception as exc:  # noqa: BLE001
            self.send_error(502, str(exc))


class ProxyServer:
    """
    A local HTTP proxy that scrubs PII from outgoing request bodies.

    Start it with :meth:`start` (non-blocking, runs in a daemon thread).
    Configure your application to use ``http://127.0.0.1:<port>`` as its
    HTTP proxy.

    Example::

        proxy = ProxyServer(port=8080)
        proxy.start()
        # proxy is now running in background
        proxy.stop()
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        session_key: Optional[str] = None,
        randomise: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self._filter = OutboundFilter(session_key=session_key, randomise=randomise)
        self._server: Optional[socketserver.TCPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the proxy in a background daemon thread."""
        # Patch the filter onto the handler class
        handler = type(
            "_BoundHandler",
            (_ScrubHandler,),
            {"filter": self._filter},
        )
        self._server = socketserver.TCPServer((self.host, self.port), handler)
        self._server.allow_reuse_address = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="alfatracerpc-proxy",
        )
        self._thread.start()
        logger.info("Privacy proxy running on %s:%d", self.host, self.port)

    def stop(self) -> None:
        """Shut down the proxy server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        logger.info("Privacy proxy stopped.")

    @property
    def address(self) -> str:
        return f"http://{self.host}:{self.port}"
