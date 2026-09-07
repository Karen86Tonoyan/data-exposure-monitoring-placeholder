"""
Privacy Coordinator – ties together scanner, masker, monitor and all
integrations into a single high-level ``PrivacyEngine`` class.
"""

from __future__ import annotations

import logging
from typing import Optional

from alfatracerpc.core.masker import DataMasker
from alfatracerpc.core.monitor import OutboundFilter, ProxyServer
from alfatracerpc.core.scanner import PIICategory, PrivacyScanner, ScanResult

logger = logging.getLogger(__name__)


class PrivacyEngine:
    """
    Central coordinator for AlfaTracerPC privacy protection.

    Combines:
      - PII scanning & masking
      - Outbound data filter
      - HTTP proxy with scrubbing
      - Tor routing integration (optional)
      - AI fingerprint countermeasures (optional)

    Parameters
    ----------
    session_key:
        Seed for deterministic synthetic data within a session.
    randomise:
        If True, every replacement is fully random (maximum unlinkability).
    proxy_port:
        Local port for the scrubbing HTTP proxy (0 = disabled).
    use_tor:
        Attempt to route traffic through a local Tor SOCKS proxy.
    """

    def __init__(
        self,
        session_key: Optional[str] = None,
        randomise: bool = False,
        proxy_port: int = 0,
        use_tor: bool = False,
    ) -> None:
        self.scanner = PrivacyScanner()
        self.masker = DataMasker(session_key=session_key, randomise=randomise)
        self.filter = OutboundFilter(session_key=session_key, randomise=randomise)

        self._proxy: Optional[ProxyServer] = None
        if proxy_port > 0:
            self._proxy = ProxyServer(port=proxy_port, session_key=session_key)

        self._tor_enabled = use_tor
        if use_tor:
            self._init_tor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scrub(self, text: str) -> str:
        """Scan *text* and return it with all PII replaced."""
        return self.filter.scrub(text)

    def scrub_bytes(self, data: bytes, encoding: str = "utf-8") -> bytes:
        """Bytes-level scrub helper."""
        return self.filter.scrub_bytes(data, encoding)

    def scan(self, text: str) -> ScanResult:
        """Return a detailed scan result without modifying the text."""
        return self.scanner.scan(text)

    def start_proxy(self) -> Optional[str]:
        """Start the HTTP scrubbing proxy; returns its URL or None."""
        if self._proxy is None:
            logger.warning("No proxy configured (proxy_port was 0).")
            return None
        self._proxy.start()
        return self._proxy.address

    def stop_proxy(self) -> None:
        """Stop the HTTP scrubbing proxy."""
        if self._proxy:
            self._proxy.stop()

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "PrivacyEngine":
        self.start_proxy()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop_proxy()

    # ------------------------------------------------------------------
    # Tor integration
    # ------------------------------------------------------------------

    def _init_tor(self) -> None:
        """Configure the environment to route through the local Tor proxy."""
        try:
            from alfatracerpc.integrations.tor import configure_tor_proxy
            configure_tor_proxy()
            logger.info("Tor routing enabled.")
        except ImportError:
            logger.warning("Tor integration unavailable – stem not installed.")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to configure Tor: %s", exc)

    # ------------------------------------------------------------------
    # Convenience report
    # ------------------------------------------------------------------

    def report(self, text: str) -> dict[str, object]:
        """
        Return a summary dict of PII found in *text* (for diagnostics).

        Does NOT return the original values – only category counts.
        """
        result = self.scanner.scan(text)
        counts: dict[str, int] = {}
        for match in result.matches:
            name = match.category.name
            counts[name] = counts.get(name, 0) + 1
        return {
            "pii_found": result.has_pii,
            "total_items": len(result.matches),
            "by_category": counts,
        }
