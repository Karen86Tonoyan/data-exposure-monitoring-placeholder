"""
Tor Integration – configures Python's urllib / requests to route
traffic through the local Tor SOCKS5 proxy (default: 127.0.0.1:9050).

Requires the ``stem`` package for Tor control-port interaction and a
running Tor daemon on the local machine.

Usage::

    from alfatracerpc.integrations.tor import TorRouter
    router = TorRouter()
    router.connect()
    router.new_circuit()   # rotate exit node
    router.disconnect()
"""

from __future__ import annotations

import logging
import os
import socket
import socks  # type: ignore[import-untyped]  # PySocks
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)

_TOR_HOST = "127.0.0.1"
_TOR_SOCKS_PORT = 9050
_TOR_CONTROL_PORT = 9051


def configure_tor_proxy(
    host: str = _TOR_HOST,
    port: int = _TOR_SOCKS_PORT,
) -> None:
    """
    Patch the default socket to route through Tor's SOCKS5 proxy.

    This affects all subsequent socket connections made from Python in
    the current process (including urllib, http.client, etc.).
    """
    socks.set_default_proxy(socks.SOCKS5, host, port)
    socket.socket = socks.socksocket  # type: ignore[misc]
    logger.info("Default socket patched to use Tor SOCKS5 @ %s:%d", host, port)


def reset_proxy() -> None:
    """Remove the Tor proxy patch and restore direct connections."""
    socks.set_default_proxy()
    socket.socket = socket.socket.__class__  # type: ignore[assignment]
    logger.info("Default socket proxy removed.")


class TorRouter:
    """
    High-level Tor routing manager.

    Parameters
    ----------
    socks_host / socks_port:
        Location of the Tor SOCKS5 proxy.
    control_host / control_port:
        Location of the Tor control port (for circuit rotation).
    control_password:
        Authentication password for the Tor control port.
        Read from the ``TOR_CONTROL_PASSWORD`` environment variable
        if not provided explicitly.
    """

    def __init__(
        self,
        socks_host: str = _TOR_HOST,
        socks_port: int = _TOR_SOCKS_PORT,
        control_host: str = _TOR_HOST,
        control_port: int = _TOR_CONTROL_PORT,
        control_password: Optional[str] = None,
    ) -> None:
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_host = control_host
        self.control_port = control_port
        self.control_password = control_password or os.getenv(
            "TOR_CONTROL_PASSWORD", ""
        )
        self._controller = None  # stem.control.Controller instance

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Patch the default socket and connect to the Tor control port."""
        configure_tor_proxy(self.socks_host, self.socks_port)
        self._connect_control()

    def disconnect(self) -> None:
        """Disconnect from the control port and restore direct routing."""
        if self._controller is not None:
            self._controller.close()
            self._controller = None
        reset_proxy()

    def _connect_control(self) -> None:
        try:
            from stem.control import Controller  # type: ignore[import-untyped]
            self._controller = Controller.from_port(
                address=self.control_host, port=self.control_port
            )
            self._controller.authenticate(self.control_password or None)
            logger.info("Connected to Tor control port.")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not connect to Tor control port: %s", exc)
            self._controller = None

    # ------------------------------------------------------------------
    # Circuit rotation
    # ------------------------------------------------------------------

    def new_circuit(self) -> bool:
        """
        Request a new Tor circuit (changes the apparent IP address).

        Returns True on success, False if the control port is unavailable.
        """
        if self._controller is None:
            logger.warning("Tor controller not connected – cannot rotate circuit.")
            return False
        try:
            self._controller.signal("NEWNYM")
            logger.info("New Tor circuit requested.")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to request new Tor circuit: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Current exit node
    # ------------------------------------------------------------------

    def current_exit_ip(self) -> Optional[str]:
        """Return the current Tor exit node IP (via a check service)."""
        try:
            with urllib.request.urlopen(
                "https://check.torproject.org/api/ip", timeout=10
            ) as resp:
                import json
                data = json.loads(resp.read().decode())
                return data.get("IP")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not determine Tor exit IP: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "TorRouter":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.disconnect()
