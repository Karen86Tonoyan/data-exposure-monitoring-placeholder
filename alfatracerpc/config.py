"""
AlfaTracerPC configuration module.

All configurable settings are collected here so they can be overridden
from a config file or environment variables without touching the code.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Default configuration values
_DEFAULTS: dict[str, Any] = {
    # Core
    "detect_names": True,
    "randomise_replacements": False,
    # Proxy
    "proxy_enabled": False,
    "proxy_host": "127.0.0.1",
    "proxy_port": 8080,
    # Tor
    "tor_enabled": False,
    "tor_socks_host": "127.0.0.1",
    "tor_socks_port": 9050,
    "tor_control_host": "127.0.0.1",
    "tor_control_port": 9051,
    # DNS
    "doh_enabled": True,
    "doh_provider": "cloudflare",
    "block_trackers": True,
    # AI fingerprint shield
    "fingerprint_shield_enabled": True,
    "ua_rotate_after": 10,
    "jitter_min_ms": 10.0,
    "jitter_max_ms": 100.0,
    # Database
    "db_path": "~/.alfatracerpc/privacy.db",
    # Logging
    "log_level": "INFO",
}

# Environment variable prefix
_ENV_PREFIX = "ALFATRACE_"


def _env_key(name: str) -> str:
    return f"{_ENV_PREFIX}{name.upper()}"


class Config:
    """
    Layered configuration: defaults → config file → environment variables.

    Parameters
    ----------
    path:
        Optional path to a JSON config file.  Unset keys fall back to
        defaults.  Environment variables always take highest precedence.
    """

    def __init__(self, path: Optional[str | Path] = None) -> None:
        self._data: dict[str, Any] = dict(_DEFAULTS)
        if path:
            self._load_file(path)
        self._apply_env()

    def _load_file(self, path: str | Path) -> None:
        p = Path(path).expanduser()
        if not p.exists():
            logger.warning("Config file not found: %s – using defaults.", p)
            return
        try:
            with p.open() as fh:
                overrides = json.load(fh)
            for key, value in overrides.items():
                if key in self._data:
                    self._data[key] = value
                else:
                    logger.warning("Unknown config key '%s' ignored.", key)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse config file %s: %s", p, exc)

    def _apply_env(self) -> None:
        for key in list(self._data):
            env_val = os.getenv(_env_key(key))
            if env_val is None:
                continue
            existing = self._data[key]
            if isinstance(existing, bool):
                self._data[key] = env_val.lower() in ("1", "true", "yes")
            elif isinstance(existing, int):
                self._data[key] = int(env_val)
            elif isinstance(existing, float):
                self._data[key] = float(env_val)
            else:
                self._data[key] = env_val

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(f"No config key '{name}'") from None

    def as_dict(self) -> dict[str, Any]:
        return dict(self._data)


# Module-level default instance (can be replaced by the application)
default_config = Config()
