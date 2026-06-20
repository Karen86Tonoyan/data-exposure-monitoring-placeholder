"""
AI Fingerprint Protection – countermeasures against machine-learning
based fingerprinting and behavioural profiling.

Modern surveillance systems build statistical profiles of users by
correlating:
  - Browser / HTTP User-Agent strings
  - Canvas fingerprints (GPU rendering)
  - Font / plugin enumeration
  - Timing patterns (typing speed, mouse movement entropy)
  - HTTP header order and value patterns

This module provides:
  - :class:`UserAgentRotator` – pool of realistic UA strings rotated on
    a configurable schedule
  - :class:`HeaderSanitizer` – removes or normalises identifying HTTP
    headers
  - :class:`TimingJitter` – adds calibrated random delays to break timing
    fingerprints
  - :class:`FingerprintShield` – convenience wrapper combining all the above
"""

from __future__ import annotations

import logging
import random
import secrets
import time
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# User-Agent pool
# ---------------------------------------------------------------------------

# A curated set of common, stable User-Agent strings.  Rotating through
# this pool prevents sites from building a consistent browser fingerprint.
_UA_POOL = [
    # Windows – Chrome
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    # macOS – Safari
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.4 Safari/605.1.15"
    ),
    # Linux – Firefox
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) "
        "Gecko/20100101 Firefox/125.0"
    ),
    # Android – Chrome Mobile
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.6367.82 Mobile Safari/537.36"
    ),
    # Windows – Edge
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
    ),
]


class UserAgentRotator:
    """
    Maintains a pool of User-Agent strings and rotates them.

    Parameters
    ----------
    rotate_after:
        Number of requests after which the UA is rotated.
        Set to 0 to rotate on every request.
    pool:
        Custom pool of UA strings.  Uses a built-in pool by default.
    """

    def __init__(
        self,
        rotate_after: int = 10,
        pool: Optional[list[str]] = None,
    ) -> None:
        self._pool = list(pool or _UA_POOL)
        self.rotate_after = rotate_after
        self._current: str = secrets.choice(self._pool)
        self._request_count = 0

    @property
    def current(self) -> str:
        """The currently active User-Agent string."""
        return self._current

    def get(self) -> str:
        """
        Return the current UA string, rotating if the threshold is reached.
        """
        if self.rotate_after == 0 or self._request_count >= self.rotate_after:
            self._rotate()
        self._request_count += 1
        return self._current

    def _rotate(self) -> None:
        remaining = [ua for ua in self._pool if ua != self._current]
        self._current = secrets.choice(remaining) if remaining else self._current
        self._request_count = 0
        logger.debug("User-Agent rotated.")


# ---------------------------------------------------------------------------
# Header sanitizer
# ---------------------------------------------------------------------------

# Headers that can uniquely identify a user or reveal system information
_SENSITIVE_HEADERS = frozenset(
    {
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Client-IP",
        "Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Forwarded",
        "Via",
        "X-Device-User-Agent",
        "X-Original-URL",
        "X-Requested-With",
        "DNT",  # Do Not Track – ironically can be used for fingerprinting
    }
)

# Headers that should be normalised to prevent fingerprinting
_NORMALISED_HEADERS: dict[str, str] = {
    "Accept-Language": "pl-PL,pl;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class HeaderSanitizer:
    """
    Removes identifying HTTP headers and normalises fingerprint-leaking ones.
    """

    def __init__(
        self,
        extra_sensitive: Optional[set[str]] = None,
        normalise: bool = True,
    ) -> None:
        self._sensitive = _SENSITIVE_HEADERS | (extra_sensitive or set())
        self._normalise = normalise

    def sanitize(self, headers: dict[str, str]) -> dict[str, str]:
        """
        Return a sanitised copy of *headers*.

        - Removes sensitive / identifying headers.
        - Optionally normalises Accept-Language, Accept-Encoding, etc.
        """
        result = {
            k: v
            for k, v in headers.items()
            if k not in self._sensitive
        }
        if self._normalise:
            result.update(_NORMALISED_HEADERS)
        return result


# ---------------------------------------------------------------------------
# Timing jitter
# ---------------------------------------------------------------------------


class TimingJitter:
    """
    Adds calibrated random sleep intervals to break timing fingerprints.

    Timing-based fingerprinting correlates inter-keystroke delays,
    page-load timings, and request cadence to identify users even across
    sessions.  Inserting noise into these timings degrades the
    classifier's accuracy.

    Parameters
    ----------
    min_ms / max_ms:
        Range (in milliseconds) of the random delay added per call.
    distribution:
        ``'uniform'`` or ``'gaussian'`` (clipped to [min_ms, max_ms]).
    """

    def __init__(
        self,
        min_ms: float = 10.0,
        max_ms: float = 150.0,
        distribution: str = "uniform",
    ) -> None:
        if min_ms < 0 or max_ms < min_ms:
            raise ValueError("Invalid timing jitter range.")
        self.min_ms = min_ms
        self.max_ms = max_ms
        self.distribution = distribution

    def sleep(self) -> float:
        """Sleep for a random interval; return the actual duration in ms."""
        delay_ms = self._sample()
        time.sleep(delay_ms / 1000.0)
        return delay_ms

    def _sample(self) -> float:
        if self.distribution == "gaussian":
            mid = (self.min_ms + self.max_ms) / 2
            sigma = (self.max_ms - self.min_ms) / 6
            value = random.gauss(mid, sigma)
            return max(self.min_ms, min(self.max_ms, value))
        return random.uniform(self.min_ms, self.max_ms)


# ---------------------------------------------------------------------------
# Combined shield
# ---------------------------------------------------------------------------


class FingerprintShield:
    """
    Convenience wrapper that combines all fingerprint countermeasures.

    Usage::

        shield = FingerprintShield()
        headers = shield.prepare_headers({"Content-Type": "application/json"})
        # ... make HTTP request with headers ...
        shield.jitter()   # optional: add timing noise
    """

    def __init__(
        self,
        ua_rotate_after: int = 10,
        jitter_min_ms: float = 10.0,
        jitter_max_ms: float = 100.0,
        normalise_headers: bool = True,
    ) -> None:
        self.ua_rotator = UserAgentRotator(rotate_after=ua_rotate_after)
        self.header_sanitizer = HeaderSanitizer(normalise=normalise_headers)
        self.timing_jitter = TimingJitter(
            min_ms=jitter_min_ms, max_ms=jitter_max_ms
        )

    def prepare_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Return sanitised headers with current User-Agent injected."""
        sanitised = self.header_sanitizer.sanitize(headers)
        sanitised["User-Agent"] = self.ua_rotator.get()
        return sanitised

    def jitter(self) -> float:
        """Apply timing noise; return the sleep duration in ms."""
        return self.timing_jitter.sleep()
