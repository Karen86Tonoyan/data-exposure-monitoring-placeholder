"""
DNS Privacy – provides DNS-over-HTTPS (DoH) resolution to prevent
DNS leaks, and implements DNS query filtering to block known tracker
and surveillance domains.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)

# Well-known DoH providers
DOH_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
    "quad9": "https://dns.quad9.net:5053/dns-query",
}

# Tracker / surveillance domain blocklist (partial, illustrative)
_BLOCKLIST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(^|\.)doubleclick\.net$"),
    re.compile(r"(^|\.)googleadservices\.com$"),
    re.compile(r"(^|\.)googlesyndication\.com$"),
    re.compile(r"(^|\.)facebook\.com$"),
    re.compile(r"(^|\.)connect\.facebook\.net$"),
    re.compile(r"(^|\.)analytics\.google\.com$"),
    re.compile(r"(^|\.)google-analytics\.com$"),
    re.compile(r"(^|\.)scorecardresearch\.com$"),
    re.compile(r"(^|\.)quantserve\.com$"),
    re.compile(r"(^|\.)adnxs\.com$"),
    re.compile(r"(^|\.)adsrvr\.org$"),
    re.compile(r"(^|\.)moatads\.com$"),
    re.compile(r"(^|\.)hotjar\.com$"),
    re.compile(r"(^|\.)mouseflow\.com$"),
    re.compile(r"(^|\.)mixpanel\.com$"),
    re.compile(r"(^|\.)segment\.io$"),
    re.compile(r"(^|\.)segment\.com$"),
    re.compile(r"(^|\.)amplitude\.com$"),
    re.compile(r"(^|\.)heap\.io$"),
    re.compile(r"(^|\.)fullstory\.com$"),
]


class DNSPrivacy:
    """
    Privacy-preserving DNS resolver.

    - Resolves queries via DNS-over-HTTPS to prevent eavesdropping.
    - Optionally blocks known tracker / surveillance domains.
    - Caches results to minimise external queries.

    Parameters
    ----------
    provider:
        DoH provider name from :data:`DOH_PROVIDERS` or a custom URL.
    block_trackers:
        If True, return ``None`` for blocked domains instead of resolving.
    """

    def __init__(
        self,
        provider: str = "cloudflare",
        block_trackers: bool = True,
    ) -> None:
        self.doh_url = DOH_PROVIDERS.get(provider, provider)
        self.block_trackers = block_trackers
        self._cache: dict[str, Optional[str]] = {}

    def is_blocked(self, domain: str) -> bool:
        """Return True if *domain* matches the tracker blocklist."""
        domain = domain.rstrip(".").lower()
        return any(p.search(domain) for p in _BLOCKLIST_PATTERNS)

    def resolve(self, domain: str, record_type: str = "A") -> Optional[str]:
        """
        Resolve *domain* via DoH.

        Returns the first matching IP address or None if blocked / not found.
        """
        cache_key = f"{record_type}:{domain}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self.block_trackers and self.is_blocked(domain):
            logger.info("Blocked tracker domain: %s", domain)
            self._cache[cache_key] = None
            return None

        url = (
            f"{self.doh_url}?name={urllib.parse.quote(domain)}"
            f"&type={record_type}"
        )
        result = self._query_doh(url)
        self._cache[cache_key] = result
        return result

    def _query_doh(self, url: str) -> Optional[str]:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "AlfaTracerPC/0.1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                answers = data.get("Answer", [])
                for answer in answers:
                    if answer.get("type") in (1, 28):  # A or AAAA
                        return answer.get("data")
        except Exception as exc:  # noqa: BLE001
            logger.warning("DoH query failed for %s: %s", url, exc)
        return None


# Avoid circular import in urllib.parse used above
import urllib.parse  # noqa: E402 (must come after class body)
