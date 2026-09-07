"""
Data Masker – replaces detected PII with realistic synthetic equivalents.

For each PIICategory the masker provides a synthetic replacement that:
 - preserves format (length, separators, character class)
 - is deterministic per (session_key, original) by default so that the
   same value always maps to the same fake within a single session
 - is optionally randomised per call for maximum unlinkability
"""

from __future__ import annotations

import hashlib
import random
import re
import string
from typing import Optional

from alfatracerpc.core.scanner import PIICategory, PIIMatch, ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seeded_rng(seed_str: str, session_key: str) -> random.Random:
    digest = hashlib.sha256(f"{session_key}:{seed_str}".encode()).hexdigest()
    seed = int(digest[:16], 16)
    return random.Random(seed)


def _random_digits(rng: random.Random, count: int) -> str:
    return "".join(str(rng.randint(0, 9)) for _ in range(count))


def _luhn_complete(partial: str) -> str:
    """Append a Luhn check-digit to *partial* (digits only)."""
    total = 0
    for i, ch in enumerate(reversed(partial)):
        n = int(ch)
        if i % 2 == 0:  # even index from right → double
            n *= 2
            if n > 9:
                n -= 9
        total += n
    check = (10 - (total % 10)) % 10
    return partial + str(check)


# ---------------------------------------------------------------------------
# Per-category synthetic generators
# ---------------------------------------------------------------------------


def _fake_email(original: str, rng: random.Random) -> str:
    parts = original.split("@")
    tld = parts[1].rsplit(".", 1)[-1] if "." in parts[1] else "com"
    domain_choices = ["mailbox", "secure", "private", "anon", "shadow"]
    user = "".join(rng.choices(string.ascii_lowercase, k=8))
    domain = rng.choice(domain_choices)
    return f"{user}@{domain}.{tld}"


def _fake_phone(original: str, rng: random.Random) -> str:
    prefix = "+48" if original.startswith("+48") else "+00"
    digits = _random_digits(rng, 9)
    return f"{prefix}{digits}"


def _fake_credit_card(original: str, rng: random.Random) -> str:
    separators = re.findall(r"[\s\-]", original)
    sep = separators[0] if separators else ""
    digits_only = re.sub(r"\D", "", original)
    n = len(digits_only)
    partial = _random_digits(rng, n - 1)
    full = _luhn_complete(partial)
    # Reformat into groups of 4
    groups = [full[i : i + 4] for i in range(0, len(full), 4)]
    return sep.join(groups)


def _fake_pesel(original: str, rng: random.Random) -> str:
    """Generate a syntactically valid synthetic PESEL."""
    year = rng.randint(0, 99)
    month = rng.randint(1, 12)
    day = rng.randint(1, 28)
    seq = rng.randint(0, 999)
    base = f"{year:02d}{month:02d}{day:02d}{seq:04d}"
    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    checksum = sum(int(base[i]) * weights[i] for i in range(10)) % 10
    check = (10 - checksum) % 10
    return base + str(check)


def _fake_iban(original: str, rng: random.Random) -> str:
    country = original[:2]
    length = len(re.sub(r"\s", "", original))
    body = _random_digits(rng, length - 4)
    check = _random_digits(rng, 2)
    return f"{country}{check}{body}"


def _fake_ipv4(rng: random.Random) -> str:
    # Use documentation range (RFC 5737) to avoid collisions
    return f"192.0.2.{rng.randint(1, 254)}"


def _fake_ipv6(rng: random.Random) -> str:
    groups = [f"{rng.randint(0, 0xFFFF):04x}" for _ in range(8)]
    return ":".join(groups)


def _fake_name(original: str, rng: random.Random) -> str:
    first_names = [
        "Marek", "Anna", "Piotr", "Katarzyna", "Tomasz",
        "Agnieszka", "Michał", "Monika", "Paweł", "Joanna",
    ]
    last_names = [
        "Nowak", "Kowalski", "Wiśniewski", "Wójcik", "Kowalczyk",
        "Kamiński", "Lewandowski", "Zieliński", "Szymański", "Woźniak",
    ]
    # Preserve word-count structure
    word_count = len(original.split())
    if word_count >= 2:
        return f"{rng.choice(first_names)} {rng.choice(last_names)}"
    return rng.choice(first_names)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class DataMasker:
    """
    Replaces PII detected by PrivacyScanner with synthetic equivalents.

    Parameters
    ----------
    session_key:
        Secret seed that makes replacements deterministic within a session.
        Change this between sessions for unlinkability. Pass ``None`` to
        generate a fresh random session key.
    randomise:
        If True, ignore *session_key* and use a fresh random seed for each
        replacement (maximum unlinkability at the cost of consistency).
    """

    def __init__(
        self,
        session_key: Optional[str] = None,
        randomise: bool = False,
    ) -> None:
        if session_key is None:
            import secrets
            session_key = secrets.token_hex(16)
        self.session_key = session_key
        self.randomise = randomise
        self._cache: dict[str, str] = {}

    def _rng_for(self, original: str) -> random.Random:
        if self.randomise:
            return random.Random()
        return _seeded_rng(original, self.session_key)

    def mask_match(self, match: PIIMatch) -> str:
        """Return a synthetic replacement for a single PIIMatch."""
        key = f"{match.category.name}:{match.original}"
        if key in self._cache:
            return self._cache[key]

        rng = self._rng_for(match.original)
        cat = match.category

        if cat == PIICategory.EMAIL:
            fake = _fake_email(match.original, rng)
        elif cat == PIICategory.PHONE:
            fake = _fake_phone(match.original, rng)
        elif cat == PIICategory.CREDIT_CARD:
            fake = _fake_credit_card(match.original, rng)
        elif cat == PIICategory.PESEL:
            fake = _fake_pesel(match.original, rng)
        elif cat == PIICategory.IBAN:
            fake = _fake_iban(match.original, rng)
        elif cat == PIICategory.IPV4:
            fake = _fake_ipv4(rng)
        elif cat == PIICategory.IPV6:
            fake = _fake_ipv6(rng)
        elif cat == PIICategory.PERSON_NAME:
            fake = _fake_name(match.original, rng)
        else:
            # Generic: replace each digit with random digit, keep structure
            fake = re.sub(r"\d", lambda _: str(rng.randint(0, 9)), match.original)

        self._cache[key] = fake
        return fake

    def mask_text(self, scan_result: ScanResult) -> str:
        """
        Replace all PII found in *scan_result* with synthetic values.

        Applies replacements from right to left so that span indices remain
        valid as the string length changes.
        """
        text = scan_result.text
        for match in reversed(scan_result.matches):
            replacement = self.mask_match(match)
            text = text[: match.start] + replacement + text[match.end :]
        return text

    def reset_cache(self) -> None:
        """Clear the replacement cache (forces new synthetic values)."""
        self._cache.clear()
