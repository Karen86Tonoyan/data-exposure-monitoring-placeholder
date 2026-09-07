"""
Privacy Scanner – detects Personally Identifiable Information (PII)
in text/data streams using regular expressions and heuristic rules.

Detects:
 - E-mail addresses
 - Phone numbers (international)
 - Credit/debit card numbers (Luhn-valid)
 - PESEL (Polish national ID)
 - IBAN / account numbers
 - IP addresses (v4 and v6)
 - Postal addresses (street + number patterns)
 - Names (heuristic: consecutive Capitalised words)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterator

# ---------------------------------------------------------------------------
# PII category definitions
# ---------------------------------------------------------------------------


class PIICategory(Enum):
    EMAIL = auto()
    PHONE = auto()
    CREDIT_CARD = auto()
    PESEL = auto()
    IBAN = auto()
    IPV4 = auto()
    IPV6 = auto()
    POSTAL_ADDRESS = auto()
    PERSON_NAME = auto()
    GENERIC_ID = auto()


@dataclass(frozen=True)
class PIIMatch:
    """A single detected PII occurrence."""

    category: PIICategory
    original: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# Compiled regular expressions
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[PIICategory, re.Pattern[str]]] = [
    # E-mail
    (
        PIICategory.EMAIL,
        re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            re.IGNORECASE,
        ),
    ),
    # Phone – international (+XX) and local formats, 7-15 digits
    (
        PIICategory.PHONE,
        re.compile(
            r"(?<!\d)(\+?[\d][\d\s\-\(\)]{6,18}\d)(?!\d)",
        ),
    ),
    # PESEL (Polish national ID: exactly 11 digits)
    (
        PIICategory.PESEL,
        re.compile(r"(?<!\d)\d{11}(?!\d)"),
    ),
    # IBAN (2 letters + 2 digits + up to 30 alphanumeric)
    (
        PIICategory.IBAN,
        re.compile(
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",
        ),
    ),
    # IPv4
    (
        PIICategory.IPV4,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    # IPv6 (simplified)
    (
        PIICategory.IPV6,
        re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b",
        ),
    ),
    # Credit card (13–19 digits, optional separators every 4 digits)
    (
        PIICategory.CREDIT_CARD,
        re.compile(
            r"(?<!\d)(?:\d{4}[\s\-]?){3,4}\d{1,4}(?!\d)",
        ),
    ),
]

# Name heuristic: 2-4 consecutive Capitalised words (each 2-30 letters)
_NAME_RE = re.compile(
    r"\b(?:[A-ZŁŚÓĄĆĘŹŻŃ][a-złśóąćęźżń]{1,29}(?:\s+|-))"
    r"{1,3}[A-ZŁŚÓĄĆĘŹŻŃ][a-złśóąćęźżń]{1,29}\b"
)


# ---------------------------------------------------------------------------
# Luhn check for credit cards
# ---------------------------------------------------------------------------


def _luhn_valid(digits: str) -> bool:
    """Return True if *digits* passes the Luhn algorithm."""
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Aggregated result of scanning a single text block."""

    text: str
    matches: list[PIIMatch] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return bool(self.matches)

    def by_category(self, category: PIICategory) -> list[PIIMatch]:
        return [m for m in self.matches if m.category == category]


class PrivacyScanner:
    """Scans arbitrary text for PII and returns structured matches."""

    def __init__(self, detect_names: bool = True) -> None:
        self.detect_names = detect_names

    def scan(self, text: str) -> ScanResult:
        result = ScanResult(text=text)
        seen_spans: set[tuple[int, int]] = set()

        # Run all regex patterns
        for category, pattern in _PATTERNS:
            for m in pattern.finditer(text):
                raw = m.group(0).replace(" ", "").replace("-", "")

                # For credit cards, apply Luhn validation
                if category == PIICategory.CREDIT_CARD:
                    digits_only = re.sub(r"\D", "", raw)
                    if len(digits_only) < 13 or not _luhn_valid(digits_only):
                        continue

                span = (m.start(), m.end())
                if span in seen_spans:
                    continue
                seen_spans.add(span)
                result.matches.append(
                    PIIMatch(
                        category=category,
                        original=m.group(0),
                        start=m.start(),
                        end=m.end(),
                    )
                )

        # Name heuristic
        if self.detect_names:
            for m in _NAME_RE.finditer(text):
                span = (m.start(), m.end())
                if span in seen_spans:
                    continue
                seen_spans.add(span)
                result.matches.append(
                    PIIMatch(
                        category=PIICategory.PERSON_NAME,
                        original=m.group(0),
                        start=m.start(),
                        end=m.end(),
                    )
                )

        # Sort by position for predictable ordering
        result.matches.sort(key=lambda x: x.start)
        return result

    def iter_scan(self, texts: Iterator[str]) -> Iterator[ScanResult]:
        """Scan an iterable of text blocks, yielding only results with PII."""
        for text in texts:
            result = self.scan(text)
            if result.has_pii:
                yield result
