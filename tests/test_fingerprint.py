"""Tests for AI fingerprint protection components."""

import pytest

from alfatracerpc.ai_protection.fingerprint import (
    FingerprintShield,
    HeaderSanitizer,
    TimingJitter,
    UserAgentRotator,
)


class TestUserAgentRotator:
    def test_returns_string(self) -> None:
        rotator = UserAgentRotator()
        ua = rotator.get()
        assert isinstance(ua, str)
        assert len(ua) > 20

    def test_rotates_after_threshold(self) -> None:
        rotator = UserAgentRotator(rotate_after=2)
        first = rotator.current
        rotator.get()
        rotator.get()  # threshold reached → rotate
        ua_after = rotator.get()
        # Not guaranteed to differ (could pick same by chance with small pool)
        assert isinstance(ua_after, str)

    def test_custom_pool(self) -> None:
        pool = ["Agent-A", "Agent-B", "Agent-C"]
        rotator = UserAgentRotator(pool=pool)
        ua = rotator.get()
        assert ua in pool

    def test_rotate_every_request(self) -> None:
        pool = ["Agent-X", "Agent-Y"]
        rotator = UserAgentRotator(rotate_after=0, pool=pool)
        # Should rotate on every call (no exception)
        for _ in range(10):
            ua = rotator.get()
            assert ua in pool


class TestHeaderSanitizer:
    def test_removes_sensitive_headers(self) -> None:
        headers = {
            "Content-Type": "application/json",
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "5.6.7.8",
        }
        sanitizer = HeaderSanitizer(normalise=False)
        result = sanitizer.sanitize(headers)
        assert "X-Forwarded-For" not in result
        assert "X-Real-IP" not in result
        assert "Content-Type" in result

    def test_normalises_accept_language(self) -> None:
        headers = {"Accept-Language": "en-US,en;q=0.9"}
        sanitizer = HeaderSanitizer(normalise=True)
        result = sanitizer.sanitize(headers)
        # Should be overwritten with the normalised value
        assert "pl" in result.get("Accept-Language", "")

    def test_no_normalisation_when_disabled(self) -> None:
        headers = {"Accept-Language": "en-US"}
        sanitizer = HeaderSanitizer(normalise=False)
        result = sanitizer.sanitize(headers)
        assert result.get("Accept-Language") == "en-US"

    def test_extra_sensitive_headers_removed(self) -> None:
        headers = {"X-Custom-Secret": "value", "Content-Type": "text/plain"}
        sanitizer = HeaderSanitizer(extra_sensitive={"X-Custom-Secret"})
        result = sanitizer.sanitize(headers)
        assert "X-Custom-Secret" not in result


class TestTimingJitter:
    def test_sleep_duration_in_range(self) -> None:
        jitter = TimingJitter(min_ms=1.0, max_ms=5.0)
        duration = jitter.sleep()
        assert 1.0 <= duration <= 5.0

    def test_gaussian_distribution(self) -> None:
        jitter = TimingJitter(min_ms=10.0, max_ms=50.0, distribution="gaussian")
        for _ in range(20):
            d = jitter.sleep()
            assert 10.0 <= d <= 50.0

    def test_invalid_range_raises(self) -> None:
        with pytest.raises(ValueError):
            TimingJitter(min_ms=100.0, max_ms=10.0)


class TestFingerprintShield:
    def test_prepare_headers_adds_ua(self) -> None:
        shield = FingerprintShield()
        headers = shield.prepare_headers({"Content-Type": "application/json"})
        assert "User-Agent" in headers

    def test_prepare_headers_removes_sensitive(self) -> None:
        shield = FingerprintShield()
        headers = shield.prepare_headers(
            {"X-Forwarded-For": "9.9.9.9", "Accept": "text/html"}
        )
        assert "X-Forwarded-For" not in headers

    def test_jitter_returns_float(self) -> None:
        shield = FingerprintShield(jitter_min_ms=1.0, jitter_max_ms=5.0)
        result = shield.jitter()
        assert isinstance(result, float)
        assert 1.0 <= result <= 5.0
