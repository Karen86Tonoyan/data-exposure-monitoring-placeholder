"""Tests for the PrivacyScanner."""

import pytest

from alfatracerpc.core.scanner import PIICategory, PrivacyScanner


@pytest.fixture
def scanner() -> PrivacyScanner:
    return PrivacyScanner(detect_names=True)


class TestEmailDetection:
    def test_plain_email(self, scanner: PrivacyScanner) -> None:
        result = scanner.scan("Contact me at jan.kowalski@example.com please.")
        emails = result.by_category(PIICategory.EMAIL)
        assert len(emails) == 1
        assert emails[0].original == "jan.kowalski@example.com"

    def test_no_email_in_clean_text(self, scanner: PrivacyScanner) -> None:
        result = scanner.scan("No sensitive data here.")
        assert not result.has_pii

    def test_multiple_emails(self, scanner: PrivacyScanner) -> None:
        text = "From: a@b.com to c@d.org"
        result = scanner.scan(text)
        emails = result.by_category(PIICategory.EMAIL)
        assert len(emails) == 2


class TestPhoneDetection:
    def test_polish_mobile(self, scanner: PrivacyScanner) -> None:
        result = scanner.scan("Call me: +48 123 456 789")
        phones = result.by_category(PIICategory.PHONE)
        assert len(phones) >= 1

    def test_phone_without_country_code(self, scanner: PrivacyScanner) -> None:
        result = scanner.scan("Tel: 123456789")
        phones = result.by_category(PIICategory.PHONE)
        assert len(phones) >= 1


class TestPESELDetection:
    def test_valid_pesel_sequence(self, scanner: PrivacyScanner) -> None:
        # 11 consecutive digits
        result = scanner.scan("PESEL: 85010112345")
        pesels = result.by_category(PIICategory.PESEL)
        assert len(pesels) >= 1

    def test_12_digit_not_pesel(self, scanner: PrivacyScanner) -> None:
        # 12 digits should NOT be matched as PESEL (boundary check)
        result = scanner.scan("Number: 123456789012")
        pesels = result.by_category(PIICategory.PESEL)
        assert len(pesels) == 0


class TestCreditCardDetection:
    def test_visa_luhn_valid(self, scanner: PrivacyScanner) -> None:
        # Classic Visa test number (passes Luhn)
        result = scanner.scan("Card: 4111 1111 1111 1111")
        cards = result.by_category(PIICategory.CREDIT_CARD)
        assert len(cards) == 1

    def test_invalid_luhn_not_detected(self, scanner: PrivacyScanner) -> None:
        # All zeros – fails Luhn (0000 0000 0000 0000 → checksum 0 → valid
        # actually but all-zeros is valid Luhn, so let's use a different invalid)
        # 4111 1111 1111 1112 fails Luhn
        result = scanner.scan("Card: 4111 1111 1111 1112")
        cards = result.by_category(PIICategory.CREDIT_CARD)
        assert len(cards) == 0


class TestIPDetection:
    def test_ipv4(self, scanner: PrivacyScanner) -> None:
        result = scanner.scan("Server at 192.168.1.100")
        ips = result.by_category(PIICategory.IPV4)
        assert len(ips) == 1
        assert ips[0].original == "192.168.1.100"

    def test_ipv6(self, scanner: PrivacyScanner) -> None:
        result = scanner.scan("Addr: 2001:db8:85a3:0000:0000:8a2e:0370:7334")
        ips = result.by_category(PIICategory.IPV6)
        assert len(ips) >= 1


class TestNameDetection:
    def test_two_word_name(self, scanner: PrivacyScanner) -> None:
        result = scanner.scan("My name is Jan Kowalski.")
        names = result.by_category(PIICategory.PERSON_NAME)
        assert len(names) >= 1

    def test_no_name_in_lowercase(self, scanner: PrivacyScanner) -> None:
        result = scanner.scan("this is just normal text here")
        names = result.by_category(PIICategory.PERSON_NAME)
        assert len(names) == 0


class TestScanResult:
    def test_sorted_by_position(self, scanner: PrivacyScanner) -> None:
        text = "Email a@b.com and IP 10.0.0.1"
        result = scanner.scan(text)
        positions = [m.start for m in result.matches]
        assert positions == sorted(positions)

    def test_no_pii_flag(self, scanner: PrivacyScanner) -> None:
        result = scanner.scan("hello world")
        assert not result.has_pii

    def test_iter_scan_filters_empty(self, scanner: PrivacyScanner) -> None:
        texts = ["no pii here", "email: x@y.com", "also clean"]
        results = list(scanner.iter_scan(iter(texts)))
        assert len(results) == 1
        assert results[0].by_category(PIICategory.EMAIL)
