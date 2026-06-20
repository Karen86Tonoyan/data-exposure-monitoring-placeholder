"""Tests for the privacy database."""

import pytest

from alfatracerpc.database.db import PrivacyDB


@pytest.fixture
def db() -> PrivacyDB:
    """In-memory database – no files created."""
    return PrivacyDB(path=":memory:")


class TestRules:
    def test_add_and_retrieve_rule(self, db: PrivacyDB) -> None:
        rule_id = db.add_rule("whitelist", r"internal\.corp", "Internal domain")
        rules = db.get_rules()
        assert len(rules) == 1
        assert rules[0]["id"] == rule_id
        assert rules[0]["rule_type"] == "whitelist"
        assert rules[0]["pattern"] == r"internal\.corp"

    def test_filter_by_type(self, db: PrivacyDB) -> None:
        db.add_rule("whitelist", r"safe\.domain")
        db.add_rule("blacklist", r"tracker\.io")
        whitelists = db.get_rules("whitelist")
        blacklists = db.get_rules("blacklist")
        assert len(whitelists) == 1
        assert len(blacklists) == 1

    def test_delete_rule(self, db: PrivacyDB) -> None:
        rule_id = db.add_rule("blacklist", r"evil\.net")
        db.delete_rule(rule_id)
        rules = db.get_rules()
        assert len(rules) == 0

    def test_invalid_rule_type_raises(self, db: PrivacyDB) -> None:
        with pytest.raises(Exception):
            db.add_rule("invalid_type", r"pattern")


class TestEvents:
    def test_log_and_retrieve_event(self, db: PrivacyDB) -> None:
        db.log_event("EMAIL", count=3, session_id="sess-1")
        events = db.get_events()
        assert len(events) == 1
        assert events[0]["category"] == "EMAIL"
        assert events[0]["count"] == 3

    def test_filter_events_by_session(self, db: PrivacyDB) -> None:
        db.log_event("EMAIL", session_id="A")
        db.log_event("PHONE", session_id="B")
        events_a = db.get_events(session_id="A")
        assert len(events_a) == 1
        assert events_a[0]["category"] == "EMAIL"

    def test_event_summary(self, db: PrivacyDB) -> None:
        db.log_event("EMAIL", count=5)
        db.log_event("EMAIL", count=3)
        db.log_event("PHONE", count=2)
        summary = db.event_summary()
        assert summary["EMAIL"] == 8
        assert summary["PHONE"] == 2

    def test_empty_summary(self, db: PrivacyDB) -> None:
        summary = db.event_summary()
        assert summary == {}


class TestSessions:
    def test_register_and_end_session(self, db: PrivacyDB) -> None:
        db.register_session("session-xyz")
        db.end_session("session-xyz")
        # No exception means success; verify via events table indirectly
        db.log_event("EMAIL", session_id="session-xyz")
        events = db.get_events(session_id="session-xyz")
        assert len(events) == 1

    def test_duplicate_session_register_is_idempotent(self, db: PrivacyDB) -> None:
        db.register_session("dup-session")
        db.register_session("dup-session")  # should not raise


class TestContextManager:
    def test_context_manager_closes_db(self) -> None:
        with PrivacyDB(path=":memory:") as db:
            db.log_event("EMAIL")
            events = db.get_events()
            assert len(events) == 1
        # After __exit__, connection is closed
        assert db._conn is None
