"""
Privacy Database – SQLite-backed store for:
  - Replacement rules (whitelist / blacklist of PII patterns)
  - Event log (when and what category of PII was detected & masked)
  - Session registry (maps session keys to creation timestamps)
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Iterator, Optional

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type   TEXT    NOT NULL CHECK(rule_type IN ('whitelist', 'blacklist')),
    pattern     TEXT    NOT NULL,
    description TEXT,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT,
    category    TEXT    NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    occurred_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT    PRIMARY KEY,
    created_at  TEXT    NOT NULL,
    ended_at    TEXT
);
"""


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class PrivacyDB:
    """
    Lightweight SQLite database for AlfaTracerPC.

    Parameters
    ----------
    path:
        Path to the SQLite database file.  Use ``":memory:"`` for an
        in-process ephemeral database (useful in tests).
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._conn: Optional[sqlite3.Connection] = None
        self._open()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _open(self) -> None:
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.debug("PrivacyDB opened at %s", self.path)

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    @contextlib.contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        if self._conn is None:
            raise RuntimeError("Database is closed.")
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def add_rule(
        self,
        rule_type: str,
        pattern: str,
        description: str = "",
    ) -> int:
        """Insert a whitelist or blacklist rule; return its row id."""
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO rules (rule_type, pattern, description, created_at) "
                "VALUES (?, ?, ?, ?)",
                (rule_type, pattern, description, _now()),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_rules(self, rule_type: Optional[str] = None) -> list[sqlite3.Row]:
        """Return all rules, optionally filtered by type."""
        with self._cursor() as cur:
            if rule_type:
                cur.execute(
                    "SELECT * FROM rules WHERE rule_type = ? ORDER BY id",
                    (rule_type,),
                )
            else:
                cur.execute("SELECT * FROM rules ORDER BY id")
            return cur.fetchall()

    def delete_rule(self, rule_id: int) -> None:
        """Delete a rule by ID."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM rules WHERE id = ?", (rule_id,))

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def log_event(
        self,
        category: str,
        count: int = 1,
        session_id: Optional[str] = None,
    ) -> None:
        """Log a PII detection event."""
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO events (session_id, category, count, occurred_at) "
                "VALUES (?, ?, ?, ?)",
                (session_id, category, count, _now()),
            )

    def get_events(
        self,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        """Return recent events, optionally filtered by session."""
        with self._cursor() as cur:
            if session_id:
                cur.execute(
                    "SELECT * FROM events WHERE session_id = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (session_id, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            return cur.fetchall()

    def event_summary(self) -> dict[str, int]:
        """Return total PII detections grouped by category."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT category, SUM(count) as total FROM events GROUP BY category"
            )
            return {row["category"]: row["total"] for row in cur.fetchall()}

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def register_session(self, session_id: str) -> None:
        """Record a new session."""
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO sessions (id, created_at) VALUES (?, ?)",
                (session_id, _now()),
            )

    def end_session(self, session_id: str) -> None:
        """Mark a session as ended."""
        with self._cursor() as cur:
            cur.execute(
                "UPDATE sessions SET ended_at = ? WHERE id = ?",
                (_now(), session_id),
            )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "PrivacyDB":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
