#!/usr/bin/env python3
"""
AlfaTracerPC – CLI entry point.

Usage examples:

    # Scan a text string for PII and show a report
    python -m alfatracerpc scan "Hello, my email is jan.kowalski@example.com"

    # Mask PII in a text string
    python -m alfatracerpc mask "Phone: +48 123 456 789"

    # Mask PII from stdin
    echo "ID: 12345678901" | python -m alfatracerpc mask -

    # Start the local scrubbing proxy (Ctrl-C to stop)
    python -m alfatracerpc proxy --port 8080

    # Show database event summary
    python -m alfatracerpc stats
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from alfatracerpc import __version__
from alfatracerpc.config import Config
from alfatracerpc.core.masker import DataMasker
from alfatracerpc.core.monitor import ProxyServer
from alfatracerpc.core.scanner import PrivacyScanner
from alfatracerpc.database.db import PrivacyDB


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        level=getattr(logging, level.upper(), logging.INFO),
    )


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace, cfg: Config) -> int:
    text = _read_input(args.text)
    scanner = PrivacyScanner(detect_names=cfg.detect_names)
    result = scanner.scan(text)

    if not result.has_pii:
        print("No PII detected.")
        return 0

    report: dict[str, object] = {
        "total_items": len(result.matches),
        "by_category": {},
    }
    for match in result.matches:
        cat = match.category.name
        report["by_category"].setdefault(cat, [])  # type: ignore[union-attr]
        report["by_category"][cat].append(  # type: ignore[index]
            {"start": match.start, "end": match.end}
        )

    print(json.dumps(report, indent=2, ensure_ascii=False))

    # Log to database
    if args.db:
        with PrivacyDB(path=args.db) as db:
            for match in result.matches:
                db.log_event(match.category.name, count=1)

    return 0


def cmd_mask(args: argparse.Namespace, cfg: Config) -> int:
    text = _read_input(args.text)
    scanner = PrivacyScanner(detect_names=cfg.detect_names)
    masker = DataMasker(randomise=cfg.randomise_replacements)

    result = scanner.scan(text)
    masked = masker.mask_text(result)
    print(masked)

    if args.db and result.has_pii:
        with PrivacyDB(path=args.db) as db:
            for match in result.matches:
                db.log_event(match.category.name, count=1)

    return 0


def cmd_proxy(args: argparse.Namespace, cfg: Config) -> int:
    port = args.port or cfg.proxy_port
    proxy = ProxyServer(host="127.0.0.1", port=port)
    proxy.start()
    print(f"AlfaTracerPC privacy proxy running on http://127.0.0.1:{port}")
    print("Press Ctrl-C to stop.")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        proxy.stop()
        print("\nProxy stopped.")
    return 0


def cmd_stats(args: argparse.Namespace, _cfg: Config) -> int:
    db_path = args.db or "~/.alfatracerpc/privacy.db"
    with PrivacyDB(path=Path(db_path).expanduser()) as db:
        summary = db.event_summary()
    if not summary:
        print("No events recorded yet.")
        return 0
    total = sum(summary.values())
    print(f"Total PII items detected: {total}")
    for cat, count in sorted(summary.items(), key=lambda x: -x[1]):
        print(f"  {cat:<20} {count}")
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_input(text: str) -> str:
    if text == "-":
        return sys.stdin.read()
    return text


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alfatracerpc",
        description="AlfaTracerPC – Privacy Protection Suite",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Path to JSON config file.",
        default=None,
    )
    parser.add_argument(
        "--db",
        metavar="FILE",
        help="Path to SQLite database (default: ~/.alfatracerpc/privacy.db).",
        default=None,
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Scan text for PII.")
    p_scan.add_argument(
        "text",
        help='Text to scan (use "-" to read from stdin).',
    )

    # mask
    p_mask = sub.add_parser("mask", help="Mask PII in text.")
    p_mask.add_argument(
        "text",
        help='Text to mask (use "-" to read from stdin).',
    )

    # proxy
    p_proxy = sub.add_parser("proxy", help="Run the local scrubbing proxy.")
    p_proxy.add_argument(
        "--port", type=int, default=0, help="Port to listen on (default: 8080)."
    )

    # stats
    sub.add_parser("stats", help="Show database statistics.")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.log_level)
    cfg = Config(path=args.config)

    dispatch = {
        "scan": cmd_scan,
        "mask": cmd_mask,
        "proxy": cmd_proxy,
        "stats": cmd_stats,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1
    return handler(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
