"""One-time backfill of SUBSCRIPTION_EVENTS from the unsubscribe service's audit.log.

Unsubscribes that happened before SUBSCRIPTION_EVENTS existed only left a trace in
the PHP service's audit.log (on DreamHost, in the CDP_UNSUB_STORAGE_DIR folder):

    2026-10-14T09:12:03-07:00 action=unsubscribe.success success=true token=1a2b3c4d5e6f ip=...

`token` is the first 12 hex chars of sha256(UNSUBSCRIBE_TOKEN), so we can match it
back to a customer. The campaign is *inferred* as the last campaign successfully
sent to that customer before the unsubscribe time; rows are written with
SOURCE='audit_log' so the console labels them "(inferred)".

Only customers who are currently unsubscribed and have no unsubscribe event yet
are backfilled, so the script is safe to re-run.

Usage (dry run by default; prints what it would insert):
    python scripts/backfill_unsubscribe_events.py /path/to/audit.log
    python scripts/backfill_unsubscribe_events.py /path/to/audit.log --apply
"""
from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv

APP_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))
load_dotenv(APP_DIR / ".env")

from mailer import db as dbmod  # noqa: E402

LINE_RE = re.compile(r"^(\S+)\s+action=unsubscribe\.success\s+success=true\s+token=([0-9a-f]{12})\b")


def parse_log(path: pathlib.Path) -> dict[str, datetime]:
    """{token_hash: last successful unsubscribe time (naive UTC)}."""
    latest: dict[str, datetime] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.fromisoformat(m.group(1)).astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            continue
        h = m.group(2)
        if h not in latest or ts > latest[h]:
            latest[h] = ts
    return latest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audit_log", type=pathlib.Path)
    ap.add_argument("--apply", action="store_true", help="write rows (default is a dry run)")
    args = ap.parse_args()

    by_hash = parse_log(args.audit_log)
    print(f"Found {len(by_hash)} distinct successful unsubscribes in {args.audit_log}")

    dbmod.ensure_subscription_event_tables()
    conn = dbmod.get_connection()
    cur = conn.cursor(dbmod.DictCursor)
    planned = []
    for mode, table in dbmod.get_customer_table_options().items():
        cur.execute(
            f"""
            SELECT c.CUSTID, c.EMAIL, c.UNSUBSCRIBE_TOKEN
            FROM {table} c
            WHERE c.IS_SUBSCRIBED = '0' AND c.UNSUBSCRIBE_TOKEN IS NOT NULL AND c.UNSUBSCRIBE_TOKEN <> ''
              AND NOT EXISTS (
                SELECT 1 FROM SUBSCRIPTION_EVENTS e
                WHERE e.CUSTOMER_TABLE = %s AND e.CUSTID = c.CUSTID AND e.ACTION = 'unsubscribe'
              )
            """,
            (table,),
        )
        for row in cur.fetchall():
            h = hashlib.sha256(row["UNSUBSCRIBE_TOKEN"].encode()).hexdigest()[:12]
            when = by_hash.get(h)
            if not when:
                continue
            cur.execute(
                """
                SELECT r.SEND_ID, s.CAMPAIGN_NAME, s.CAMPAIGN_FILE
                FROM CAMPAIGN_SEND_RESULTS r
                JOIN CAMPAIGN_SENDS s ON s.SEND_ID = r.SEND_ID
                WHERE s.MODE = %s AND r.STATUS = 'sent' AND r.ATTEMPTED_AT <= %s
                  AND (r.CUSTID = %s OR LOWER(r.EMAIL) = LOWER(%s))
                ORDER BY r.ATTEMPTED_AT DESC
                LIMIT 1
                """,
                (mode, when, row["CUSTID"], row["EMAIL"]),
            )
            send = cur.fetchone()
            planned.append((table, row, when, send))

    cur.close()
    for table, row, when, send in planned:
        label = (send["CAMPAIGN_NAME"] or send["CAMPAIGN_FILE"]) if send else "(no campaign found)"
        print(f"  {table:14} {row['EMAIL']:40} {when:%Y-%m-%d %H:%M} UTC  {label}")
    print(f"{len(planned)} customer(s) matched.")

    if not args.apply:
        print("Dry run only. Re-run with --apply to write these rows.")
        return 0
    for table, row, when, send in planned:
        dbmod.record_subscription_event(
            customer_table=table,
            custid=row["CUSTID"],
            email=row["EMAIL"],
            action="unsubscribe",
            source="audit_log",
            send_id=send["SEND_ID"] if send else None,
            occurred_at=when,
        )
    print(f"Inserted {len(planned)} row(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
