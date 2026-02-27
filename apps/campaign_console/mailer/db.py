"""MySQL connection helpers.
- Loads credentials from .env (via app.py at startup).
- Uses PyMySQL to avoid native semaphore issues.
"""
from __future__ import annotations
import os
import re
import secrets
import threading
from datetime import datetime
import pymysql
from pymysql.cursors import DictCursor
from pymysql.constants import ER


_conn_state = threading.local()

_customer_table_state = threading.local()
_TABLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.$]+$")

CLAIM_STALE_SECONDS = int(os.getenv("SEND_CLAIM_STALE_SECONDS", "300"))


def _normalize_table(table: str | None) -> str:
    candidate = (table or "").strip()
    if not candidate:
        return "CUSTOMERS"
    if not _TABLE_NAME_PATTERN.match(candidate):
        return "CUSTOMERS"
    return candidate


_DEFAULT_CUSTOMER_TABLE = _normalize_table(os.getenv("DB_CUSTOMER_TABLE", "CUSTOMERS"))
_TEST_CUSTOMER_TABLE = _normalize_table(os.getenv("DB_TEST_CUSTOMER_TABLE", "TESTCUSTOMERS"))


def get_customer_table_options() -> dict[str, str]:
    """Return the physical table names used for each mode."""
    return {"production": _DEFAULT_CUSTOMER_TABLE, "test": _TEST_CUSTOMER_TABLE}


def set_customer_table_mode(mode: str | None):
    """Select the CUSTOMER or TESTCUSTOMER table for the current context."""
    normalized = (mode or "").strip().lower()
    table = _TEST_CUSTOMER_TABLE if normalized == "test" else _DEFAULT_CUSTOMER_TABLE
    _customer_table_state.name = _normalize_table(table)


def clear_customer_table_mode():
    if hasattr(_customer_table_state, "name"):
        delattr(_customer_table_state, "name")
    close_connection()


def get_customer_table_name() -> str:
    table = getattr(_customer_table_state, "name", None)
    return _normalize_table(table or _DEFAULT_CUSTOMER_TABLE)


def _connect():
    """Build a fresh MySQL connection from environment settings."""
    return pymysql.connect(
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    database=os.getenv("DB_NAME"),
    autocommit=True,
    )


class DuplicateCustomerError(Exception):
    """Raised when inserting a customer that already exists."""


class CustomerNotFoundError(Exception):
    """Raised when a requested customer row does not exist."""


class ServiceUserAlreadyExists(Exception):
    """Raised when attempting to create a duplicate service user."""


def get_connection():
    conn = getattr(_conn_state, "connection", None)
    if conn is None:
        conn = _connect()
        _conn_state.connection = conn
        return conn
    try:
        # Ensure the existing connection is alive; reconnect if it dropped.
        conn.ping(reconnect=True)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        conn = _connect()
        _conn_state.connection = conn
    return conn


def close_connection():
    conn = getattr(_conn_state, "connection", None)
    if conn is None:
        return
    try:
        conn.close()
    except Exception:
        pass
    finally:
        if hasattr(_conn_state, "connection"):
            delattr(_conn_state, "connection")



def fetch_subscribed_customers():
    """Returns basic fields needed for sending.
    Keep this read-only in the campaign app; writes occur only in the unsubscribe service.
    """
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    table = get_customer_table_name()
    cur.execute(
    f"""
    SELECT CUSTID, FIRSTNAME, LASTNAME, EMAIL, UNSUBSCRIBE_TOKEN
    FROM {table}
    WHERE IS_SUBSCRIBED = 1 AND EMAIL IS NOT NULL AND EMAIL <> ''
    """
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def _blank_to_empty(value: str | None) -> str:
    """All optional columns are defined as NOT NULL in CUSTOMERS."""
    if value is None:
        return ""
    value = value.strip()
    return value or ""


_CUSTOMER_FIELD_SET = """
    CUSTID,
    FIRSTNAME,
    LASTNAME,
    EMAIL,
    COMPANY,
    PHONE,
    COMMENTS,
    IS_SUBSCRIBED,
    UNSUBSCRIBE_TOKEN
"""


def fetch_all_customers():
    """Return every customer with editable fields."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    table = get_customer_table_name()
    cur.execute(
    f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM {table}
    ORDER BY CUSTID DESC
    """
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def find_duplicate_emails() -> dict[str, list[dict]]:
    """Return customers grouped by LOWER(EMAIL) where more than one row shares that email."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    table = get_customer_table_name()
    cur.execute(
    f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM {table}
    WHERE LOWER(EMAIL) IN (
        SELECT LOWER(EMAIL)
        FROM {table}
        WHERE EMAIL IS NOT NULL AND EMAIL <> ''
        GROUP BY LOWER(EMAIL)
        HAVING COUNT(*) > 1
    )
    ORDER BY LOWER(EMAIL), CUSTID ASC
    """
    )
    rows = cur.fetchall()
    cur.close()

    groups: dict[str, list[dict]] = {}
    for row in rows:
        key = (row.get("EMAIL") or "").strip().lower()
        if key:
            groups.setdefault(key, []).append(row)
    return groups


def count_customer_stats() -> dict:
    """Return the total number of customers and subscribers."""
    conn = get_connection()
    table = get_customer_table_name()
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN IS_SUBSCRIBED = 1 THEN 1 ELSE 0 END) AS subscribed
        FROM {table}
        """
    )
    row = cur.fetchone()
    cur.close()
    total = int(row[0]) if row else 0
    subscribed = int(row[1]) if row and row[1] is not None else 0
    return {"total_customers": total, "total_subscribers": subscribed}


def fetch_customers_paginated(*, search: str | None = None, limit: int = 50, offset: int = 0):
    """Return a page of customers along with the total count."""
    conn = get_connection()
    normalized_limit = max(1, int(limit))
    normalized_offset = max(0, int(offset))
    table = get_customer_table_name()

    where_clause = ""
    search_params: list[str] = []
    if search:
        term = search.strip().lower()
        if term:
            like = f"%{term}%"
            where_clause = """
        WHERE
            LOWER(FIRSTNAME) LIKE %s OR
            LOWER(LASTNAME) LIKE %s OR
            LOWER(EMAIL) LIKE %s OR
            LOWER(COMPANY) LIKE %s OR
            LOWER(PHONE) LIKE %s OR
            LOWER(COMMENTS) LIKE %s
        """
            search_params = [like] * 6

    count_sql = f"SELECT COUNT(*) AS total FROM {table} {where_clause}"
    count_cur = conn.cursor()
    count_cur.execute(count_sql, search_params)
    count_row = count_cur.fetchone()
    total = int(count_row[0]) if count_row else 0
    count_cur.close()

    data_sql = f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM {table}
    {where_clause}
    ORDER BY CUSTID DESC
    LIMIT %s OFFSET %s
    """
    params = list(search_params)
    params.extend([normalized_limit, normalized_offset])
    data_cur = conn.cursor(DictCursor)
    data_cur.execute(data_sql, params)
    rows = data_cur.fetchall()
    data_cur.close()

    return rows, total


def fetch_customer_by_id(custid: int):
    """Return a single customer row or None."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    table = get_customer_table_name()
    cur.execute(
    f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM {table}
    WHERE CUSTID = %s
    """,
    (custid,),
    )
    row = cur.fetchone()
    cur.close()
    return row


def fetch_customer_by_email(email: str):
    """Return a single customer row matched by email (case-insensitive)."""
    if not email:
        return None
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    table = get_customer_table_name()
    cur.execute(
    f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM {table}
    WHERE LOWER(EMAIL) = LOWER(%s)
    LIMIT 1
    """,
    (email,),
    )
    row = cur.fetchone()
    cur.close()
    return row


def create_customer(
    *,
    email: str,
    firstname: str | None = None,
    lastname: str | None = None,
    company: str | None = None,
    phone: str | None = None,
    comments: str | None = None,
    is_subscribed: bool = True,
) -> dict[str, int | str]:
    """Insert a single subscriber and return metadata."""
    token = secrets.token_hex(32)
    conn = get_connection()
    cur = conn.cursor()
    custid = None
    table = get_customer_table_name()
    try:
        cur.execute(
        f"""
        SELECT 1
        FROM {table}
        WHERE LOWER(EMAIL) = LOWER(%s)
        LIMIT 1
        """,
        (email,),
        )
        if cur.fetchone():
            raise DuplicateCustomerError("Customer already exists.")

        cur.execute(
        f"""
        INSERT INTO {table}
        (FIRSTNAME, LASTNAME, EMAIL, COMPANY, PHONE, COMMENTS, IS_SUBSCRIBED, UNSUBSCRIBE_TOKEN)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
        _blank_to_empty(firstname),
        _blank_to_empty(lastname),
        email,
        _blank_to_empty(company),
        _blank_to_empty(phone),
        _blank_to_empty(comments),
        "1" if is_subscribed else "0",
        token,
        ),
        )
        custid = cur.lastrowid
    except pymysql.MySQLError as exc:
        if getattr(exc, "errno", None) == ER.DUP_ENTRY:
            raise DuplicateCustomerError("Customer already exists.") from exc
        raise
    finally:
        cur.close()
    return {"custid": custid, "unsubscribe_token": token}


def update_customer(
    custid: int,
    *,
    email: str,
    firstname: str | None = None,
    lastname: str | None = None,
    company: str | None = None,
    phone: str | None = None,
    comments: str | None = None,
    is_subscribed: bool = True,
):
    """Update customer fields or raise errors."""
    conn = get_connection()
    cur = conn.cursor()
    table = get_customer_table_name()
    try:
        cur.execute(
        f"""
        SELECT 1
        FROM {table}
        WHERE CUSTID = %s
        """,
        (custid,),
        )
        if not cur.fetchone():
            raise CustomerNotFoundError(f"CUSTID {custid} not found.")

        cur.execute(
        f"""
        SELECT 1
        FROM {table}
        WHERE LOWER(EMAIL) = LOWER(%s) AND CUSTID <> %s
        LIMIT 1
        """,
        (email, custid),
        )
        if cur.fetchone():
            raise DuplicateCustomerError("Customer already exists.")

        cur.execute(
        f"""
        UPDATE {table}
        SET
            FIRSTNAME = %s,
            LASTNAME = %s,
            EMAIL = %s,
            COMPANY = %s,
            PHONE = %s,
            COMMENTS = %s,
            IS_SUBSCRIBED = %s
        WHERE CUSTID = %s
        """,
        (
        _blank_to_empty(firstname),
        _blank_to_empty(lastname),
        email,
        _blank_to_empty(company),
        _blank_to_empty(phone),
        _blank_to_empty(comments),
        "1" if is_subscribed else "0",
        custid,
        ),
        )
        if cur.rowcount == 0:
            raise CustomerNotFoundError(f"CUSTID {custid} not found.")
    except pymysql.MySQLError as exc:
        if getattr(exc, "errno", None) == ER.DUP_ENTRY:
            raise DuplicateCustomerError("Customer already exists.") from exc
        raise
    finally:
        cur.close()


def delete_customer(custid: int):
    """Hard-delete a customer row."""
    conn = get_connection()
    cur = conn.cursor()
    table = get_customer_table_name()
    try:
        cur.execute(
        f"""
        DELETE FROM {table}
        WHERE CUSTID = %s
        """,
        (custid,),
        )
        if cur.rowcount == 0:
            raise CustomerNotFoundError(f"CUSTID {custid} not found.")
    finally:
        cur.close()


def ensure_unsubscribe_token(custid: int, token: str | None = None) -> str:
    """Guarantee a subscriber row has an unsubscribe token and return it."""
    token_value = (token or "").strip()
    if token_value:
        return token_value

    conn = get_connection()
    cur = conn.cursor(DictCursor)
    table = get_customer_table_name()
    try:
        new_token = secrets.token_hex(32)
        cur.execute(
        f"""
        UPDATE {table}
        SET UNSUBSCRIBE_TOKEN = %s
        WHERE CUSTID = %s AND (
            UNSUBSCRIBE_TOKEN IS NULL OR CHAR_LENGTH(TRIM(UNSUBSCRIBE_TOKEN)) = 0
        )
        """,
        (new_token, custid),
        )
        if cur.rowcount:
            return new_token

        cur.execute(
        f"""
        SELECT UNSUBSCRIBE_TOKEN
        FROM {table}
        WHERE CUSTID = %s
        """,
        (custid,),
        )
        row = cur.fetchone()
        if not row:
            raise CustomerNotFoundError(f"CUSTID {custid} not found.")

        existing = (row.get("UNSUBSCRIBE_TOKEN") or "").strip()
        if existing:
            return existing
        raise RuntimeError(f"Unable to ensure unsubscribe token for CUSTID {custid}.")
    finally:
        cur.close()


def fetch_user_by_username(username: str):
    """Return a single service user row for authentication."""
    if not username:
        return None
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute(
        """
        SELECT
            id,
            username,
            password_hash,
            password_algo,
            role,
            is_active,
            force_password_reset,
            failed_login_count,
            locked_until,
            last_login_at
        FROM service_users
        WHERE LOWER(username) = LOWER(%s)
        LIMIT 1
        """,
        (username,),
        )
        return cur.fetchone()
    finally:
        cur.close()


def fetch_user_by_id(user_id: int):
    """Look up a service user by id."""
    if not user_id:
        return None
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute(
        """
        SELECT
            id,
            username,
            role,
            is_active,
            force_password_reset,
            failed_login_count,
            locked_until,
            last_login_at
        FROM service_users
        WHERE id = %s
        LIMIT 1
        """,
        (user_id,),
        )
        return cur.fetchone()
    finally:
        cur.close()


def record_successful_login(user_id: int):
    """Reset lockout counters on successful authentication."""
    if not user_id:
        return
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE service_users
        SET
            failed_login_count = 0,
            locked_until = NULL,
            last_login_at = UTC_TIMESTAMP()
        WHERE id = %s
        """,
        (user_id,),
        )
    finally:
        cur.close()


def update_failed_login(user_id: int, *, failed_login_count: int, locked_until: datetime | None):
    """Persist a failed-login attempt counter and optional lockout timestamp."""
    if not user_id:
        return
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE service_users
        SET
            failed_login_count = %s,
            locked_until = %s
        WHERE id = %s
        """,
        (failed_login_count, locked_until, user_id),
        )
    finally:
        cur.close()


def create_service_user(
    *,
    email: str,
    password_hash: str,
    role: str = "admin",
    password_algo: str = "pbkdf2_sha256",
    is_active: bool = True,
) -> int:
    """Insert a new operator account."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        INSERT INTO service_users
            (username, password_hash, password_algo, role, is_active)
        VALUES
            (%s, %s, %s, %s, %s)
        """,
        (email, password_hash, password_algo, role, 1 if is_active else 0),
        )
        return cur.lastrowid or 0
    except pymysql.MySQLError as exc:
        if getattr(exc, "errno", None) == ER.DUP_ENTRY:
            raise ServiceUserAlreadyExists("User already exists.") from exc
        raise
    finally:
        cur.close()


def list_service_users():
    """Return all service users (safe columns only)."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute(
        """
        SELECT
            id,
            username,
            role,
            is_active,
            last_login_at
        FROM service_users
        ORDER BY username ASC
        """,
        )
        return cur.fetchall()
    finally:
        cur.close()


def update_service_user_password(
    user_id: int,
    *,
    password_hash: str,
    password_algo: str = "pbkdf2_sha256",
):
    """Update the password for a service user and clear force-reset flag."""
    if not user_id:
        return
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE service_users
        SET
            password_hash = %s,
            password_algo = %s,
            force_password_reset = 0
        WHERE id = %s
        """,
        (password_hash, password_algo, user_id),
        )
    finally:
        cur.close()


# ── Campaign history ─────────────────────────────────────────────


def ensure_campaign_tables():
    """Create CAMPAIGN_SENDS and CAMPAIGN_SEND_RESULTS if they do not exist,
    and apply incremental migrations for the scheduler-based queue architecture.
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS CAMPAIGN_SENDS (
            SEND_ID          VARCHAR(32)  NOT NULL PRIMARY KEY,
            CAMPAIGN_FILE    VARCHAR(255) NOT NULL,
            SUBJECT          VARCHAR(500) NULL,
            MODE             VARCHAR(20)  NOT NULL,
            TOTAL_RECIPIENTS INT          NOT NULL DEFAULT 0,
            SENT_COUNT       INT          NOT NULL DEFAULT 0,
            FAILED_COUNT     INT          NOT NULL DEFAULT 0,
            STATUS           VARCHAR(20)  NOT NULL DEFAULT 'queued',
            QUEUED_AT        DATETIME     NULL,
            STARTED_AT       DATETIME     NULL,
            FINISHED_AT      DATETIME     NULL,
            LAST_BATCH_AT    DATETIME     NULL,
            BATCH_SIZE       INT          NULL,
            DELAY_MS         INT          NULL,
            COOLDOWN_SECONDS INT          NULL,
            CLAIMED_BY       VARCHAR(64)  NULL,
            CLAIMED_AT       DATETIME     NULL
        )
        """)
        _migrate_columns = [
            ("BATCH_SIZE", "INT NULL"),
            ("DELAY_MS", "INT NULL"),
            ("COOLDOWN_SECONDS", "INT NULL"),
            ("LAST_BATCH_AT", "DATETIME NULL"),
            ("CLAIMED_BY", "VARCHAR(64) NULL"),
            ("CLAIMED_AT", "DATETIME NULL"),
            ("QUEUED_AT", "DATETIME NULL"),
        ]
        for col, col_type in _migrate_columns:
            try:
                cur.execute(
                    f"ALTER TABLE CAMPAIGN_SENDS ADD COLUMN {col} {col_type}"
                )
            except pymysql.MySQLError as exc:
                if getattr(exc, "errno", None) != ER.DUP_FIELDNAME:
                    raise
        cur.execute("""
        CREATE TABLE IF NOT EXISTS CAMPAIGN_SEND_RESULTS (
            ID            BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
            SEND_ID       VARCHAR(32)  NOT NULL,
            CUSTID        INT          NULL,
            EMAIL         VARCHAR(320) NOT NULL,
            FIRSTNAME     VARCHAR(255) NULL,
            LASTNAME      VARCHAR(255) NULL,
            STATUS        VARCHAR(20)  NOT NULL DEFAULT 'pending',
            ERROR_MESSAGE TEXT         NULL,
            ATTEMPTED_AT  DATETIME     NULL,
            INDEX idx_send_id (SEND_ID),
            INDEX idx_send_status (SEND_ID, STATUS)
        )
        """)
        _result_migrations = [
            ("CUSTID", "INT NULL"),
        ]
        for col, col_type in _result_migrations:
            try:
                cur.execute(
                    f"ALTER TABLE CAMPAIGN_SEND_RESULTS ADD COLUMN {col} {col_type}"
                )
            except pymysql.MySQLError as exc:
                if getattr(exc, "errno", None) != ER.DUP_FIELDNAME:
                    raise
        # Rename SENT_AT -> ATTEMPTED_AT if the old column exists
        try:
            cur.execute(
                "ALTER TABLE CAMPAIGN_SEND_RESULTS CHANGE COLUMN SENT_AT ATTEMPTED_AT DATETIME NULL"
            )
        except pymysql.MySQLError:
            pass
        # Add composite index if missing
        try:
            cur.execute(
                "ALTER TABLE CAMPAIGN_SEND_RESULTS ADD INDEX idx_send_status (SEND_ID, STATUS)"
            )
        except pymysql.MySQLError:
            pass
    finally:
        cur.close()


def insert_campaign_send(
    send_id: str,
    campaign_file: str,
    subject: str | None,
    mode: str,
    total_recipients: int,
    *,
    batch_size: int | None = None,
    delay_ms: int | None = None,
    cooldown_seconds: int | None = None,
):
    """Create the initial CAMPAIGN_SENDS row when a campaign is queued."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        INSERT INTO CAMPAIGN_SENDS
            (SEND_ID, CAMPAIGN_FILE, SUBJECT, MODE, TOTAL_RECIPIENTS,
             STATUS, QUEUED_AT, BATCH_SIZE, DELAY_MS, COOLDOWN_SECONDS)
        VALUES
            (%s, %s, %s, %s, %s, 'queued', UTC_TIMESTAMP(), %s, %s, %s)
        """,
        (send_id, campaign_file, subject, mode, total_recipients,
         batch_size, delay_ms, cooldown_seconds),
        )
    finally:
        cur.close()


def activate_campaign_send(send_id: str):
    """Transition a queued send to running after recipients are populated."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SENDS
        SET STATUS = 'running', STARTED_AT = UTC_TIMESTAMP()
        WHERE SEND_ID = %s AND STATUS = 'queued'
        """,
        (send_id,),
        )
    finally:
        cur.close()


def bulk_insert_send_recipients(send_id: str, customer_rows: list[dict]):
    """Bulk-insert all recipients as 'pending' for a given send."""
    if not customer_rows:
        return
    conn = get_connection()
    cur = conn.cursor()
    try:
        values = []
        for r in customer_rows:
            values.append((
                send_id,
                r.get("CUSTID"),
                r.get("EMAIL", "").strip(),
                r.get("FIRSTNAME"),
                r.get("LASTNAME"),
            ))
        cur.executemany(
        """
        INSERT INTO CAMPAIGN_SEND_RESULTS
            (SEND_ID, CUSTID, EMAIL, FIRSTNAME, LASTNAME, STATUS)
        VALUES
            (%s, %s, %s, %s, %s, 'pending')
        """,
        values,
        )
    finally:
        cur.close()


def insert_send_result(
    send_id: str,
    email: str,
    firstname: str | None,
    lastname: str | None,
    status: str,
    error_message: str | None = None,
):
    """Record the outcome of a single recipient email attempt (legacy path)."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        INSERT INTO CAMPAIGN_SEND_RESULTS
            (SEND_ID, EMAIL, FIRSTNAME, LASTNAME, STATUS, ERROR_MESSAGE, ATTEMPTED_AT)
        VALUES
            (%s, %s, %s, %s, %s, %s, UTC_TIMESTAMP())
        """,
        (send_id, email, firstname, lastname, status, error_message),
        )
    finally:
        cur.close()


def fetch_pending_recipients(send_id: str, limit: int = 25) -> list[dict]:
    """Fetch the next batch of pending recipients for a send."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute(
        """
        SELECT ID, SEND_ID, CUSTID, EMAIL, FIRSTNAME, LASTNAME
        FROM CAMPAIGN_SEND_RESULTS
        WHERE SEND_ID = %s AND STATUS = 'pending'
        ORDER BY ID ASC
        LIMIT %s
        """,
        (send_id, limit),
        )
        return cur.fetchall()
    finally:
        cur.close()


def mark_recipient_sent(result_id: int):
    """Mark a single queued recipient as successfully sent."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SEND_RESULTS
        SET STATUS = 'sent', ATTEMPTED_AT = UTC_TIMESTAMP()
        WHERE ID = %s
        """,
        (result_id,),
        )
    finally:
        cur.close()


def mark_recipient_failed(result_id: int, error_message: str | None = None):
    """Mark a single queued recipient as failed."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SEND_RESULTS
        SET STATUS = 'failed', ERROR_MESSAGE = %s, ATTEMPTED_AT = UTC_TIMESTAMP()
        WHERE ID = %s
        """,
        (error_message, result_id),
        )
    finally:
        cur.close()


def update_send_progress(send_id: str, sent_count: int, failed_count: int):
    """Increment SENT_COUNT/FAILED_COUNT and set LAST_BATCH_AT after each batch."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SENDS
        SET SENT_COUNT = %s,
            FAILED_COUNT = %s,
            LAST_BATCH_AT = UTC_TIMESTAMP()
        WHERE SEND_ID = %s
        """,
        (sent_count, failed_count, send_id),
        )
    finally:
        cur.close()


def update_campaign_send_finished(
    send_id: str,
    status: str,
    sent_count: int,
    failed_count: int,
):
    """Mark a campaign send as completed, failed, or cancelled."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SENDS
        SET STATUS = %s,
            SENT_COUNT = %s,
            FAILED_COUNT = %s,
            FINISHED_AT = UTC_TIMESTAMP()
        WHERE SEND_ID = %s
        """,
        (status, sent_count, failed_count, send_id),
        )
    finally:
        cur.close()


def get_send_status(send_id: str) -> dict | None:
    """Return status, counts, and control parameters for a send."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute(
        """
        SELECT SEND_ID, CAMPAIGN_FILE, SUBJECT, MODE,
               TOTAL_RECIPIENTS, SENT_COUNT, FAILED_COUNT, STATUS,
               QUEUED_AT, STARTED_AT, FINISHED_AT, LAST_BATCH_AT,
               BATCH_SIZE, DELAY_MS, COOLDOWN_SECONDS
        FROM CAMPAIGN_SENDS
        WHERE SEND_ID = %s
        """,
        (send_id,),
        )
        return cur.fetchone()
    finally:
        cur.close()


def update_send_controls(
    send_id: str,
    *,
    batch_size: int | None = None,
    delay_ms: int | None = None,
    cooldown_seconds: int | None = None,
):
    """Update mutable send parameters mid-flight."""
    updates = []
    params: list = []
    if batch_size is not None:
        updates.append("BATCH_SIZE = %s")
        params.append(batch_size)
    if delay_ms is not None:
        updates.append("DELAY_MS = %s")
        params.append(delay_ms)
    if cooldown_seconds is not None:
        updates.append("COOLDOWN_SECONDS = %s")
        params.append(cooldown_seconds)
    if not updates:
        return
    params.append(send_id)
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            f"UPDATE CAMPAIGN_SENDS SET {', '.join(updates)} WHERE SEND_ID = %s",
            params,
        )
    finally:
        cur.close()


def pause_send(send_id: str) -> bool:
    """Pause a running send. Returns True if the status was changed."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SENDS
        SET STATUS = 'paused'
        WHERE SEND_ID = %s AND STATUS = 'running'
        """,
        (send_id,),
        )
        return cur.rowcount > 0
    finally:
        cur.close()


def resume_send(send_id: str) -> bool:
    """Resume a paused send. Returns True if the status was changed."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SENDS
        SET STATUS = 'running'
        WHERE SEND_ID = %s AND STATUS = 'paused'
        """,
        (send_id,),
        )
        return cur.rowcount > 0
    finally:
        cur.close()


def cancel_send(send_id: str) -> bool:
    """Cancel a running or paused send. Returns True if the status was changed."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SENDS
        SET STATUS = 'cancelled', FINISHED_AT = UTC_TIMESTAMP()
        WHERE SEND_ID = %s AND STATUS IN ('running', 'paused', 'queued')
        """,
        (send_id,),
        )
        return cur.rowcount > 0
    finally:
        cur.close()


def fetch_ready_sends() -> list[dict]:
    """Find running sends whose cooldown has elapsed (scheduler query)."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute(
        """
        SELECT *
        FROM CAMPAIGN_SENDS
        WHERE STATUS = 'running'
          AND (LAST_BATCH_AT IS NULL
               OR TIMESTAMPDIFF(SECOND, LAST_BATCH_AT, UTC_TIMESTAMP())
                  >= COALESCE(COOLDOWN_SECONDS, 0))
        ORDER BY STARTED_AT ASC
        """
        )
        return cur.fetchall()
    finally:
        cur.close()


def claim_send(send_id: str, worker_id: str) -> bool:
    """Atomically claim a send for this worker. Returns True if claimed."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SENDS
        SET CLAIMED_BY = %s, CLAIMED_AT = UTC_TIMESTAMP()
        WHERE SEND_ID = %s
          AND STATUS = 'running'
          AND (CLAIMED_BY IS NULL
               OR CLAIMED_BY = %s
               OR TIMESTAMPDIFF(SECOND, CLAIMED_AT, UTC_TIMESTAMP()) > %s)
        """,
        (worker_id, send_id, worker_id, CLAIM_STALE_SECONDS),
        )
        return cur.rowcount > 0
    finally:
        cur.close()


def release_claim(send_id: str):
    """Clear the claim on a send after batch processing."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        UPDATE CAMPAIGN_SENDS
        SET CLAIMED_BY = NULL, CLAIMED_AT = NULL
        WHERE SEND_ID = %s
        """,
        (send_id,),
        )
    finally:
        cur.close()


def fetch_send_recipients_paginated(
    send_id: str,
    *,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Return a page of recipients for a send with total count."""
    conn = get_connection()
    normalized_limit = max(1, int(limit))
    normalized_offset = max(0, int(offset))

    where = "WHERE SEND_ID = %s"
    params: list = [send_id]
    if status_filter:
        where += " AND STATUS = %s"
        params.append(status_filter)

    count_cur = conn.cursor()
    try:
        count_cur.execute(
            f"SELECT COUNT(*) FROM CAMPAIGN_SEND_RESULTS {where}", params
        )
        total = int(count_cur.fetchone()[0])
    finally:
        count_cur.close()

    data_cur = conn.cursor(DictCursor)
    try:
        data_cur.execute(
            f"""
            SELECT ID, CUSTID, EMAIL, FIRSTNAME, LASTNAME,
                   STATUS, ERROR_MESSAGE, ATTEMPTED_AT
            FROM CAMPAIGN_SEND_RESULTS
            {where}
            ORDER BY ID ASC
            LIMIT %s OFFSET %s
            """,
            params + [normalized_limit, normalized_offset],
        )
        rows = data_cur.fetchall()
    finally:
        data_cur.close()

    return rows, total


def fetch_campaign_history(mode_filter: str | None = None):
    """Return all campaign sends ordered by most recent first."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        if mode_filter:
            cur.execute(
            """
            SELECT * FROM CAMPAIGN_SENDS
            WHERE MODE = %s
            ORDER BY STARTED_AT DESC
            """,
            (mode_filter,),
            )
        else:
            cur.execute(
            """
            SELECT * FROM CAMPAIGN_SENDS
            ORDER BY STARTED_AT DESC
            """,
            )
        return cur.fetchall()
    finally:
        cur.close()


def fetch_campaign_detail(send_id: str):
    """Return the campaign send row and all per-recipient results."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute(
        "SELECT * FROM CAMPAIGN_SENDS WHERE SEND_ID = %s",
        (send_id,),
        )
        send_row = cur.fetchone()
        if not send_row:
            return None, []
        cur.execute(
        """
        SELECT * FROM CAMPAIGN_SEND_RESULTS
        WHERE SEND_ID = %s
        ORDER BY ID ASC
        """,
        (send_id,),
        )
        results = cur.fetchall()
        return send_row, results
    finally:
        cur.close()


def fetch_sent_emails_for_send(send_id: str) -> set[str]:
    """Return the set of email addresses already successfully sent for a given send."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        SELECT EMAIL FROM CAMPAIGN_SEND_RESULTS
        WHERE SEND_ID = %s AND STATUS = 'sent'
        """,
        (send_id,),
        )
        return {row[0] for row in cur.fetchall()}
    finally:
        cur.close()


def count_send_results(send_id: str) -> dict[str, int]:
    """Return counts of pending/sent/failed recipients for a send."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        SELECT STATUS, COUNT(*) AS cnt
        FROM CAMPAIGN_SEND_RESULTS
        WHERE SEND_ID = %s
        GROUP BY STATUS
        """,
        (send_id,),
        )
        result = {"pending": 0, "sent": 0, "failed": 0}
        for row in cur.fetchall():
            result[row[0]] = int(row[1])
        return result
    finally:
        cur.close()


def fetch_active_send() -> dict | None:
    """Return the currently running send, if any."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute(
        """
        SELECT SEND_ID, CAMPAIGN_FILE, SUBJECT, STATUS,
               TOTAL_RECIPIENTS, SENT_COUNT, FAILED_COUNT
        FROM CAMPAIGN_SENDS
        WHERE STATUS IN ('queued', 'running')
        ORDER BY STARTED_AT DESC
        LIMIT 1
        """
        )
        return cur.fetchone()
    finally:
        cur.close()
