"""MySQL connection helpers.
- Loads credentials from .env (via app.py at startup).
- Uses mysql-connector-python for portability.
"""
from __future__ import annotations
import os
import secrets
import threading
import mysql.connector as mysql
from mysql.connector import errorcode


_conn_pool = None
_conn_lock = threading.Lock()


def _connect():
    """Build a fresh MySQL connection from environment settings."""
    return mysql.connect(
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


def get_connection():
    global _conn_pool
    with _conn_lock:
        if _conn_pool is None:
            _conn_pool = _connect()
            return _conn_pool

        try:
            # Ensure the existing connection is alive; reconnect if it dropped.
            _conn_pool.ping(reconnect=True, attempts=3, delay=2)
        except mysql.Error:
            try:
                _conn_pool.close()
            except Exception:
                pass
            _conn_pool = _connect()
        return _conn_pool



def fetch_subscribed_customers():
    """Returns basic fields needed for sending.
    Keep this read-only in the campaign app; writes occur only in the unsubscribe service.
    """
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute(
    """
    SELECT CUSTID, FIRSTNAME, LASTNAME, EMAIL, UNSUBSCRIBE_TOKEN
    FROM CUSTOMERS
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
    cur = conn.cursor(dictionary=True)
    cur.execute(
    f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM CUSTOMERS
    ORDER BY CUSTID DESC
    """
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def fetch_customers_paginated(*, search: str | None = None, limit: int = 50, offset: int = 0):
    """Return a page of customers along with the total count."""
    conn = get_connection()
    normalized_limit = max(1, int(limit))
    normalized_offset = max(0, int(offset))

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

    count_sql = f"SELECT COUNT(*) AS total FROM CUSTOMERS {where_clause}"
    count_cur = conn.cursor()
    count_cur.execute(count_sql, search_params)
    count_row = count_cur.fetchone()
    total = int(count_row[0]) if count_row else 0
    count_cur.close()

    data_sql = f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM CUSTOMERS
    {where_clause}
    ORDER BY CUSTID DESC
    LIMIT %s OFFSET %s
    """
    params = list(search_params)
    params.extend([normalized_limit, normalized_offset])
    data_cur = conn.cursor(dictionary=True)
    data_cur.execute(data_sql, params)
    rows = data_cur.fetchall()
    data_cur.close()

    return rows, total


def fetch_customer_by_id(custid: int):
    """Return a single customer row or None."""
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute(
    f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM CUSTOMERS
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
    cur = conn.cursor(dictionary=True)
    cur.execute(
    f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM CUSTOMERS
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
    try:
        cur.execute(
        """
        SELECT 1
        FROM CUSTOMERS
        WHERE LOWER(EMAIL) = LOWER(%s)
        LIMIT 1
        """,
        (email,),
        )
        if cur.fetchone():
            raise DuplicateCustomerError("Customer already exists.")

        cur.execute(
        """
        INSERT INTO CUSTOMERS
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
    except mysql.Error as exc:
        if getattr(exc, "errno", None) == errorcode.ER_DUP_ENTRY:
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
    try:
        cur.execute(
        """
        SELECT 1
        FROM CUSTOMERS
        WHERE CUSTID = %s
        """,
        (custid,),
        )
        if not cur.fetchone():
            raise CustomerNotFoundError(f"CUSTID {custid} not found.")

        cur.execute(
        """
        SELECT 1
        FROM CUSTOMERS
        WHERE LOWER(EMAIL) = LOWER(%s) AND CUSTID <> %s
        LIMIT 1
        """,
        (email, custid),
        )
        if cur.fetchone():
            raise DuplicateCustomerError("Customer already exists.")

        cur.execute(
        """
        UPDATE CUSTOMERS
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
    except mysql.Error as exc:
        if getattr(exc, "errno", None) == errorcode.ER_DUP_ENTRY:
            raise DuplicateCustomerError("Customer already exists.") from exc
        raise
    finally:
        cur.close()


def delete_customer(custid: int):
    """Hard-delete a customer row."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
        """
        DELETE FROM CUSTOMERS
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
    cur = conn.cursor(dictionary=True)
    try:
        new_token = secrets.token_hex(32)
        cur.execute(
        """
        UPDATE CUSTOMERS
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
        """
        SELECT UNSUBSCRIBE_TOKEN
        FROM CUSTOMERS
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
