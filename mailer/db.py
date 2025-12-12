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
    FROM TESTCUSTOMERS
    WHERE IS_SUBSCRIBED = 1 AND EMAIL IS NOT NULL AND EMAIL <> ''
    """
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def _blank_to_empty(value: str | None) -> str:
    """All optional columns are defined as NOT NULL in TESTCUSTOMERS."""
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
    FROM TESTCUSTOMERS
    ORDER BY CUSTID DESC
    """
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def fetch_customer_by_id(custid: int):
    """Return a single customer row or None."""
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute(
    f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM TESTCUSTOMERS
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
    FROM TESTCUSTOMERS
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
        FROM TESTCUSTOMERS
        WHERE LOWER(EMAIL) = LOWER(%s)
        LIMIT 1
        """,
        (email,),
        )
        if cur.fetchone():
            raise DuplicateCustomerError("Customer already exists.")

        cur.execute(
        """
        INSERT INTO TESTCUSTOMERS
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
        FROM TESTCUSTOMERS
        WHERE CUSTID = %s
        """,
        (custid,),
        )
        if not cur.fetchone():
            raise CustomerNotFoundError(f"CUSTID {custid} not found.")

        cur.execute(
        """
        SELECT 1
        FROM TESTCUSTOMERS
        WHERE LOWER(EMAIL) = LOWER(%s) AND CUSTID <> %s
        LIMIT 1
        """,
        (email, custid),
        )
        if cur.fetchone():
            raise DuplicateCustomerError("Customer already exists.")

        cur.execute(
        """
        UPDATE TESTCUSTOMERS
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
        DELETE FROM TESTCUSTOMERS
        WHERE CUSTID = %s
        """,
        (custid,),
        )
        if cur.rowcount == 0:
            raise CustomerNotFoundError(f"CUSTID {custid} not found.")
    finally:
        cur.close()
