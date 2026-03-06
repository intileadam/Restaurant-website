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



def _normalize_tag_name(name: str) -> str:
    """Trim and lowercase for case-insensitive uniqueness."""
    return (name or "").strip().lower()


def fetch_subscribed_customers(tag_names: list[str] | None = None):
    """Returns basic fields needed for sending.
    When tag_names is None or empty: all subscribed customers (respects IS_SUBSCRIBED).
    When tag_names is non-empty: only subscribed customers that have at least one of
    the given tags (OR semantics); each customer appears once (distinct).
    """
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    table = get_customer_table_name()
    if not tag_names:
        cur.execute(
            f"""
            SELECT CUSTID, FIRSTNAME, LASTNAME, EMAIL, UNSUBSCRIBE_TOKEN
            FROM {table}
            WHERE IS_SUBSCRIBED = 1 AND EMAIL IS NOT NULL AND EMAIL <> ''
            """
        )
        rows = cur.fetchall()
    else:
        normalized = [_normalize_tag_name(n) for n in tag_names if _normalize_tag_name(n)]
        if not normalized:
            cur.execute(
                f"""
                SELECT CUSTID, FIRSTNAME, LASTNAME, EMAIL, UNSUBSCRIBE_TOKEN
                FROM {table}
                WHERE IS_SUBSCRIBED = 1 AND EMAIL IS NOT NULL AND EMAIL <> ''
                """
            )
            rows = cur.fetchall()
        else:
            placeholders = ", ".join(["%s"] * len(normalized))
            cur.execute(
                f"""
                SELECT DISTINCT c.CUSTID, c.FIRSTNAME, c.LASTNAME, c.EMAIL, c.UNSUBSCRIBE_TOKEN
                FROM {table} c
                INNER JOIN customer_tags ct ON ct.customer_table = %s AND ct.custid = c.CUSTID
                INNER JOIN tags t ON t.id = ct.tag_id AND t.name IN ({placeholders})
                WHERE c.IS_SUBSCRIBED = 1 AND c.EMAIL IS NOT NULL AND c.EMAIL <> ''
                """,
                [table] + normalized,
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


def fetch_customers_paginated(
    *,
    search: str | None = None,
    tag_ids: list[int] | None = None,
    limit: int = 50,
    offset: int = 0,
):
    """Return a page of customers along with the total count.
    When tag_ids is non-empty, only customers that have ALL of those tags are returned.
    Each row is enriched with a 'tags' key: list of {id, name}.
    """
    conn = get_connection()
    normalized_limit = max(1, int(limit))
    normalized_offset = max(0, int(offset))
    table = get_customer_table_name()

    search_params: list[str] = []
    tag_filter_sql = ""
    tag_filter_params: list[str] = []
    if tag_ids:
        tag_ids = [int(x) for x in tag_ids if x]
        if tag_ids:
            placeholders = ", ".join(["%s"] * len(tag_ids))
            tag_filter_sql = f"""
            AND c.CUSTID IN (
                SELECT ct.custid
                FROM customer_tags ct
                WHERE ct.customer_table = %s AND ct.tag_id IN ({placeholders})
                GROUP BY ct.custid
                HAVING COUNT(DISTINCT ct.tag_id) = %s
            )
            """
            tag_filter_params = [table] + tag_ids + [len(tag_ids)]

    use_alias = bool(tag_filter_sql)

    if search:
        term = search.strip().lower()
        if term:
            like = f"%{term}%"
            if use_alias:
                search_where = """
        WHERE (
            LOWER(c.FIRSTNAME) LIKE %s OR
            LOWER(c.LASTNAME) LIKE %s OR
            LOWER(c.EMAIL) LIKE %s OR
            LOWER(c.COMPANY) LIKE %s OR
            LOWER(c.PHONE) LIKE %s OR
            LOWER(c.COMMENTS) LIKE %s
        )
            """ + tag_filter_sql
            else:
                search_where = """
        WHERE
            LOWER(FIRSTNAME) LIKE %s OR
            LOWER(LASTNAME) LIKE %s OR
            LOWER(EMAIL) LIKE %s OR
            LOWER(COMPANY) LIKE %s OR
            LOWER(PHONE) LIKE %s OR
            LOWER(COMMENTS) LIKE %s
        """
            search_params = [like] * 6
    else:
        if use_alias:
            search_where = "WHERE 1=1 " + tag_filter_sql
        else:
            search_where = ""

    all_params = search_params + tag_filter_params

    if use_alias:
        count_sql = f"SELECT COUNT(*) AS total FROM {table} c {search_where}"
        field_set = ", ".join(
            f"c.{f.strip()}" for f in _CUSTOMER_FIELD_SET.split(",") if f.strip()
        )
        data_sql = f"""
    SELECT {field_set}
    FROM {table} c
    {search_where}
    ORDER BY c.CUSTID DESC
    LIMIT %s OFFSET %s
    """
    else:
        count_sql = f"SELECT COUNT(*) AS total FROM {table} {search_where}"
        data_sql = f"""
    SELECT {_CUSTOMER_FIELD_SET}
    FROM {table}
    {search_where}
    ORDER BY CUSTID DESC
    LIMIT %s OFFSET %s
    """

    count_cur = conn.cursor()
    count_cur.execute(count_sql, all_params)
    count_row = count_cur.fetchone()
    total = int(count_row[0]) if count_row else 0
    count_cur.close()

    params = list(all_params)
    params.extend([normalized_limit, normalized_offset])
    data_cur = conn.cursor(DictCursor)
    data_cur.execute(data_sql, params)
    rows = data_cur.fetchall()
    data_cur.close()

    # Attach tags to each row
    if rows:
        custids = [r["CUSTID"] for r in rows]
        tags_by_cust = fetch_tags_for_customers(table, custids)
        for r in rows:
            r["tags"] = tags_by_cust.get(r["CUSTID"], [])

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
    """Hard-delete a customer row and their tag assignments."""
    conn = get_connection()
    cur = conn.cursor()
    table = get_customer_table_name()
    try:
        cur.execute(
            "DELETE FROM customer_tags WHERE customer_table = %s AND custid = %s",
            (table, custid),
        )
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


# --- Tags and customer_tags ---


def list_tags(*, include_count: bool = False) -> list[dict]:
    """Return all tags (id, name). When include_count=True, add customer_count per tag (current table only)."""
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        if include_count:
            table = get_customer_table_name()
            cur.execute(
                """
                SELECT t.id, t.name,
                    (SELECT COUNT(DISTINCT ct.custid)
                     FROM customer_tags ct
                     WHERE ct.tag_id = t.id AND ct.customer_table = %s) AS customer_count
                FROM tags t
                ORDER BY t.name
                """,
                (table,),
            )
        else:
            cur.execute(
                """
                SELECT id, name
                FROM tags
                ORDER BY name
                """
            )
        return cur.fetchall()
    finally:
        cur.close()


def get_or_create_tag(name: str) -> int:
    """Return tag id for the given name; create tag if missing. Name is normalized (trim, lowercase)."""
    canonical = _normalize_tag_name(name)
    if not canonical:
        raise ValueError("Tag name cannot be empty.")
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute("SELECT id FROM tags WHERE name = %s LIMIT 1", (canonical,))
        row = cur.fetchone()
        if row:
            return int(row["id"])
        cur.execute("INSERT INTO tags (name) VALUES (%s)", (canonical,))
        return cur.lastrowid or 0
    except pymysql.MySQLError as exc:
        if getattr(exc, "errno", None) == ER.DUP_ENTRY:
            cur.execute("SELECT id FROM tags WHERE name = %s LIMIT 1", (canonical,))
            row = cur.fetchone()
            if row:
                return int(row["id"])
        raise
    finally:
        cur.close()


def delete_tag(tag_id: int) -> None:
    """Remove a tag and all its customer assignments (CASCADE)."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM tags WHERE id = %s", (tag_id,))
    finally:
        cur.close()


def set_customer_tags(
    customer_table: str,
    custid: int,
    tag_ids_or_names: list[int | str],
) -> None:
    """Replace tags for one customer. Items can be tag ids (int) or tag names (str)."""
    table = _normalize_table(customer_table)
    tag_ids: list[int] = []
    conn = get_connection()
    cur = conn.cursor()
    try:
        for x in tag_ids_or_names:
            if isinstance(x, int):
                tag_ids.append(x)
            else:
                name = _normalize_tag_name(str(x))
                if name:
                    tid = get_or_create_tag(name)
                    tag_ids.append(tid)
        cur.execute(
            "DELETE FROM customer_tags WHERE customer_table = %s AND custid = %s",
            (table, custid),
        )
        for tag_id in tag_ids:
            cur.execute(
                """
                INSERT IGNORE INTO customer_tags (customer_table, custid, tag_id)
                VALUES (%s, %s, %s)
                """,
                (table, custid, tag_id),
            )
    finally:
        cur.close()


def get_customer_tag_ids(customer_table: str, custid: int) -> list[int]:
    """Return list of tag ids for a customer."""
    table = _normalize_table(customer_table)
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT tag_id
            FROM customer_tags
            WHERE customer_table = %s AND custid = %s
            ORDER BY tag_id
            """,
            (table, custid),
        )
        return [row[0] for row in cur.fetchall()]
    finally:
        cur.close()


def get_customer_tags(customer_table: str, custid: int) -> list[dict]:
    """Return list of {id, name} for a customer's tags."""
    table = _normalize_table(customer_table)
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        cur.execute(
            """
            SELECT t.id, t.name
            FROM customer_tags ct
            JOIN tags t ON t.id = ct.tag_id
            WHERE ct.customer_table = %s AND ct.custid = %s
            ORDER BY t.name
            """,
            (table, custid),
        )
        return cur.fetchall()
    finally:
        cur.close()


def fetch_tags_for_customers(
    customer_table: str,
    custids: list[int],
) -> dict[int, list[dict]]:
    """Return dict custid -> list of {id, name} for tags. Empty list if no tags."""
    if not custids:
        return {}
    table = _normalize_table(customer_table)
    conn = get_connection()
    cur = conn.cursor(DictCursor)
    try:
        placeholders = ", ".join(["%s"] * len(custids))
        cur.execute(
            f"""
            SELECT ct.custid, t.id, t.name
            FROM customer_tags ct
            JOIN tags t ON t.id = ct.tag_id
            WHERE ct.customer_table = %s AND ct.custid IN ({placeholders})
            ORDER BY ct.custid, t.name
            """,
            [table] + custids,
        )
        rows = cur.fetchall()
        result: dict[int, list[dict]] = {cid: [] for cid in custids}
        for r in rows:
            cid = r["custid"]
            result[cid].append({"id": r["id"], "name": r["name"]})
        return result
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


def list_service_users():
    """Return all service users (id, username, role, is_active, last_login_at) for admin UI."""
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
            ORDER BY username
            """
        )
        return cur.fetchall()
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


def update_user_password(user_id: int, *, password_hash: str, password_algo: str = "pbkdf2_sha256"):
    """Update a service user's password and clear force_password_reset."""
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
