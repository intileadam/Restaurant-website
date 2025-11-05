"""MySQL connection helpers.
- Loads credentials from .env (via app.py at startup).
- Uses mysql-connector-python for portability.
"""
from __future__ import annotations
import os
import mysql.connector as mysql


_conn_pool = None


def get_connection():
    global _conn_pool
    if _conn_pool is None:
        _conn_pool = mysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        autocommit=True,
        )
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
    FROM TESTCUSTOMER
    WHERE IS_SUBSCRIBED = 1 AND EMAIL IS NOT NULL AND EMAIL <> ''
    """
    )
    rows = cur.fetchall()
    cur.close()
    return rows