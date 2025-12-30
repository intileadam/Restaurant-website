from __future__ import annotations
import os, pathlib, re
from flask import Flask, request, render_template
from dotenv import load_dotenv
import pymysql

BASE_DIR = pathlib.Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
app = Flask(__name__)
_TABLE_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")


def _sanitize_table(name: str, fallback: str) -> str:
    candidate = (name or "").strip()
    if not candidate or not _TABLE_PATTERN.match(candidate):
        return fallback
    return candidate


PRODUCTION_TABLE = _sanitize_table(os.getenv("DB_CUSTOMER_TABLE", "CUSTOMERS"), "CUSTOMERS")
TEST_TABLE = _sanitize_table(os.getenv("DB_TEST_CUSTOMER_TABLE", "TESTCUSTOMERS"), "TESTCUSTOMERS")


# Reuse same DB creds; deploy separately on casadelpollo.com (gunicorn/uwsgi + nginx)


def get_conn():
    return pymysql.connect(
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    database=os.getenv("DB_NAME"),
    autocommit=True,
    )

def _table_for_request():
    mode = (request.args.get("mode") or "").strip().lower()
    return TEST_TABLE if mode == "test" else PRODUCTION_TABLE


@app.get("/unsubscribe")
def unsubscribe():
    token = request.args.get("token", "").strip()
    if not token:
        return render_template("error.html", message="Missing token."), 400
    try:
        conn = get_conn()
        cur = conn.cursor()
        table = _table_for_request()
        cur.execute(f"UPDATE {table} SET IS_SUBSCRIBED = 0 WHERE UNSUBSCRIBE_TOKEN = %s", (token,))
        if cur.rowcount == 0:
            return render_template("error.html", message="Invalid or already processed token."), 404
        return render_template("unsubscribed.html")
    except Exception as e:
        return render_template("error.html", message=str(e)), 500


@app.get("/resubscribe")
def resubscribe():
    token = request.args.get("token", "").strip()
    if not token:
        return render_template("error.html", message="Missing token."), 400
    try:
        conn = get_conn()
        cur = conn.cursor()
        table = _table_for_request()
        cur.execute(f"UPDATE {table} SET IS_SUBSCRIBED = 1 WHERE UNSUBSCRIBE_TOKEN = %s", (token,))
        if cur.rowcount == 0:
            return render_template("error.html", message="Invalid token."), 404
        return render_template("unsubscribed.html", rejoined=True)
    except Exception as e:
        return render_template("error.html", message=str(e)), 500
    
@app.get('/healthz')
def healthz():
    return 'ok', 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
