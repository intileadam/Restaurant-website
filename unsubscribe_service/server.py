from __future__ import annotations
import os
from flask import Flask, request, render_template
from dotenv import load_dotenv
import mysql.connector as mysql


load_dotenv()
app = Flask(__name__)


# Reuse same DB creds; deploy separately on casadelpollo.com (gunicorn/uwsgi + nginx)


def get_conn():
    return mysql.connect(
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    database=os.getenv("DB_NAME"),
    autocommit=True,
    )


@app.get("/unsubscribe")
def unsubscribe():
    token = request.args.get("token", "").strip()
    if not token:
        return render_template("error.html", message="Missing token."), 400
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE TESTCUSTOMERS SET IS_SUBSCRIBED = 0 WHERE UNSUBSCRIBE_TOKEN = %s", (token,))
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
        cur.execute("UPDATE TESTCUSTOMERS SET IS_SUBSCRIBED = 1 WHERE UNSUBSCRIBE_TOKEN = %s", (token,))
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