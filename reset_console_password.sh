#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="$SCRIPT_DIR"
APP_DIR="$REPO_DIR/apps/campaign_console"

if [ ! -f "$APP_DIR/app.py" ]; then
    echo "Expected $APP_DIR/app.py. Place this script in the repo root." >&2
    exit 1
fi

if [ -x "$REPO_DIR/.venv/bin/python" ]; then
    PYTHON="$REPO_DIR/.venv/bin/python"
else
    PYTHON="$(command -v python3 || true)"
fi

if [ -z "${PYTHON:-}" ]; then
    echo "python3 is required." >&2
    exit 1
fi

REPO_DIR="$REPO_DIR" "$PYTHON" - <<'PY'
import os
from pathlib import Path
from getpass import getpass
import sys

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
import pymysql

try:
    sys.stdin = open("/dev/tty")
except OSError:
    pass

repo = Path(os.environ["REPO_DIR"]).resolve()
app_dir = repo / "apps" / "campaign_console"
if not (app_dir / "app.py").exists():
    raise SystemExit("Run this from the repo root (Restaurant-website).")

load_dotenv(app_dir / ".env")

username = input("Username/email to reset: ").strip()
if not username:
    raise SystemExit("Username is required.")
password = getpass("New password: ")
if not password:
    raise SystemExit("Password is required.")

hashed = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

conn = pymysql.connect(
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    database=os.getenv("DB_NAME"),
    autocommit=True,
)
with conn.cursor() as cur:
    cur.execute(
        """
        UPDATE service_users
        SET password_hash=%s,
            password_algo=%s,
            force_password_reset=0,
            failed_login_count=0,
            locked_until=NULL
        WHERE LOWER(username)=LOWER(%s)
        LIMIT 1
        """,
        (hashed, "pbkdf2_sha256", username),
    )
    print(f"Updated {cur.rowcount} row(s).")
conn.close()
PY
