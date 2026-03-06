from __future__ import annotations
import csv
import io
import json, math, os, pathlib, re, secrets, sys, threading, time as time_module
from datetime import datetime, timedelta, time as dt_time
from zoneinfo import ZoneInfo
from urllib.parse import urlsplit

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    Response,
    stream_with_context,
    flash,
    jsonify,
    session,
    g,
    abort,
)
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadData

APP_ROOT = pathlib.Path(__file__).resolve().parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

load_dotenv(APP_ROOT / ".env")  # Load app-specific .env

from mailer import db as dbmod
from mailer.smtp import SmtpClient
from mailer.lint import lint_html
from mailer.render import load_campaign_html, ensure_unsubscribe, render_for_recipient, render_for_test
from mailer.sse import GLOBAL_BUS


def _emit_sse(payload: dict) -> None:
    """Emit a structured SSE event (JSON) for the confirm-page client."""
    GLOBAL_BUS.emit(json.dumps(payload))

def _normalized_app_env() -> str:
    value = os.getenv("APP_ENV", "development") or "development"
    return value.strip().lower() or "development"

APP_ENV = _normalized_app_env()

def _is_production_env() -> bool:
    return APP_ENV == "production"

def _secret_key_is_strong(candidate: str | None) -> bool:
    if not candidate:
        return False
    trimmed = candidate.strip()
    if len(trimmed) < 32:
        return False
    lowered = trimmed.lower()
    if lowered in {"changeme", "change-me", "dev-secret", "secret", "supersecret"}:
        return False
    if not re.search(r"[0-9]", trimmed):
        return False
    if not re.search(r"[A-Za-z]", trimmed):
        return False
    if len(set(trimmed)) < 8:
        return False
    return True

def _load_app_secret_key() -> str:
    candidate = os.getenv("APP_SECRET_KEY", "")
    candidate = candidate.strip()
    if candidate:
        if not _secret_key_is_strong(candidate):
            message = "APP_SECRET_KEY is too weak; provide a 32+ character mixed secret."
            if _is_production_env():
                raise RuntimeError(message)
            print(f"WARNING: {message} Using a random development secret instead.", file=sys.stderr)
            return secrets.token_hex(32)
        return candidate
    if _is_production_env():
        raise RuntimeError("APP_SECRET_KEY must be set when APP_ENV=production.")
    dev_secret = secrets.token_hex(32)
    print("INFO: Generated ephemeral development APP_SECRET_KEY.", file=sys.stderr)
    return dev_secret

APP_SECRET_KEY = _load_app_secret_key()
RAW_LOG_STREAM_TOKEN_SECRET = os.getenv("LOG_STREAM_TOKEN_SECRET", "").strip()
if _is_production_env() and not RAW_LOG_STREAM_TOKEN_SECRET:
    raise RuntimeError("LOG_STREAM_TOKEN_SECRET must be set in production.")

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY
LOG_STREAM_TOKEN_SECRET = RAW_LOG_STREAM_TOKEN_SECRET or app.secret_key

app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = _is_production_env()
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

CAMPAIGNS_DIR = APP_ROOT / "campaigns"
INDIVIDUAL_EMAILS_DIR = APP_ROOT / "individual_emails"
ALLOWED_CAMPAIGN_EXTS = {".html", ".htm"}
INDIVIDUAL_EMAIL_EXTS = {".html", ".htm"}
DEFAULT_INDIVIDUAL_EMAIL_TEMPLATE = os.getenv("WELCOME_EMAIL_TEMPLATE", "welcome.html")
LOGIN_SESSION_KEY = "auth_user_id"
MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("AUTH_MAX_FAILED_ATTEMPTS", "5"))
LOCKOUT_MINUTES = int(os.getenv("AUTH_LOCKOUT_MINUTES", "15"))
SESSION_LIFETIME_HOURS = int(os.getenv("AUTH_SESSION_HOURS", "12"))
APP_PORTAL_HOSTNAME = os.getenv("APP_PORTAL_HOSTNAME", "console.casadelpollo.com")
MIN_PASSWORD_LENGTH = int(os.getenv("AUTH_MIN_PASSWORD_LENGTH", "12"))
PUBLIC_ENDPOINTS = {"login", "static", "logs_stream"}
CUSTOMER_MODE_SESSION_KEY = "customer_table_mode"
CUSTOMER_MODE_DEFAULT = "production"
CUSTOMER_MODE_CHOICES = {"production", "test"}
LOG_STREAM_TOKEN_TTL_SECONDS = int(os.getenv("LOG_STREAM_TOKEN_TTL_SECONDS", "3600"))
LOG_STREAM_TOKEN_SALT = "logs-stream-token"
SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
CSRF_SESSION_KEY = "_csrf_token"
CSRF_FIELD_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"

app.permanent_session_lifetime = timedelta(hours=SESSION_LIFETIME_HOURS)


def list_campaign_files():
    return sorted([f.name for f in CAMPAIGNS_DIR.glob("*.html")])


def list_individual_email_templates():
    INDIVIDUAL_EMAILS_DIR.mkdir(parents=True, exist_ok=True)
    templates = []
    files = []
    for ext in INDIVIDUAL_EMAIL_EXTS:
        files.extend(INDIVIDUAL_EMAILS_DIR.glob(f"*{ext}"))
    for path in sorted(files, key=lambda p: p.name.lower()):
        try:
            html = load_campaign_html(path)
        except Exception:
            html = ""
        label = _humanize_filename(path.stem)
        subject = _extract_subject_from_html(html) or label
        templates.append({"file": path.name, "label": label, "subject": subject})
    return templates


def _sanitize_campaign_filename(raw_name: str) -> str:
    """Normalize and validate campaign filenames."""
    candidate = (raw_name or "").strip()
    if not candidate:
        raise ValueError("Please provide a file name.")
    filename = secure_filename(candidate)
    if not filename:
        raise ValueError("Invalid file name.")
    stem, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext not in ALLOWED_CAMPAIGN_EXTS:
        raise ValueError("Campaign uploads must be HTML files.")
    if ext != ".html":
        filename = f"{stem}.html"
    return filename

# Validation bounds for send controls (used in /confirm and /send)
DELAY_MS_MIN = 0
DELAY_MS_MAX = 60_000
BATCH_SIZE_MIN = 1
BATCH_SIZE_MAX = 2000


def default_controls():
    return {
    "batch_size": int(os.getenv("DEFAULT_BATCH_SIZE", "100")),
    "delay_ms": int(os.getenv("DEFAULT_BATCH_DELAY_MS", "200")),
    }

PACIFIC = ZoneInfo("America/Los_Angeles")


def _validate_send_controls(
    delay_ms_raw: int | str,
    batch_size_raw: int | str,
    restrict_start_s: str | None,
    restrict_end_s: str | None,
) -> tuple[int, int, str | None, str | None]:
    """Validate delay_ms, batch_size, and restricted hours. Returns (delay_ms, batch_size, restrict_start, restrict_end) or raises ValueError."""
    try:
        delay_ms = int(delay_ms_raw)
    except (TypeError, ValueError):
        raise ValueError("Delay (ms) must be a whole number.")
    if not (DELAY_MS_MIN <= delay_ms <= DELAY_MS_MAX):
        raise ValueError(f"Delay must be between {DELAY_MS_MIN} and {DELAY_MS_MAX} ms.")
    try:
        batch_size = int(batch_size_raw)
    except (TypeError, ValueError):
        raise ValueError("Batch size must be a whole number.")
    if not (BATCH_SIZE_MIN <= batch_size <= BATCH_SIZE_MAX):
        raise ValueError(f"Batch size must be between {BATCH_SIZE_MIN} and {BATCH_SIZE_MAX}.")
    start_s = (restrict_start_s or "").strip() or None
    end_s = (restrict_end_s or "").strip() or None
    if start_s is None and end_s is None:
        return (delay_ms, batch_size, None, None)
    if start_s is None or end_s is None:
        raise ValueError("Provide both start and end times for restricted hours, or leave both empty.")
    start_t = _parse_time_string(start_s)
    end_t = _parse_time_string(end_s)
    if start_t is None or end_t is None:
        raise ValueError("Restricted hours must be valid times (e.g. 10:00 and 22:00).")
    if start_t == end_t:
        raise ValueError("Start and end times cannot be the same. Use different times or leave both empty for no restriction.")
    return (delay_ms, batch_size, start_s, end_s)


def _parse_time_string(s: str | None):
    """Parse 'HH:MM' or 'H:MM' into datetime.time; return None if invalid or empty."""
    if not s or not isinstance(s, str):
        return None
    s = s.strip()
    if not s:
        return None
    parts = s.split(":")
    if len(parts) != 2:
        return None
    try:
        h, m = int(parts[0], 10), int(parts[1], 10)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return dt_time(h, m)
    except ValueError:
        pass
    return None


def _in_window(t: dt_time, start_t: dt_time, end_t: dt_time) -> bool:
    """True if time t is inside [start_t, end_t); supports overnight (e.g. 22:00–06:00)."""
    if start_t <= end_t:
        return start_t <= t < end_t
    return t >= start_t or t < end_t


def _next_window_start(now: datetime, start_t: dt_time, end_t: dt_time, tz: ZoneInfo) -> datetime:
    """Return the next moment when the window opens (Pacific)."""
    today = now.date()
    start_dt = datetime.combine(today, start_t, tzinfo=tz)
    end_dt = datetime.combine(today, end_t, tzinfo=tz)
    if end_t <= start_t:
        end_dt += timedelta(days=1)
    if now < start_dt:
        return start_dt
    next_start = datetime.combine(today + timedelta(days=1), start_t, tzinfo=tz)
    return next_start


def _sleep_until_in_window(restrict_start: dt_time, restrict_end: dt_time) -> bool:
    """Block until current Pacific time is inside the send window. Returns True if we had to sleep (waited)."""
    waited = False
    while True:
        now_pt = datetime.now(PACIFIC)
        tod = now_pt.timetz().replace(tzinfo=None) if now_pt.tzinfo else now_pt.time()
        if _in_window(tod, restrict_start, restrict_end):
            return waited
        waited = True
        next_start = _next_window_start(now_pt, restrict_start, restrict_end, PACIFIC)
        delta = (next_start - now_pt).total_seconds()
        if delta > 0:
            time_module.sleep(min(delta, 3600))
        else:
            time_module.sleep(60)


def estimate_completion_utc(
    recipient_count: int,
    delay_ms: int,
    restrict_start_s: str | None,
    restrict_end_s: str | None,
) -> datetime | None:
    """Estimate completion time (UTC). If restricted hours, walk through Pacific windows."""
    if recipient_count <= 0 or delay_ms < 0:
        return None
    restrict_start = _parse_time_string(restrict_start_s)
    restrict_end = _parse_time_string(restrict_end_s)
    if restrict_start is None or restrict_end is None:
        duration_ms = recipient_count * delay_ms
        return datetime.now(ZoneInfo("UTC")) + timedelta(milliseconds=duration_ms)
    now_utc = datetime.now(ZoneInfo("UTC"))
    now_pt = now_utc.astimezone(PACIFIC)
    remaining = recipient_count
    t_pt = now_pt
    delay_sec = delay_ms / 1000.0
    while remaining > 0:
        tod = t_pt.timetz().replace(tzinfo=None) if t_pt.tzinfo else t_pt.time()
        if not _in_window(tod, restrict_start, restrict_end):
            t_pt = _next_window_start(t_pt, restrict_start, restrict_end, PACIFIC)
            continue
        today = t_pt.date()
        end_dt = datetime.combine(today, restrict_end, tzinfo=PACIFIC)
        if restrict_end <= restrict_start:
            end_dt += timedelta(days=1)
        window_sec = (end_dt - t_pt).total_seconds()
        if window_sec <= 0:
            t_pt = _next_window_start(t_pt, restrict_start, restrict_end, PACIFIC)
            continue
        capacity = int(window_sec / delay_sec)
        if capacity <= 0:
            t_pt = end_dt
            continue
        send_now = min(remaining, capacity)
        t_pt = t_pt + timedelta(seconds=send_now * delay_sec)
        remaining -= send_now
    return t_pt.astimezone(ZoneInfo("UTC"))


def resolve_campaign_path(file_field: str) -> pathlib.Path:
    """Resolve and validate a campaign file path within CAMPAIGNS_DIR."""
    file_field = (file_field or "").strip()
    if not file_field:
        raise ValueError("No campaign file was provided.")

    base = CAMPAIGNS_DIR.resolve()
    candidate = (base / file_field).resolve()

    if base not in candidate.parents:
        raise ValueError("Invalid campaign path.")
    if not candidate.is_file():
        raise FileNotFoundError(f"{file_field} not found.")
    return candidate


def _clean_field(source, key: str) -> str:
    """Fetch and normalize a string field from a dict/ImmutableMultiDict."""
    if not source:
        return ""
    value = source.get(key)
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _optional_field(source, key: str):
    """Return a trimmed string or None when empty."""
    value = _clean_field(source, key)
    return value or None


def _coerce_bool(value, default: bool = True) -> bool:
    """Convert various truthy inputs into a bool."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if not lowered:
            return default
        return lowered in {"1", "true", "yes", "y", "on"}
    return default


def _bool_from_db(value) -> bool:
    """Coerce MySQL-ish values to boolean."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(int(value))
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, (bytes, bytearray)):
        if not value:
            return False
        try:
            text_value = value.decode("utf-8", errors="ignore").strip()
        except Exception:
            text_value = "".join(chr(b) for b in value).strip()
        if text_value:
            lowered = text_value.lower()
            return lowered not in {"0", "false", "f", "n", "no", "off"}
        return bool(value[0])
    if isinstance(value, str):
        lowered = value.strip().lower()
        if not lowered:
            return False
        return lowered not in {"0", "false", "f", "n", "no", "off"}
    return False


def _wants_json_response() -> bool:
    """Detect whether the current request prefers a JSON response."""
    if request.path.startswith("/api/"):
        return True
    if request.headers.get("X-Requested-With", "").lower() == "xmlhttprequest":
        return True
    accepts = request.accept_mimetypes
    html_q = accepts["text/html"]
    json_q = accepts["application/json"]
    if html_q == json_q:
        return False
    return json_q > html_q


def _normalize_customer_mode(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().lower()
    if candidate in CUSTOMER_MODE_CHOICES:
        return candidate
    return None


def _ensure_customer_mode() -> str:
    """Ensure the session always tracks a supported database mode."""
    stored = session.get(CUSTOMER_MODE_SESSION_KEY)
    normalized = _normalize_customer_mode(stored) or CUSTOMER_MODE_DEFAULT
    if stored != normalized:
        session[CUSTOMER_MODE_SESSION_KEY] = normalized
    return normalized


def _current_customer_mode() -> str:
    """Return the active customer-table mode for this request context."""
    return getattr(g, "db_mode", CUSTOMER_MODE_DEFAULT)


def _log_stream_serializer() -> URLSafeTimedSerializer:
    secret = LOG_STREAM_TOKEN_SECRET or app.secret_key
    return URLSafeTimedSerializer(secret_key=secret, salt=LOG_STREAM_TOKEN_SALT)


def _generate_log_stream_token(mode: str) -> str:
    payload = {
        "purpose": "logs-stream",
        "mode": mode or CUSTOMER_MODE_DEFAULT,
        "nonce": secrets.token_hex(16),
    }
    serializer = _log_stream_serializer()
    return serializer.dumps(payload)


def _validate_log_stream_token(token: str | None):
    if not token:
        return None
    serializer = _log_stream_serializer()
    try:
        data = serializer.loads(token, max_age=LOG_STREAM_TOKEN_TTL_SECONDS)
    except BadData:
        return None
    if data.get("purpose") != "logs-stream":
        return None
    return data


def _get_csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _rotate_csrf_token() -> str:
    session.pop(CSRF_SESSION_KEY, None)
    return _get_csrf_token()


def _extract_request_csrf_token():
    header_value = (request.headers.get(CSRF_HEADER_NAME) or "").strip()
    if header_value:
        return header_value
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        candidate = payload.get(CSRF_FIELD_NAME)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    form_value = request.form.get(CSRF_FIELD_NAME)
    if form_value:
        return form_value.strip()
    return None


def _validate_csrf_token() -> bool:
    if request.method in SAFE_HTTP_METHODS:
        return True
    expected = session.get(CSRF_SESSION_KEY)
    if not expected:
        return False
    candidate = _extract_request_csrf_token()
    if not candidate:
        return False
    try:
        return secrets.compare_digest(expected, candidate)
    except Exception:
        return False


def _login_context(**overrides):
    """Base template context for the login/create-account page."""
    context = {
    "next": "",
    "brand_host": APP_PORTAL_HOSTNAME,
    "username": "",
    "login_error": None,
    }
    context.update(overrides)
    return context


@app.context_processor
def _inject_customer_mode():
    """Expose the current DB mode to every template."""
    return {
        "current_db_mode": getattr(g, "db_mode", CUSTOMER_MODE_DEFAULT),
        "csrf_token": _get_csrf_token,
    }


def _db_value_to_bytes(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return str(value).encode("utf-8")


def _safe_next_url(candidate: str | None):
    """Allow only relative URLs for login redirects."""
    if not candidate:
        return None
    candidate = candidate.strip()
    if not candidate:
        return None
    if candidate.startswith(("http://", "https://")):
        parts = urlsplit(candidate)
        path = parts.path or "/"
        if parts.netloc and parts.netloc != request.host:
            return None
        if parts.query:
            return f"{path}?{parts.query}"
        return path
    if candidate.startswith("/"):
        return candidate
    return None


def _requested_next_path():
    """Capture the current path (plus query) when redirecting to login."""
    if request.method != "GET":
        return None
    full_path = request.full_path or request.path
    if not full_path:
        return "/"
    if full_path.endswith("?"):
        full_path = full_path[:-1]
    return full_path or "/"


def _should_skip_auth(endpoint: str | None) -> bool:
    if not endpoint:
        return False
    base = endpoint.split(".")[0]
    return base in PUBLIC_ENDPOINTS


def _now_utc() -> datetime:
    return datetime.utcnow()


def _handle_failed_login(user_row):
    """Increment counters and calculate lockouts on failed auth."""
    user_id = user_row.get("id")
    current_count = int(user_row.get("failed_login_count") or 0)
    new_count = current_count + 1
    locked_until = None
    if new_count >= MAX_FAILED_LOGIN_ATTEMPTS:
        locked_until = _now_utc() + timedelta(minutes=LOCKOUT_MINUTES)
    try:
        dbmod.update_failed_login(
        user_id,
        failed_login_count=new_count,
        locked_until=locked_until,
        )
    except Exception as exc:
        app.logger.warning("Unable to update failed login counter: %s", exc)
    return new_count, locked_until


def _password_matches(user_row, candidate: str) -> bool:
    if not candidate:
        return False
    algo = (user_row.get("password_algo") or "").lower()
    stored = user_row.get("password_hash")
    if isinstance(stored, (bytes, bytearray)):
        try:
            stored = stored.decode("utf-8")
        except Exception:
            stored = stored.decode("utf-8", errors="ignore")
    if not stored:
        return False
    if algo in {"", "pbkdf2_sha256"}:
        try:
            return check_password_hash(stored, candidate)
        except Exception as exc:
            app.logger.warning("Failed to verify password hash: %s", exc)
            return False
    app.logger.error(
        "Unsupported password algorithm '%s' for user %s; ask an admin to reset the account.",
        algo,
        user_row.get("id"),
    )
    return False


@app.before_request
def _load_logged_in_user():
    """Attach the current user to flask.g and gate non-public endpoints."""
    g.user = None
    user_id = session.get(LOGIN_SESSION_KEY)
    if user_id:
        try:
            user_row = dbmod.fetch_user_by_id(int(user_id))
        except Exception:
            user_row = None
        if user_row and user_row.get("is_active"):
            g.user = user_row
        else:
            session.pop(LOGIN_SESSION_KEY, None)

    g.db_mode = _ensure_customer_mode()
    dbmod.set_customer_table_mode(g.db_mode)

    if _should_skip_auth(request.endpoint):
        return

    if g.user:
        return

    if _wants_json_response():
        return jsonify({"error": "Authentication required."}), 401

    next_path = _requested_next_path()
    if next_path:
        return redirect(url_for("login", next=next_path))
    return redirect(url_for("login"))


@app.before_request
def _enforce_csrf_protection():
    """Reject state-changing requests lacking a valid CSRF token."""
    if request.method in SAFE_HTTP_METHODS:
        return
    endpoint = (request.endpoint or "").split(".")[0]
    if endpoint == "static":
        return
    if _validate_csrf_token():
        return
    if _wants_json_response():
        return jsonify({"error": "Invalid or missing CSRF token."}), 403
    flash("Your session expired. Please refresh and try again.", "error")
    return "Forbidden", 403


@app.teardown_request
def _reset_customer_table_mode(exception=None):
    """Ensure thread-local database state never bleeds between requests."""
    dbmod.clear_customer_table_mode()


@app.after_request
def _set_security_headers(response):
    """Inject baseline security headers on every response."""
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none';")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if _is_production_env():
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def _serialize_customer(row) -> dict | None:
    if not row:
        return None
    tags_raw = row.get("tags")
    if tags_raw is None and row.get("CUSTID") is not None:
        table = dbmod.get_customer_table_name()
        tags_raw = dbmod.get_customer_tags(table, row["CUSTID"])
    tags = []
    if tags_raw:
        for t in tags_raw:
            if isinstance(t, dict):
                tags.append({"id": t.get("id"), "name": t.get("name", "")})
            else:
                tags.append({"id": None, "name": str(t)})
    return {
        "id": row.get("CUSTID"),
        "firstname": row.get("FIRSTNAME") or "",
        "lastname": row.get("LASTNAME") or "",
        "email": row.get("EMAIL") or "",
        "company": row.get("COMPANY") or "",
        "phone": row.get("PHONE") or "",
        "comments": row.get("COMMENTS") or "",
        "is_subscribed": _bool_from_db(row.get("IS_SUBSCRIBED")),
        "tags": tags,
    }


def _parse_int(value, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    """Coerce a request arg into a bounded integer."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _humanize_filename(stem: str) -> str:
    text = (stem or "").strip()
    text = re.sub(r"[_-]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return "Email"
    return text.title()


def _extract_subject_from_html(html: str | None) -> str | None:
    if not html:
        return None
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        subject = re.sub(r"\s+", " ", match.group(1)).strip()
        if subject:
            return subject
    heading = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.IGNORECASE | re.DOTALL)
    if heading:
        text = re.sub(r"<[^>]+>", "", heading.group(1))
        text = re.sub(r"\s+", " ", text).strip()
        if text:
            return text
    return None


def resolve_individual_email_path(file_field: str) -> pathlib.Path:
    """Validate a filename within the individual email directory."""
    file_field = (file_field or "").strip()
    if not file_field:
        raise ValueError("Select an email template.")
    INDIVIDUAL_EMAILS_DIR.mkdir(parents=True, exist_ok=True)
    base = INDIVIDUAL_EMAILS_DIR.resolve()
    candidate = (base / file_field).resolve()
    if base not in candidate.parents:
        raise ValueError("Invalid email template path.")
    if candidate.suffix.lower() not in INDIVIDUAL_EMAIL_EXTS:
        raise ValueError("Email templates must be HTML files.")
    if not candidate.is_file():
        raise FileNotFoundError(f"{file_field} not found.")
    return candidate


def _prepare_individual_email(
    row: dict,
    template_file: str,
    subject_override: str | None = None,
    *,
    mode: str | None = None,
):
    path = resolve_individual_email_path(template_file)
    raw_html = load_campaign_html(path)
    ensured = ensure_unsubscribe(raw_html)
    token = dbmod.ensure_unsubscribe_token(row.get("CUSTID"), row.get("UNSUBSCRIBE_TOKEN"))
    html = render_for_recipient(
    ensured,
    row.get("FIRSTNAME"),
    row.get("LASTNAME"),
    token,
    mode=mode,
    )
    subject = (subject_override or _extract_subject_from_html(raw_html) or _humanize_filename(path.stem)).strip()
    return subject, html


def send_individual_email(
    cust_id: int,
    template_file: str,
    subject_override: str | None = None,
    *,
    mode: str | None = None,
):
    """Send a one-off email to the specified subscriber."""
    row = dbmod.fetch_customer_by_id(cust_id)
    if not row:
        raise dbmod.CustomerNotFoundError(f"CUSTID {cust_id} not found.")
    email = (row.get("EMAIL") or "").strip()
    if not email:
        raise ValueError("Customer does not have an email address.")
    if not _bool_from_db(row.get("IS_SUBSCRIBED")):
        raise ValueError("Customer is currently unsubscribed.")
    active_mode = mode or _current_customer_mode()
    subject, html = _prepare_individual_email(
    row,
    template_file,
    subject_override,
    mode=active_mode,
    )
    smtp = SmtpClient()
    msg = smtp.build_message(email, subject, html)
    smtp.send(msg)
    return {"email": email, "subject": subject}


def _send_individual_email_worker(cust_id: int, template_file: str, subject_override: str | None = None, mode: str = CUSTOMER_MODE_DEFAULT):
    try:
        dbmod.set_customer_table_mode(mode)
        send_individual_email(cust_id, template_file, subject_override, mode=mode)
    except Exception as exc:
        app.logger.warning("Failed to send individual email to %s: %s", cust_id, exc)
    finally:
        dbmod.clear_customer_table_mode()


def _maybe_send_welcome_email(cust_id: int, *, is_subscribed: bool):
    template_file = (DEFAULT_INDIVIDUAL_EMAIL_TEMPLATE or "").strip()
    if not template_file or not is_subscribed:
        return
    path = INDIVIDUAL_EMAILS_DIR / template_file
    if not path.exists():
        return
    mode = getattr(g, "db_mode", CUSTOMER_MODE_DEFAULT)
    threading.Thread(
        target=_send_individual_email_worker,
        args=(cust_id, template_file, None, mode),
        daemon=True,
    ).start()


@app.route("/login", methods=["GET", "POST"])
def login():
    """Render and process the operator login form."""
    next_url = _safe_next_url(request.values.get("next")) or ""
    if request.method == "GET":
        if g.user:
            return redirect(next_url or url_for("index"))
        return render_template("login.html", **_login_context(next=next_url))

    username_raw = _clean_field(request.form, "username")
    password = request.form.get("password") or ""
    if not username_raw or not password:
        error = "Enter both username and password."
        return render_template("login.html", **_login_context(next=next_url, login_error=error, username=username_raw))

    try:
        email_info = validate_email(username_raw, allow_smtputf8=False)
    except EmailNotValidError as exc:
        error = f"Enter a valid email address: {exc}"
        return render_template("login.html", **_login_context(next=next_url, login_error=error, username=username_raw))

    username = email_info.normalized

    try:
        user_row = dbmod.fetch_user_by_username(username)
    except Exception as exc:
        app.logger.exception("Unable to fetch user for login: %s", exc)
        error = "Unable to sign in right now. Please try again."
        return render_template("login.html", **_login_context(next=next_url, login_error=error, username=username))

    if not user_row or not user_row.get("is_active"):
        error = "Invalid username or password."
        return render_template("login.html", **_login_context(next=next_url, login_error=error, username=username))

    locked_until = user_row.get("locked_until")
    now = _now_utc()
    if locked_until and locked_until > now:
        delta_seconds = max(0, int((locked_until - now).total_seconds()))
        remaining = max(1, delta_seconds // 60 or 1)
        error = f"Account locked. Try again in {remaining} minute(s)."
        return render_template("login.html", **_login_context(next=next_url, login_error=error, username=username))

    if user_row.get("force_password_reset"):
        error = "Password reset required. Please contact an administrator."
        return render_template("login.html", **_login_context(next=next_url, login_error=error, username=username))

    if not _password_matches(user_row, password):
        _handle_failed_login(user_row)
        error = "Invalid username or password."
        return render_template("login.html", **_login_context(next=next_url, login_error=error, username=username))

    session[LOGIN_SESSION_KEY] = user_row["id"]
    session.permanent = True
    _rotate_csrf_token()
    try:
        dbmod.record_successful_login(user_row["id"])
    except Exception as exc:
        app.logger.warning("Unable to record successful login for %s: %s", user_row["id"], exc)
    return redirect(next_url or url_for("index"))


@app.get("/logout")
def logout():
    """Clear the current session and redirect to login."""
    session.pop(LOGIN_SESSION_KEY, None)
    session.pop(CSRF_SESSION_KEY, None)
    g.user = None
    return redirect(url_for("login"))


@app.get("/")
def index():
    return render_template(
    "index.html",
    campaign_files=list_campaign_files(),
    defaults=default_controls(),
    min_password_length=MIN_PASSWORD_LENGTH,
    show_user_modal=True,
    )


@app.post("/mode")
def set_customer_mode():
    """Toggle between production and test customer tables."""
    wants_json = _wants_json_response()
    payload = {}
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    raw_mode = payload.get("mode") if isinstance(payload, dict) else None
    if not raw_mode:
        raw_mode = _clean_field(request.form, "mode")

    normalized = _normalize_customer_mode(raw_mode)
    if not normalized:
        message = "Mode must be either 'production' or 'test'."
        if wants_json:
            return jsonify({"ok": False, "message": message}), 400
        flash(message, "error")
        return redirect(url_for("index"))

    session[CUSTOMER_MODE_SESSION_KEY] = normalized
    g.db_mode = normalized
    dbmod.set_customer_table_mode(normalized)
    tables = dbmod.get_customer_table_options()
    response = {"ok": True, "mode": normalized, "table": tables.get(normalized)}

    if wants_json:
        return jsonify(response)

    flash(f"Database mode switched to {normalized} mode.", "success")
    return redirect(url_for("index"))


@app.post("/users")
def add_operator():
    """Create a new operator account (authenticated)."""
    email_raw = _clean_field(request.form, "operator_email")
    password = request.form.get("operator_password") or ""
    confirm = request.form.get("operator_password_confirm") or ""
    redirect_target = url_for("index")

    if not email_raw or not password:
        flash("Provide an email address and password.", "error")
        return redirect(redirect_target)

    try:
        email_info = validate_email(email_raw, allow_smtputf8=False)
    except EmailNotValidError as exc:
        flash(f"Enter a valid email address: {exc}", "error")
        return redirect(redirect_target)

    email = email_info.normalized

    if len(password) < MIN_PASSWORD_LENGTH:
        flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.", "error")
        return redirect(redirect_target)

    if password != confirm:
        flash("Passwords do not match.", "error")
        return redirect(redirect_target)

    try:
        hashed = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
    except Exception as exc:
        app.logger.exception("Failed to hash password: %s", exc)
        flash("Unable to hash password.", "error")
        return redirect(redirect_target)

    try:
        dbmod.create_service_user(email=email, password_hash=hashed, password_algo="pbkdf2_sha256")
    except dbmod.ServiceUserAlreadyExists:
        flash("That email is already registered.", "error")
        return redirect(redirect_target)
    except Exception as exc:
        app.logger.exception("Unable to create user: %s", exc)
        flash("Unable to create user right now. Please try again.", "error")
        return redirect(redirect_target)

    flash(f"Created account for {email}.", "success")
    return redirect(redirect_target)


@app.post("/change-password")
def change_own_password():
    """Let the logged-in user change their own password."""
    redirect_target = url_for("index")
    if not g.user:
        flash("You must be logged in to change your password.", "error")
        return redirect(url_for("login"))

    current = (request.form.get("current_password") or "").strip()
    new_password = request.form.get("new_password") or ""
    new_confirm = request.form.get("new_password_confirm") or ""

    if not current:
        flash("Enter your current password.", "error")
        return redirect(redirect_target)
    if not new_password:
        flash("Enter a new password.", "error")
        return redirect(redirect_target)
    if len(new_password) < MIN_PASSWORD_LENGTH:
        flash(f"New password must be at least {MIN_PASSWORD_LENGTH} characters long.", "error")
        return redirect(redirect_target)
    if new_password != new_confirm:
        flash("New password and confirmation do not match.", "error")
        return redirect(redirect_target)

    try:
        user_row = dbmod.fetch_user_by_username(g.user["username"])
    except Exception as exc:
        app.logger.exception("change_own_password: fetch user: %s", exc)
        flash("Unable to verify your account. Please try again.", "error")
        return redirect(redirect_target)
    if not user_row or not _password_matches(user_row, current):
        flash("Current password is incorrect.", "error")
        return redirect(redirect_target)

    try:
        hashed = generate_password_hash(new_password, method="pbkdf2:sha256", salt_length=16)
    except Exception as exc:
        app.logger.exception("change_own_password: hash: %s", exc)
        flash("Unable to update password.", "error")
        return redirect(redirect_target)
    try:
        dbmod.update_user_password(g.user["id"], password_hash=hashed, password_algo="pbkdf2_sha256")
    except Exception as exc:
        app.logger.exception("change_own_password: update: %s", exc)
        flash("Unable to save new password. Please try again.", "error")
        return redirect(redirect_target)

    flash("Your password has been updated.", "success")
    return redirect(redirect_target)


@app.get("/api/operators")
def list_operators():
    """Return current admins for the Manage admins modal (authenticated)."""
    try:
        rows = dbmod.list_service_users()
    except Exception as exc:
        app.logger.exception("list_operators: %s", exc)
        return jsonify({"error": "Unable to load operators."}), 500
    out = []
    for r in rows:
        last_login_at = r.get("last_login_at")
        last_login_at_iso = None
        if last_login_at is not None:
            if last_login_at.tzinfo is None:
                last_login_at_iso = last_login_at.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
            else:
                last_login_at_iso = last_login_at.isoformat()
        out.append({
            "id": r["id"],
            "username": r["username"],
            "role": r.get("role") or "admin",
            "is_active": bool(r.get("is_active")),
            "last_login_at_iso": last_login_at_iso,
        })
    return jsonify({"operators": out})


@app.post("/campaigns/upload")
def upload_campaign():
    upload = request.files.get("campaign_file")
    desired_name = (request.form.get("filename") or "").strip()

    if not upload or not upload.filename:
        flash("Choose an HTML file to upload.", "error")
        return redirect(url_for("index"))

    try:
        filename = _sanitize_campaign_filename(desired_name or upload.filename)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))

    target_path = (CAMPAIGNS_DIR / filename).resolve()
    base = CAMPAIGNS_DIR.resolve()
    if base not in target_path.parents:
        flash("Invalid upload path.", "error")
        return redirect(url_for("index"))

    if target_path.exists():
        flash("A campaign with that name already exists.", "error")
        return redirect(url_for("index"))

    try:
        CAMPAIGNS_DIR.mkdir(parents=True, exist_ok=True)
        upload.save(target_path)
    except Exception as e:
        flash(f"Unable to save campaign: {e}", "error")
        return redirect(url_for("index"))

    flash(f"Uploaded {filename}. It is now available in the campaign list.", "success")
    return redirect(url_for("index"))


@app.get("/preview")
def preview():
    file_field = (request.args.get("file") or "").strip()
    if not file_field:
        return jsonify({"error": "No campaign file was selected."}), 400

    try:
        campaign_path = resolve_campaign_path(file_field)
        html = load_campaign_html(campaign_path)
        html_with_unsub = ensure_unsubscribe(html)
        rendered = render_for_test(html_with_unsub, mode=_current_customer_mode())
        lint_report = lint_html(html)
    except FileNotFoundError:
        return jsonify({"error": "Campaign file not found."}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unable to load preview: {e}"}), 500

    return jsonify({"file": file_field, "html": rendered, "lint": lint_report})


@app.post("/lint")
def lint_route():
    file_field = (request.form.get("file") or "").strip()
    if not file_field:
        return jsonify({"error": "No campaign file was selected."}), 400

    try:
        campaign_path = resolve_campaign_path(file_field)
        html = load_campaign_html(campaign_path)
        report = lint_html(html)
    except FileNotFoundError:
        return jsonify({"error": "Campaign file not found."}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unable to lint campaign: {e}"}), 500

    return jsonify({"file": file_field, "lint": report})


@app.post("/send-test")
def send_test():
    wants_json = _wants_json_response()

    def error_response(message, status=400):
        if wants_json:
            return jsonify({"ok": False, "message": message}), status
        flash(message, "error")
        return redirect(url_for("index"))

    def success_response(message, email):
        if wants_json:
            return jsonify({"ok": True, "message": message, "email": email})
        flash(message, "success")
        return redirect(url_for("index"))

    # Pull fields safely and normalize
    file_field = (request.form.get("file") or "").strip()  # ensure not None
    subject = (request.form.get("subject") or "").strip() or "Test Campaign"
    email_raw = (request.form.get("email") or "").strip()

    # Basic presence checks first
    if not file_field:
        return error_response("No campaign file was selected.")
    if not email_raw:
        return error_response("Please enter a test email address.")

    # Validate & normalize email
    try:
        email_obj = validate_email(email_raw)
        to_addr = email_obj.email  # normalized
    except EmailNotValidError as e:
        return error_response(f"Invalid email: {e}")

    subscriber = None
    subscriber_token = None
    try:
        subscriber = dbmod.fetch_customer_by_email(to_addr)
    except Exception as e:
        return error_response(f"Unable to load subscriber info: {e}")
    if subscriber:
        try:
            subscriber_token = dbmod.ensure_unsubscribe_token(
            subscriber.get("CUSTID"),
            subscriber.get("UNSUBSCRIBE_TOKEN"),
            )
        except Exception as e:
            return error_response(f"Unable to ensure unsubscribe token: {e}")

    try:
        candidate = resolve_campaign_path(file_field)
    except FileNotFoundError:
        return error_response("Campaign file not found.", 404)
    except ValueError as e:
        return error_response(str(e))

    # Load and render the campaign (catch template/HTML errors)
    try:
        campaign_html = load_campaign_html(candidate)
    except Exception as e:
        return error_response(f"Unable to load campaign HTML: {e}")

    lint_report = lint_html(campaign_html)
    if lint_report.get("errors"):
        return error_response("Resolve lint errors before sending a test email.")

    try:
        raw_html = ensure_unsubscribe(campaign_html)
        active_mode = _current_customer_mode()
        if subscriber and subscriber_token:
            html = render_for_recipient(
            raw_html,
            subscriber.get("FIRSTNAME"),
            subscriber.get("LASTNAME"),
            subscriber_token,
            mode=active_mode,
            )
        else:
            html = render_for_test(raw_html, mode=active_mode)
    except Exception as e:
        return error_response(f"Error preparing campaign HTML: {e}")

    # Build + send the email (guard against None/invalid inputs)
    try:
        smtp = SmtpClient()  # or SmtpClient.from_env()
        msg = smtp.build_message(to_addr, subject, html)
    except Exception as e:
        return error_response(f"Error creating email message: {e}")

    try:
        smtp.send(msg)
    except Exception as e:
        return error_response(f"Failed to send test: {e}")

    return success_response(f"Test email sent to {to_addr}.", to_addr)


@app.get("/customers/new")
def new_customer():
    """Render the customer creation form."""
    return render_template("add_customer.html")


@app.post("/customers")
def add_customer():
    """Create a new customer/subscriber via the dashboard form."""
    form = request.form
    email_raw = _clean_field(form, "email")
    firstname = _optional_field(form, "firstname")
    lastname = _optional_field(form, "lastname")
    company = _optional_field(form, "company")
    phone = _optional_field(form, "phone")
    comments = _optional_field(form, "comments")

    if not email_raw:
        flash("Email is required to add a customer.", "error")
        return redirect(url_for("index"))

    try:
        email = validate_email(email_raw).email
    except EmailNotValidError as e:
        flash(f"Invalid email: {e}", "error")
        return redirect(url_for("index"))

    try:
        record = dbmod.create_customer(
        email=email,
        firstname=firstname,
        lastname=lastname,
        company=company,
        phone=phone,
        comments=comments,
        )
    except dbmod.DuplicateCustomerError:
        flash("That email address is already subscribed.", "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Failed to add customer: {e}", "error")
        return redirect(url_for("index"))

    if record and record.get("custid"):
        _maybe_send_welcome_email(record["custid"], is_subscribed=True)

    flash(f"Customer {email} added successfully.", "success")
    return redirect(url_for("index"))


@app.get("/api/customers")
def list_customers_api():
    search_term = _optional_field(request.args, "search")
    tag_ids_raw = request.args.getlist("tag")
    tag_ids = []
    for t in tag_ids_raw:
        try:
            tag_ids.append(int(t))
        except (TypeError, ValueError):
            pass
    per_page = _parse_int(request.args.get("per_page"), 25, minimum=1, maximum=100)
    page = _parse_int(request.args.get("page"), 1, minimum=1, maximum=1000)
    offset = (page - 1) * per_page
    try:
        rows, total = dbmod.fetch_customers_paginated(
        search=search_term,
        tag_ids=tag_ids if tag_ids else None,
        limit=per_page,
        offset=offset,
        )
        total = int(total or 0)
        if total <= 0:
            page = 1
            total_pages = 1
        else:
            total_pages = max(1, math.ceil(total / per_page))
            if page > total_pages:
                page = total_pages
                offset = (page - 1) * per_page
                rows, total = dbmod.fetch_customers_paginated(
                search=search_term,
                tag_ids=tag_ids if tag_ids else None,
                limit=per_page,
                offset=offset,
                )
    except Exception as e:
        app.logger.exception("Failed to fetch customers")
        return jsonify({"error": f"Unable to load customers: {e}"}), 500
    serialized = [_serialize_customer(row) for row in rows]
    if total > 0:
        total_pages = max(1, math.ceil(total / per_page))
    else:
        total_pages = 1
    pagination = {
    "page": page,
    "per_page": per_page,
    "total": total,
    "total_pages": total_pages,
    "has_next": total > 0 and page < total_pages,
    "has_prev": total > 0 and page > 1,
    }
    return jsonify({"customers": serialized, "pagination": pagination, "search": search_term or ""})


@app.post("/api/customers")
def create_customer_api():
    payload = request.get_json(silent=True) or {}
    email_raw = _clean_field(payload, "email")
    if not email_raw:
        return jsonify({"error": "Email is required."}), 400

    try:
        email = validate_email(email_raw).email
    except EmailNotValidError as e:
        return jsonify({"error": f"Invalid email: {e}"}), 400

    firstname = _optional_field(payload, "firstname")
    lastname = _optional_field(payload, "lastname")
    company = _optional_field(payload, "company")
    phone = _optional_field(payload, "phone")
    comments = _optional_field(payload, "comments")
    is_subscribed = _coerce_bool(payload.get("is_subscribed"), True)

    try:
        record = dbmod.create_customer(
        email=email,
        firstname=firstname,
        lastname=lastname,
        company=company,
        phone=phone,
        comments=comments,
        is_subscribed=is_subscribed,
        )
        row = dbmod.fetch_customer_by_id(record["custid"])
    except dbmod.DuplicateCustomerError:
        return jsonify({"error": "That email address is already subscribed."}), 409
    except Exception as e:
        app.logger.exception("Failed to create customer")
        return jsonify({"error": f"Failed to add customer: {e}"}), 500

    if not row:
        return jsonify({"error": "Unable to load created customer."}), 500

    tag_names = payload.get("tags")
    if isinstance(tag_names, list) and tag_names:
        table = dbmod.get_customer_table_name()
        try:
            dbmod.set_customer_tags(table, row["CUSTID"], tag_names)
        except Exception:
            pass
        row = dbmod.fetch_customer_by_id(row["CUSTID"])
        row["tags"] = dbmod.get_customer_tags(table, row["CUSTID"])

    _maybe_send_welcome_email(row["CUSTID"], is_subscribed=is_subscribed)

    return jsonify({"customer": _serialize_customer(row)}), 201


@app.post("/api/customers/import")
def import_customers_api():
    """Import customers from CSV. Columns: email (required), firstname, lastname, company, phone, comments, is_subscribed, tags (comma-separated)."""
    upload = request.files.get("file") or request.files.get("csv_file")
    if not upload or not upload.filename:
        return jsonify({"error": "No CSV file provided."}), 400
    if not upload.filename.lower().endswith(".csv"):
        return jsonify({"error": "File must be a CSV."}), 400
    try:
        raw = upload.read().decode("utf-8-sig").strip()
    except UnicodeDecodeError:
        return jsonify({"error": "CSV must be UTF-8 encoded."}), 400
    table = dbmod.get_customer_table_name()
    created = 0
    updated = 0
    errors: list[dict] = []
    reader = csv.DictReader(io.StringIO(raw))
    if not reader.fieldnames or "email" not in [f.strip().lower() for f in reader.fieldnames]:
        return jsonify({"error": "CSV must have an 'email' column."}), 400
    for row_num, row in enumerate(reader, start=2):
        row_lower = {k.strip().lower(): v for k, v in row.items() if k}
        email_raw = (row_lower.get("email") or "").strip()
        if not email_raw:
            errors.append({"row": row_num, "message": "Missing email"})
            continue
        try:
            email = validate_email(email_raw).email
        except EmailNotValidError as e:
            errors.append({"row": row_num, "email": email_raw, "message": str(e)})
            continue
        firstname = (row_lower.get("firstname") or "").strip() or None
        lastname = (row_lower.get("lastname") or "").strip() or None
        company = (row_lower.get("company") or "").strip() or None
        phone = (row_lower.get("phone") or "").strip() or None
        comments = (row_lower.get("comments") or "").strip() or None
        is_sub_raw = (row_lower.get("is_subscribed") or "").strip().lower()
        is_subscribed = is_sub_raw in ("1", "yes", "true", "on")
        tags_raw = (row_lower.get("tags") or "").strip()
        tag_names = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []
        existing = dbmod.fetch_customer_by_email(email)
        try:
            if existing:
                dbmod.update_customer(
                    existing["CUSTID"],
                    email=email,
                    firstname=firstname or "",
                    lastname=lastname or "",
                    company=company or "",
                    phone=phone or "",
                    comments=comments or "",
                    is_subscribed=is_subscribed,
                )
                dbmod.set_customer_tags(table, existing["CUSTID"], tag_names)
                updated += 1
            else:
                record = dbmod.create_customer(
                    email=email,
                    firstname=firstname,
                    lastname=lastname,
                    company=company,
                    phone=phone,
                    comments=comments,
                    is_subscribed=is_subscribed,
                )
                dbmod.set_customer_tags(table, record["custid"], tag_names)
                created += 1
        except dbmod.DuplicateCustomerError:
            errors.append({"row": row_num, "email": email, "message": "Duplicate email"})
        except Exception as e:
            errors.append({"row": row_num, "email": email, "message": str(e)})
    return jsonify({
        "created": created,
        "updated": updated,
        "errors": errors,
    })


@app.get("/api/customers/export")
def export_customers_api():
    """Export customers as CSV. Optional ?tag=1&tag=2 to filter by tag (AND semantics)."""
    fmt = (request.args.get("format") or "csv").strip().lower()
    if fmt != "csv":
        return jsonify({"error": "Only format=csv is supported."}), 400
    tag_ids_raw = request.args.getlist("tag")
    tag_ids = []
    for t in tag_ids_raw:
        try:
            tag_ids.append(int(t))
        except (TypeError, ValueError):
            pass
    tag_ids = tag_ids if tag_ids else None
    try:
        rows, _ = dbmod.fetch_customers_paginated(
            tag_ids=tag_ids,
            limit=10000,
            offset=0,
        )
    except Exception as e:
        app.logger.exception("Failed to export customers")
        return jsonify({"error": str(e)}), 500
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["email", "firstname", "lastname", "company", "phone", "comments", "is_subscribed", "tags"])
    for r in rows:
        tags_cell = ""
        if r.get("tags"):
            tags_cell = ",".join((t.get("name") or "") for t in r["tags"])
        writer.writerow([
            (r.get("EMAIL") or ""),
            (r.get("FIRSTNAME") or ""),
            (r.get("LASTNAME") or ""),
            (r.get("COMPANY") or ""),
            (r.get("PHONE") or ""),
            (r.get("COMMENTS") or ""),
            "1" if _bool_from_db(r.get("IS_SUBSCRIBED")) else "0",
            tags_cell,
        ])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=customers.csv"},
    )


@app.put("/api/customers/<int:cust_id>")
def update_customer_api(cust_id: int):
    payload = request.get_json(silent=True) or {}
    email_raw = _clean_field(payload, "email")
    if not email_raw:
        return jsonify({"error": "Email is required."}), 400

    try:
        email = validate_email(email_raw).email
    except EmailNotValidError as e:
        return jsonify({"error": f"Invalid email: {e}"}), 400

    firstname = _optional_field(payload, "firstname")
    lastname = _optional_field(payload, "lastname")
    company = _optional_field(payload, "company")
    phone = _optional_field(payload, "phone")
    comments = _optional_field(payload, "comments")

    existing = dbmod.fetch_customer_by_id(cust_id)
    if not existing:
        return jsonify({"error": "Customer not found."}), 404

    if "is_subscribed" in payload:
        is_subscribed = _coerce_bool(payload.get("is_subscribed"), True)
    else:
        is_subscribed = _bool_from_db(existing.get("IS_SUBSCRIBED"))

    try:
        dbmod.update_customer(
        cust_id,
        email=email,
        firstname=firstname,
        lastname=lastname,
        company=company,
        phone=phone,
        comments=comments,
        is_subscribed=is_subscribed,
        )
        row = dbmod.fetch_customer_by_id(cust_id)
    except dbmod.CustomerNotFoundError:
        return jsonify({"error": "Customer not found."}), 404
    except dbmod.DuplicateCustomerError:
        return jsonify({"error": "That email address is already subscribed."}), 409
    except Exception as e:
        app.logger.exception("Failed to update customer")
        return jsonify({"error": f"Failed to update customer: {e}"}), 500

    if not row:
        return jsonify({"error": "Customer not found."}), 404

    tag_names = payload.get("tags")
    if isinstance(tag_names, list):
        table = dbmod.get_customer_table_name()
        try:
            dbmod.set_customer_tags(table, cust_id, tag_names)
        except Exception:
            pass
        row["tags"] = dbmod.get_customer_tags(table, cust_id)

    return jsonify({"customer": _serialize_customer(row)})


@app.delete("/api/customers/<int:cust_id>")
def delete_customer_api(cust_id: int):
    existing = dbmod.fetch_customer_by_id(cust_id)
    if not existing:
        return jsonify({"error": "Customer not found."}), 404

    try:
        dbmod.delete_customer(cust_id)
    except dbmod.CustomerNotFoundError:
        return jsonify({"error": "Customer not found."}), 404
    except Exception as e:
        app.logger.exception("Failed to delete customer")
        return jsonify({"error": f"Failed to delete customer: {e}"}), 500

    return jsonify({"status": "deleted"})


@app.get("/api/tags")
def list_tags_api():
    try:
        tags = dbmod.list_tags(include_count=True)
    except Exception as e:
        app.logger.exception("Failed to list tags")
        return jsonify({"error": str(e)}), 500
    out = []
    for t in tags:
        item = {"id": t["id"], "name": t["name"]}
        if "customer_count" in t:
            item["customer_count"] = t["customer_count"]
        out.append(item)
    return jsonify({"tags": out})


@app.post("/api/tags")
def create_tag_api():
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Tag name is required."}), 400
    try:
        tag_id = dbmod.get_or_create_tag(name)
        tags = dbmod.list_tags()
        tag = next((t for t in tags if t["id"] == tag_id), None)
        if not tag:
            tag = {"id": tag_id, "name": name}
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.exception("Failed to create tag")
        return jsonify({"error": str(e)}), 500
    return jsonify({"tag": {"id": tag["id"], "name": tag["name"]}}), 201


@app.delete("/api/tags/<int:tag_id>")
def delete_tag_api(tag_id: int):
    try:
        dbmod.delete_tag(tag_id)
    except Exception as e:
        app.logger.exception("Failed to delete tag")
        return jsonify({"error": str(e)}), 500
    return jsonify({"status": "deleted"})


@app.get("/api/individual-emails")
def list_individual_emails_api():
    try:
        templates = list_individual_email_templates()
    except Exception as e:
        app.logger.exception("Failed to list individual emails")
        return jsonify({"error": f"Unable to load individual emails: {e}"}), 500
    return jsonify({"templates": templates})


@app.get("/api/customers/<int:cust_id>/individual-emails/preview")
def preview_individual_email_api(cust_id: int):
    template_name = _clean_field(request.args, "template")
    if not template_name:
        return jsonify({"error": "Select an email template."}), 400
    row = dbmod.fetch_customer_by_id(cust_id)
    if not row:
        return jsonify({"error": "Customer not found."}), 404
    try:
        subject, html = _prepare_individual_email(row, template_name, None, mode=_current_customer_mode())
    except FileNotFoundError:
        return jsonify({"error": "Email template not found."}), 404
    except dbmod.CustomerNotFoundError:
        return jsonify({"error": "Customer not found."}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.exception("Failed to render individual email preview")
        return jsonify({"error": f"Unable to render email: {e}"}), 500
    return jsonify({"subject": subject, "html": html})


@app.post("/api/customers/<int:cust_id>/individual-emails/send")
def send_individual_email_api(cust_id: int):
    payload = request.get_json(silent=True) or {}
    template_name = _clean_field(payload, "template")
    if not template_name:
        return jsonify({"error": "Select an email template."}), 400
    subject_override = _optional_field(payload, "subject")
    try:
        result = send_individual_email(
        cust_id,
        template_name,
        subject_override,
        mode=_current_customer_mode(),
        )
    except FileNotFoundError:
        return jsonify({"error": "Email template not found."}), 404
    except dbmod.CustomerNotFoundError:
        return jsonify({"error": "Customer not found."}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.exception("Failed to send individual email")
        return jsonify({"error": f"Unable to send email: {e}"}), 500
    return jsonify({"status": "sent", **result})


def _build_confirm_context(
    file: str,
    subject: str | None,
    batch_size: int,
    delay_ms: int,
    restrict_start: str | None = None,
    restrict_end: str | None = None,
    tag_names: list[str] | None = None,
):
    """Assemble the template context for the confirm page.
    When tag_names is None or empty, recipients = all subscribed ('Send to all').
    When tag_names is non-empty, recipients = subscribed customers with at least one of those tags (distinct).
    """
    campaign_path = resolve_campaign_path(file)
    raw_html = load_campaign_html(campaign_path)
    lint_report = lint_html(raw_html)
    lint_has_errors = bool(lint_report.get("errors"))
    lint_has_warnings = bool(lint_report.get("warnings"))

    preview_html = None
    preview_error = None
    try:
        preview_html = render_for_test(ensure_unsubscribe(raw_html), mode=_current_customer_mode())
    except Exception as e:
        preview_error = f"Unable to render campaign preview: {e}"

    recipients = dbmod.fetch_subscribed_customers(tag_names=tag_names) or []
    recipient_count = len(recipients)
    eta_utc = estimate_completion_utc(recipient_count, delay_ms, restrict_start, restrict_end)
    return {
        "file": file,
        "subject": subject,
        "recipient_count": recipient_count,
        "recipients": recipients,
        "batch_size": batch_size,
        "delay_ms": delay_ms,
        "restrict_start": restrict_start or "",
        "restrict_end": restrict_end or "",
        "lint_report": lint_report,
        "lint_has_errors": lint_has_errors,
        "lint_has_warnings": lint_has_warnings,
        "preview_html": preview_html,
        "preview_error": preview_error,
        "eta_utc_iso": eta_utc.isoformat() if eta_utc else None,
        "send_to": "all" if not tag_names else "tags",
        "tag_names": tag_names or [],
    }

@app.get("/confirm")
def confirm():
    file = (request.args.get("file") or "").strip()
    subject = request.args.get("subject")
    send_to = (request.args.get("send_to") or "all").strip().lower()
    tag_names_list = request.args.getlist("tag_names")
    tag_names_raw = (request.args.get("tag_names") or "").strip()
    tag_names = [n.strip() for n in tag_names_list if n and n.strip()]
    if not tag_names and tag_names_raw:
        tag_names = [n.strip() for n in tag_names_raw.split(",") if n.strip()]
    tag_names = tag_names if tag_names else None
    if send_to == "tags" and (not tag_names or not any(tag_names)):
        flash("Select at least one tag when sending to selected tags.", "error")
        return redirect(url_for("index"))
    if send_to != "tags":
        tag_names = None
    defaults = default_controls()
    batch_size_raw = request.args.get("batch_size", defaults["batch_size"])
    delay_ms_raw = request.args.get("delay_ms", defaults["delay_ms"])
    restrict_start = (request.args.get("restrict_start") or "").strip() or None
    restrict_end = (request.args.get("restrict_end") or "").strip() or None

    if not file:
        flash("No campaign file was selected.", "error")
        return redirect(url_for("index"))
    try:
        delay_ms, batch_size, restrict_start, restrict_end = _validate_send_controls(
            delay_ms_raw, batch_size_raw, restrict_start, restrict_end
        )
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    try:
        context = _build_confirm_context(file, subject, batch_size, delay_ms, restrict_start, restrict_end, tag_names=tag_names)
    except FileNotFoundError:
        flash("Campaign file not found.", "error")
        return redirect(url_for("index"))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Unable to prepare confirmation: {e}", "error")
        return redirect(url_for("index"))

    if context["lint_has_errors"]:
        flash("Resolve lint errors before reviewing the live send.", "error")
        return redirect(url_for("index"))

    return render_template("confirm.html", **context, sending=False, log_stream_token=None)


@app.post("/send")
def send_to_customers():
    file = (request.form.get("file") or "").strip()
    subject = request.form.get("subject")
    send_to = (request.form.get("send_to") or "all").strip().lower()
    tag_names_raw = (request.form.get("tag_names") or "").strip()
    tag_names = [n.strip() for n in tag_names_raw.split(",") if n.strip()] if tag_names_raw else None
    if send_to != "tags":
        tag_names = None
    defaults = default_controls()
    batch_size_raw = request.form.get("batch_size", defaults["batch_size"])
    delay_ms_raw = request.form.get("delay_ms", defaults["delay_ms"])
    restrict_start = (request.form.get("restrict_start") or "").strip() or None
    restrict_end = (request.form.get("restrict_end") or "").strip() or None

    if not file:
        flash("No campaign file was selected.", "error")
        return redirect(url_for("index"))
    try:
        delay_ms, batch_size, restrict_start, restrict_end = _validate_send_controls(
            delay_ms_raw, batch_size_raw, restrict_start, restrict_end
        )
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    try:
        context = _build_confirm_context(file, subject, batch_size, delay_ms, restrict_start, restrict_end, tag_names=tag_names)
    except FileNotFoundError:
        flash("Campaign file not found.", "error")
        return redirect(url_for("index"))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Unable to prepare confirmation: {e}", "error")
        return redirect(url_for("index"))

    if context["lint_has_errors"]:
        flash("Resolve lint errors before sending to customers.", "error")
        return redirect(
            url_for(
                "confirm",
                file=file,
                subject=subject,
                batch_size=batch_size,
                delay_ms=delay_ms,
                restrict_start=restrict_start or "",
                restrict_end=restrict_end or "",
                send_to=context.get("send_to", "all"),
                tag_names=",".join(context.get("tag_names") or []),
            )
        )

    # Kick off a background thread that does the sending and emits logs.
    mode = getattr(g, "db_mode", CUSTOMER_MODE_DEFAULT)
    threading.Thread(
        target=_send_worker,
        args=(file, subject, batch_size, delay_ms, mode),
        kwargs={"restrict_start": restrict_start, "restrict_end": restrict_end, "tag_names": tag_names},
        daemon=True,
    ).start()
    log_stream_token = _generate_log_stream_token(mode)
    context["sending"] = True
    return render_template("confirm.html", **context, log_stream_token=log_stream_token)


def _send_worker(
    file: str,
    subject: str,
    batch_size: int,
    delay_ms: int,
    mode: str,
    *,
    restrict_start: str | None = None,
    restrict_end: str | None = None,
    tag_names: list[str] | None = None,
):
    dbmod.set_customer_table_mode(mode)
    start_t = _parse_time_string(restrict_start)
    end_t = _parse_time_string(restrict_end)
    use_restricted = start_t is not None and end_t is not None
    try:
        candidate = resolve_campaign_path(file)
        raw_html = load_campaign_html(candidate)
        raw_html = ensure_unsubscribe(raw_html)
        if "{{ unsubscribe_url }}" not in raw_html and "{{ UNSUBSCRIBE_URL }}" not in raw_html:
            _emit_sse({"type": "log", "text": "⚠ No unsubscribe placeholder present after ensure_unsubscribe()"})
        smtp = SmtpClient()
        rows = dbmod.fetch_subscribed_customers(tag_names=tag_names)
        total = len(rows)
        _emit_sse({"type": "log", "text": f"Starting send: {total} recipients; batch_size={batch_size}; delay={delay_ms}ms"})
        if use_restricted:
            _emit_sse({"type": "log", "text": f"Restricted hours (Pacific): {restrict_start}–{restrict_end}"})

        sent = 0
        failed = 0
        skipped = 0
        idx = 0
        while idx < total:
            batch = rows[idx: idx + batch_size]
            _emit_sse({"type": "log", "text": f"Batch {idx//batch_size + 1}: {len(batch)} recipients"})
            for r in batch:
                to_addr = r["EMAIL"].strip()
                if use_restricted:
                    waited = _sleep_until_in_window(start_t, end_t)
                    if waited:
                        _emit_sse({"type": "log", "text": "Waiting for send window…"})
                try:
                    token = dbmod.ensure_unsubscribe_token(r.get("CUSTID"), r.get("UNSUBSCRIBE_TOKEN"))
                except Exception as e:
                    skipped += 1
                    _emit_sse({"type": "skipped", "to": to_addr, "reason": f"missing_unsubscribe_token: {e}"})
                    continue

                html = render_for_recipient(
                raw_html,
                r.get("FIRSTNAME"),
                r.get("LASTNAME"),
                token,
                mode=mode,
                )
                try:
                    msg = smtp.build_message(to_addr, subject, html)
                    smtp.send(msg, delay_ms=delay_ms)
                    sent += 1
                    _emit_sse({"type": "sent", "to": to_addr})
                except Exception as e:
                    failed += 1
                    _emit_sse({"type": "failed", "to": to_addr, "reason": str(e)})
            idx += batch_size
        _emit_sse({"type": "summary", "sent": sent, "failed": failed, "total": total, "skipped": skipped})
        _emit_sse({"type": "log", "text": f"Done. Sent {sent}/{total}; failed {failed}; skipped {skipped}."})
    except Exception as e:
        _emit_sse({"type": "log", "text": f"Fatal error: {e}"})
    finally:
        dbmod.clear_customer_table_mode()

@app.get("/logs/stream")
def logs_stream():
    token = (request.args.get("token") or "").strip()
    payload = _validate_log_stream_token(token)
    if not payload:
        return Response("Unauthorized", status=401)
    return Response(
    stream_with_context(GLOBAL_BUS.stream()),
    mimetype='text/event-stream',
    headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no"
    },
)



if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, threaded=True)
