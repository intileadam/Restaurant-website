from __future__ import annotations
import csv
import io
import json, math, os, pathlib, re, secrets, socket, sys, threading, time as time_module
from datetime import date, datetime, timedelta, time as dt_time
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
    send_file,
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
from mailer.sse import GLOBAL_BUS, create_send_session, get_send_session, finish_send_session, evict_stale_sessions


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

CAMPAIGNS_DIR = pathlib.Path(os.getenv("CAMPAIGNS_DIR", str(APP_ROOT / "campaigns")))
CAMPAIGNS_DIR.mkdir(parents=True, exist_ok=True)
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
SCHEDULER_POLL_INTERVAL = int(os.getenv("SCHEDULER_POLL_INTERVAL", "10"))
SEND_SCHEDULER_ENABLED = os.getenv("SEND_SCHEDULER_ENABLED", "1").strip() not in ("0", "false", "no", "")
_scheduler_thread = None
_scheduler_last_tick = None

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
    "batch_size": int(os.getenv("DEFAULT_BATCH_SIZE", "25")),
    "delay_ms": int(os.getenv("DEFAULT_BATCH_DELAY_MS", "1000")),
    "batch_cooldown_seconds": int(os.getenv("DEFAULT_BATCH_COOLDOWN_SECONDS", "1200")),
    }

PACIFIC = ZoneInfo("America/Los_Angeles")
UTC = ZoneInfo("UTC")


def _pacific_time_str_to_utc(pacific_hhmm: str | None) -> str | None:
    """Convert a Pacific time string (HH:MM) to UTC (HH:MM) using today's date for DST. Used when saving restrict window."""
    if not pacific_hhmm:
        return None
    t = _parse_time_string(pacific_hhmm)
    if t is None:
        return None
    today = date.today()
    dt_pacific = datetime.combine(today, t, tzinfo=PACIFIC)
    dt_utc = dt_pacific.astimezone(UTC)
    return dt_utc.strftime("%H:%M")


def _utc_time_str_to_pacific_display(utc_hhmm: str | None) -> str:
    """Convert a UTC time string (HH:MM) to Pacific display e.g. '10:00 AM'. Returns empty string if invalid."""
    if not utc_hhmm:
        return ""
    t = _parse_time_string(utc_hhmm)
    if t is None:
        return ""
    today = date.today()
    dt_utc = datetime.combine(today, t, tzinfo=UTC)
    dt_pacific = dt_utc.astimezone(PACIFIC)
    pt = dt_pacific.time()
    h, m = pt.hour, pt.minute
    display_h = (h % 12) or 12
    ampm = "AM" if h < 12 else "PM"
    return f"{display_h}:{m:02d} {ampm}"


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
    """Return the next moment when the window opens in the given timezone."""
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
    """Block until current UTC time is inside the send window (stored times are UTC). Returns True if we had to sleep (waited)."""
    waited = False
    while True:
        now_utc = datetime.now(UTC)
        tod = now_utc.timetz().replace(tzinfo=None) if now_utc.tzinfo else now_utc.time()
        if _in_window(tod, restrict_start, restrict_end):
            return waited
        waited = True
        next_start = _next_window_start(now_utc, restrict_start, restrict_end, UTC)
        delta = (next_start - now_utc).total_seconds()
        if delta > 0:
            time_module.sleep(min(delta, 3600))
        else:
            time_module.sleep(60)


def estimate_completion_utc(
    recipient_count: int,
    delay_ms: int,
    restrict_start_s: str | None,
    restrict_end_s: str | None,
    *,
    batch_size: int = 0,
    cooldown_seconds: int = 0,
    seconds_until_first_batch: float = 0.0,
) -> datetime | None:
    """Estimate completion time (UTC). Accounts for batching and cooldown between batches.
    If restricted hours, walks through UTC windows (stored times are UTC)."""
    if recipient_count <= 0 or delay_ms < 0:
        return None
    restrict_start = _parse_time_string(restrict_start_s)
    restrict_end = _parse_time_string(restrict_end_s)
    delay_sec = delay_ms / 1000.0
    # Time from start until last email is sent: (N-1) gaps of delay_sec (no delay after the last email)
    total_send_sec = max(0.0, (recipient_count - 1) * delay_sec)
    # Cooldown between batches: (num_batches - 1) * cooldown_seconds
    num_batches = math.ceil(recipient_count / batch_size) if batch_size > 0 else 1
    total_cooldown_sec = (num_batches - 1) * cooldown_seconds if cooldown_seconds > 0 else 0
    total_seconds = seconds_until_first_batch + total_send_sec + total_cooldown_sec

    if restrict_start is None or restrict_end is None:
        return datetime.now(UTC) + timedelta(seconds=total_seconds)

    # Place send + cooldown time within send windows (time-based consumption).
    # When batching is used, cooldown is modeled as time consumed inside windows;
    # if a cooldown would span past window end in reality, this can slightly underestimate finish time.
    now_utc = datetime.now(UTC)
    t_utc = now_utc + timedelta(seconds=seconds_until_first_batch)
    remaining_seconds = total_send_sec + total_cooldown_sec
    while remaining_seconds > 0:
        tod = t_utc.timetz().replace(tzinfo=None) if t_utc.tzinfo else t_utc.time()
        if not _in_window(tod, restrict_start, restrict_end):
            t_utc = _next_window_start(t_utc, restrict_start, restrict_end, UTC)
            continue
        today = t_utc.date()
        end_dt = datetime.combine(today, restrict_end, tzinfo=UTC)
        if restrict_end <= restrict_start:
            end_dt += timedelta(days=1)
        window_sec = (end_dt - t_utc).total_seconds()
        if window_sec <= 0:
            t_utc = _next_window_start(t_utc, restrict_start, restrict_end, UTC)
            continue
        consume = min(remaining_seconds, window_sec)
        t_utc = t_utc + timedelta(seconds=consume)
        remaining_seconds -= consume
    return t_utc


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
    ctx = {
        "current_db_mode": getattr(g, "db_mode", CUSTOMER_MODE_DEFAULT),
        "csrf_token": _get_csrf_token,
    }
    if getattr(g, "user", None):
        try:
            ctx["customer_stats"] = dbmod.fetch_customer_subscription_stats()
        except Exception as exc:
            app.logger.warning("Unable to load customer subscription stats: %s", exc)
            ctx["customer_stats"] = None
    return ctx


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
    header_mode = _normalize_customer_mode(request.headers.get("X-DB-Mode"))
    query_mode = _normalize_customer_mode(request.args.get("db_mode"))
    request_mode = query_mode or header_mode
    if request_mode is not None:
        g.db_mode = request_mode
        dbmod.set_customer_table_mode(request_mode)
        session[CUSTOMER_MODE_SESSION_KEY] = request_mode

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
    """Home page: campaigns list."""
    mode_filter = request.args.get("mode")
    if mode_filter and mode_filter not in CUSTOMER_MODE_CHOICES:
        mode_filter = None
    try:
        sends = dbmod.fetch_campaign_history(mode_filter=mode_filter)
    except Exception as exc:
        app.logger.exception("Failed to load campaign history: %s", exc)
        sends = []
    return render_template("history.html", sends=sends, mode_filter=mode_filter or "all")


@app.get("/queue")
def queue_campaign():
    """Queue campaign workflow: select campaign, configure, send."""
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


@app.get("/users")
@app.get("/api/operators")
def list_operators():
    """Return current admins for the Manage admins modal (authenticated)."""
    try:
        rows = dbmod.list_service_users()
    except Exception as exc:
        app.logger.exception("list_operators: %s", exc)
        return jsonify({"ok": False, "error": "Unable to load operators."}), 500
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
            "last_login_at": last_login_at_iso,
            "last_login_at_iso": last_login_at_iso,
        })
    return jsonify({"ok": True, "users": out, "operators": out})


@app.get("/api/campaigns")
def api_campaigns_list():
    """Return list of campaign filenames for modal/dropdown refresh."""
    return jsonify({"files": list_campaign_files()})


@app.get("/campaigns/download")
def download_campaign():
    file_param = (request.args.get("file") or "").strip()
    if not file_param:
        return jsonify({"error": "No campaign file was specified."}), 400
    try:
        campaign_path = resolve_campaign_path(file_param)
        return send_file(
            campaign_path,
            as_attachment=True,
            download_name=campaign_path.name,
            mimetype="text/html",
        )
    except FileNotFoundError:
        return jsonify({"error": "Campaign file not found."}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.post("/campaigns/delete")
def delete_campaign():
    file_param = (request.form.get("file") or (request.get_json(silent=True) or {}).get("file") or "").strip()
    if not file_param:
        return jsonify({"error": "No campaign file was specified."}), 400
    try:
        campaign_path = resolve_campaign_path(file_param)
        campaign_path.unlink(missing_ok=False)
        return jsonify({"ok": True})
    except FileNotFoundError:
        return jsonify({"error": "Campaign file not found."}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except OSError as e:
        app.logger.exception("Failed to delete campaign file")
        return jsonify({"error": f"Unable to delete file: {e}"}), 500


@app.post("/campaigns/upload")
def upload_campaign():
    upload = request.files.get("campaign_file")
    desired_name = (request.form.get("filename") or "").strip()
    wants_json = _wants_json_response()

    if not upload or not upload.filename:
        if wants_json:
            return jsonify({"error": "Choose an HTML file to upload."}), 400
        flash("Choose an HTML file to upload.", "error")
        return redirect(url_for("queue_campaign"))

    try:
        filename = _sanitize_campaign_filename(desired_name or upload.filename)
    except ValueError as e:
        if wants_json:
            return jsonify({"error": str(e)}), 400
        flash(str(e), "error")
        return redirect(url_for("queue_campaign"))

    target_path = (CAMPAIGNS_DIR / filename).resolve()
    base = CAMPAIGNS_DIR.resolve()
    if base not in target_path.parents:
        if wants_json:
            return jsonify({"error": "Invalid upload path."}), 400
        flash("Invalid upload path.", "error")
        return redirect(url_for("queue_campaign"))

    if target_path.exists():
        if wants_json:
            return jsonify({"error": "A campaign with that name already exists."}), 409
        flash("A campaign with that name already exists.", "error")
        return redirect(url_for("queue_campaign"))

    try:
        CAMPAIGNS_DIR.mkdir(parents=True, exist_ok=True)
        upload.save(target_path)
    except Exception as e:
        if wants_json:
            return jsonify({"error": f"Unable to save campaign: {e}"}), 500
        flash(f"Unable to save campaign: {e}", "error")
        return redirect(url_for("queue_campaign"))

    if wants_json:
        return jsonify({"ok": True, "filename": filename})
    flash(f"Uploaded {filename}. It is now available in the campaign list.", "success")
    return redirect(url_for("queue_campaign"))


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
        return redirect(url_for("queue_campaign"))

    def success_response(message, email):
        if wants_json:
            return jsonify({"ok": True, "message": message, "email": email})
        flash(message, "success")
        return redirect(url_for("queue_campaign"))

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
    subscribed_raw = (request.args.get("subscribed") or "").strip().lower()
    subscribed_filter: bool | None = None
    if subscribed_raw in ("1", "true"):
        subscribed_filter = True
    elif subscribed_raw in ("0", "false"):
        subscribed_filter = False
    per_page = _parse_int(request.args.get("per_page"), 25, minimum=1, maximum=100)
    page = _parse_int(request.args.get("page"), 1, minimum=1, maximum=1000)
    offset = (page - 1) * per_page
    try:
        rows, total = dbmod.fetch_customers_paginated(
            search=search_term,
            tag_ids=tag_ids if tag_ids else None,
            subscribed=subscribed_filter,
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
                    subscribed=subscribed_filter,
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
    response = jsonify({"customers": serialized, "pagination": pagination, "search": search_term or ""})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/customers/<int:cust_id>")
def get_customer_api(cust_id: int):
    """Return one customer by id (for duplicate flows and deep links)."""
    query_mode = _normalize_customer_mode(request.args.get("db_mode"))
    if query_mode is not None:
        g.db_mode = query_mode
        dbmod.set_customer_table_mode(query_mode)
        session[CUSTOMER_MODE_SESSION_KEY] = query_mode
    try:
        row = dbmod.fetch_customer_by_id(cust_id)
    except Exception as e:
        app.logger.exception("fetch_customer_by_id(%s) failed", cust_id)
        return jsonify({"error": f"Database error: {e}"}), 500
    if not row:
        return jsonify({"error": "Customer not found."}), 404
    table = dbmod.get_customer_table_name()
    row["tags"] = dbmod.get_customer_tags(table, cust_id)
    out = _serialize_customer(row)
    if not out:
        return jsonify({"error": "Customer not found."}), 404
    response = jsonify({"customer": out})
    response.headers["Cache-Control"] = "no-store"
    return response


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
        existing_dup = None
        try:
            existing_dup = dbmod.fetch_customer_by_email(email)
        except Exception:
            app.logger.exception("fetch_customer_by_email after duplicate for %s", email)
        dup_id = None
        if existing_dup and existing_dup.get("CUSTID") is not None:
            dup_id = int(existing_dup["CUSTID"])
        return jsonify({
            "error": "A customer with this email already exists. No new record was created.",
            "existing_customer_id": dup_id,
        }), 409
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
        except Exception as e:
            app.logger.exception("Failed to save tags for customer %s", row["CUSTID"])
        row = dbmod.fetch_customer_by_id(row["CUSTID"])
        row["tags"] = dbmod.get_customer_tags(table, row["CUSTID"])

    _maybe_send_welcome_email(row["CUSTID"], is_subscribed=is_subscribed)

    return jsonify({"customer": _serialize_customer(row)}), 201


@app.post("/api/customers/import")
def import_customers_api():
    """Import customers from CSV. Columns: email (required), firstname, lastname, company, phone, comments, is_subscribed, tags (comma-separated).

    Form field ``on_duplicate``: ``skip`` (default) leaves existing rows unchanged; ``update`` overwrites fields for matching emails.
    """
    on_dup_raw = (request.form.get("on_duplicate") or request.args.get("on_duplicate") or "skip").strip().lower()
    on_duplicate = on_dup_raw if on_dup_raw in ("skip", "update") else "skip"
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
    skipped_existing = 0
    skipped_existing_rows: list[dict] = []
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
                if on_duplicate == "skip":
                    skipped_existing += 1
                    skipped_existing_rows.append({"row": row_num, "email": email})
                    continue
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
        "skipped_existing": skipped_existing,
        "skipped_existing_rows": skipped_existing_rows,
        "on_duplicate": on_duplicate,
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
    query_mode = _normalize_customer_mode(request.args.get("db_mode"))
    body_mode = _normalize_customer_mode(payload.get("db_mode"))
    request_mode = query_mode or body_mode
    if request_mode is not None:
        g.db_mode = request_mode
        dbmod.set_customer_table_mode(request_mode)
        session[CUSTOMER_MODE_SESSION_KEY] = request_mode
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

    try:
        existing = dbmod.fetch_customer_by_id(cust_id)
    except Exception as e:
        app.logger.exception("fetch_customer_by_id(%s) failed (table=%s, mode=%s)",
                             cust_id, dbmod.get_customer_table_name(), getattr(g, "db_mode", "unknown"))
        return jsonify({"error": f"Database error: {e}"}), 500
    if not existing:
        current_mode = getattr(g, "db_mode", "production")
        other_mode = "test" if current_mode == "production" else "production"
        dbmod.set_customer_table_mode(other_mode)
        try:
            existing = dbmod.fetch_customer_by_id(cust_id)
        except Exception:
            existing = None
        finally:
            if existing:
                app.logger.info("Customer %s found in %s table (request was using %s); syncing mode",
                                cust_id, other_mode, current_mode)
                g.db_mode = other_mode
                session[CUSTOMER_MODE_SESSION_KEY] = other_mode
            else:
                dbmod.set_customer_table_mode(current_mode)
        if not existing:
            app.logger.warning("Customer %s not found in table %s (mode=%s)",
                               cust_id, dbmod.get_customer_table_name(), getattr(g, "db_mode", "unknown"))
            return jsonify({"error": "Customer not found."}), 404

    if "is_subscribed" in payload:
        is_subscribed = _coerce_bool(payload.get("is_subscribed"), True)
    else:
        is_subscribed = _bool_from_db(existing.get("IS_SUBSCRIBED"))

    table_for_request = dbmod.get_customer_table_name()
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
        customer_table=table_for_request,
        )
        row = dbmod.fetch_customer_by_id(cust_id, customer_table=table_for_request)
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
        try:
            dbmod.set_customer_tags(table_for_request, cust_id, tag_names)
        except Exception as e:
            app.logger.exception("Failed to save tags for customer %s", cust_id)
            return jsonify({"error": f"Customer saved but tags failed to save: {e}"}), 500
        row["tags"] = dbmod.get_customer_tags(table_for_request, cust_id)

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


@app.patch("/api/customers/bulk")
def bulk_update_customers_api():
    """Bulk update customers. Body: customer_ids (list of int), add_tags?, remove_tags?, set_subscribed?, comment? (replaces)."""
    if not request.is_json:
        return jsonify({"error": "JSON body required."}), 400
    payload = request.get_json() or {}
    raw_ids = payload.get("customer_ids")
    if not isinstance(raw_ids, list):
        return jsonify({"error": "customer_ids must be a list."}), 400
    try:
        customer_ids = [int(x) for x in raw_ids if x is not None]
    except (TypeError, ValueError):
        return jsonify({"error": "customer_ids must be integers."}), 400
    if not customer_ids:
        return jsonify({"error": "customer_ids cannot be empty."}), 400

    add_tags = payload.get("add_tags")
    if add_tags is not None and not isinstance(add_tags, list):
        add_tags = None
    if add_tags is not None:
        add_tags = [str(t).strip() for t in add_tags if str(t).strip()]

    remove_tags = payload.get("remove_tags")
    if remove_tags is not None and not isinstance(remove_tags, list):
        remove_tags = None
    if remove_tags is not None:
        remove_tags = [str(t).strip() for t in remove_tags if str(t).strip()]

    set_subscribed = payload.get("set_subscribed")
    if set_subscribed is not None:
        set_subscribed = _coerce_bool(set_subscribed, True)

    comment = payload.get("comment")
    if comment is not None and not isinstance(comment, str):
        comment = None
    if comment is not None:
        comment = comment.strip()

    if not any([add_tags, remove_tags, set_subscribed is not None, comment is not None]):
        return jsonify({"error": "Provide at least one of: add_tags, remove_tags, set_subscribed, comment."}), 400

    table = dbmod.get_customer_table_name()
    updated = 0
    errors = []

    for cust_id in customer_ids:
        try:
            existing = dbmod.fetch_customer_by_id(cust_id, customer_table=table)
            if not existing:
                errors.append(f"Customer {cust_id} not found")
                continue

            if add_tags or remove_tags:
                current = dbmod.get_customer_tags(table, cust_id)
                names = [t.get("name") or "" for t in current if t.get("name")]
                names_set = set(names)
                for t in add_tags or []:
                    if t:
                        names_set.add(t)
                for t in remove_tags or []:
                    names_set.discard(t)
                dbmod.set_customer_tags(table, cust_id, list(names_set))

            if set_subscribed is not None or comment is not None:
                comments_new = comment if comment is not None else (existing.get("COMMENTS") or "")
                is_subscribed = set_subscribed if set_subscribed is not None else _bool_from_db(existing.get("IS_SUBSCRIBED"))
                dbmod.update_customer(
                    cust_id,
                    email=existing.get("EMAIL") or "",
                    firstname=existing.get("FIRSTNAME") or None,
                    lastname=existing.get("LASTNAME") or None,
                    company=existing.get("COMPANY") or None,
                    phone=existing.get("PHONE") or None,
                    comments=comments_new or None,
                    is_subscribed=is_subscribed,
                    customer_table=table,
                )
            updated += 1
        except dbmod.DuplicateCustomerError:
            errors.append(f"Customer {cust_id}: duplicate email")
        except Exception as e:
            app.logger.exception("Bulk update failed for customer %s", cust_id)
            errors.append(f"Customer {cust_id}: {e}")

    return jsonify({"updated": updated, "errors": errors})


@app.get("/tags")
def tags_page():
    """Render the tag management page (add/remove tags). Counts are all customers with the tag, not just subscribed."""
    try:
        all_tags = dbmod.list_tags(include_count=True, subscriber_aware=False)
    except Exception:
        all_tags = []
    return render_template("tags.html", all_tags=all_tags)


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
    return jsonify({"tag": {"id": tag["id"], "name": tag["name"], "customer_count": 0}}), 201


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
    cooldown_seconds: int | None = None,
    restrict_start: str | None = None,
    restrict_end: str | None = None,
    tag_names: list[str] | None = None,
):
    """Assemble the template context for the confirm page.
    When tag_names is None or empty, recipients = all subscribed ('Send to all').
    When tag_names is non-empty, recipients = subscribed customers with at least one of those tags (distinct).
    """
    if cooldown_seconds is None:
        cooldown_seconds = default_controls()["batch_cooldown_seconds"]
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
    if recipients:
        table = dbmod.get_customer_table_name()
        custids = [r["CUSTID"] for r in recipients]
        tags_by_cust = dbmod.fetch_tags_for_customers(table, custids)
        for r in recipients:
            r["tags"] = tags_by_cust.get(r["CUSTID"], [])
    recipient_count = len(recipients)
    num_batches = max(1, math.ceil(recipient_count / batch_size)) if recipient_count else 0
    total_cooldown = max(0, num_batches - 1) * cooldown_seconds
    # Send time: (N-1) delays between N emails
    send_time_sec = max(0, (recipient_count - 1) * (delay_ms / 1000))
    estimated_seconds = total_cooldown + send_time_sec
    # Confirm form uses Pacific; ETA expects UTC (same as stored in DB)
    restrict_start_utc = _pacific_time_str_to_utc(restrict_start) if restrict_start else None
    restrict_end_utc = _pacific_time_str_to_utc(restrict_end) if restrict_end else None
    eta_utc = estimate_completion_utc(
        recipient_count,
        delay_ms,
        restrict_start_utc,
        restrict_end_utc,
        batch_size=batch_size,
        cooldown_seconds=cooldown_seconds,
    )
    return {
        "file": file,
        "subject": subject,
        "recipient_count": recipient_count,
        "recipients": recipients,
        "batch_size": batch_size,
        "delay_ms": delay_ms,
        "cooldown_seconds": cooldown_seconds,
        "delay_seconds": int(delay_ms / 1000) if delay_ms else 0,
        "cooldown_minutes": int(cooldown_seconds / 60) if cooldown_seconds else 0,
        "restrict_start": restrict_start or "",
        "restrict_end": restrict_end or "",
        "lint_report": lint_report,
        "lint_has_errors": lint_has_errors,
        "lint_has_warnings": lint_has_warnings,
        "preview_html": preview_html,
        "preview_error": preview_error,
        "estimated_send_time": _format_duration(int(estimated_seconds)),
        "eta_utc_iso": eta_utc.isoformat() if eta_utc else None,
        "send_to": "all" if not tag_names else "tags",
        "tag_names": tag_names or [],
    }

@app.get("/confirm")
def confirm():
    file = (request.args.get("file") or "").strip()
    subject = request.args.get("subject")
    defaults = default_controls()
    batch_size = int(request.args.get("batch_size", defaults["batch_size"]))
    delay_seconds = _parse_int(request.args.get("delay_seconds"), int(defaults["delay_ms"] / 1000), minimum=0)
    delay_ms = delay_seconds * 1000
    cooldown_minutes = _parse_int(
        request.args.get("cooldown_minutes"),
        int(defaults["batch_cooldown_seconds"] / 60),
        minimum=0,
    )
    cooldown_seconds = cooldown_minutes * 60
    restrict_start = (request.args.get("restrict_start") or "").strip() or None
    restrict_end = (request.args.get("restrict_end") or "").strip() or None

    if not file:
        flash("No campaign file was selected.", "error")
        return redirect(url_for("queue_campaign"))
    try:
        context = _build_confirm_context(file, subject, batch_size, delay_ms, cooldown_seconds, restrict_start, restrict_end)
    except FileNotFoundError:
        flash("Campaign file not found.", "error")
        return redirect(url_for("queue_campaign"))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("queue_campaign"))
    except Exception as e:
        flash(f"Unable to prepare confirmation: {e}", "error")
        return redirect(url_for("queue_campaign"))

    if context["lint_has_errors"]:
        flash("Resolve lint errors before reviewing the live send.", "error")
        return redirect(url_for("queue_campaign"))

    all_tags = []
    try:
        all_tags = dbmod.list_tags(include_count=True)
    except Exception:
        pass

    return render_template("confirm.html", **context, sending=False, log_stream_token=None, all_tags=all_tags)


@app.post("/send")
@app.post("/queue")
def queue_campaign_post():
    file = (request.form.get("file") or "").strip()
    subject = request.form.get("subject")
    send_to = (request.form.get("send_to") or "all").strip().lower()
    tag_names = request.form.getlist("tag_names")
    tag_names = [n.strip() for n in tag_names if n and n.strip()] or None
    if send_to != "tags":
        tag_names = None
    defaults = default_controls()
    batch_size_raw = request.form.get("batch_size", defaults["batch_size"])
    delay_seconds = _parse_int(request.form.get("delay_seconds"), int(defaults["delay_ms"] / 1000), minimum=0)
    delay_ms = delay_seconds * 1000
    cooldown_minutes = _parse_int(
        request.form.get("cooldown_minutes"),
        int(defaults["batch_cooldown_seconds"] / 60),
        minimum=0,
    )
    cooldown_seconds = cooldown_minutes * 60
    restrict_start = (request.form.get("restrict_start") or "").strip() or None
    restrict_end = (request.form.get("restrict_end") or "").strip() or None

    if not file:
        flash("No campaign file was selected.", "error")
        return redirect(url_for("queue_campaign"))
    try:
        batch_size = int(batch_size_raw)
    except (TypeError, ValueError):
        flash("Batch size must be a whole number.", "error")
        return redirect(url_for("queue_campaign"))
    if not (BATCH_SIZE_MIN <= batch_size <= BATCH_SIZE_MAX):
        flash(f"Batch size must be between {BATCH_SIZE_MIN} and {BATCH_SIZE_MAX}.", "error")
        return redirect(url_for("queue_campaign"))
    try:
        context = _build_confirm_context(file, subject, batch_size, delay_ms, cooldown_seconds, restrict_start, restrict_end, tag_names=tag_names)
    except FileNotFoundError:
        flash("Campaign file not found.", "error")
        return redirect(url_for("queue_campaign"))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("queue_campaign"))
    except Exception as e:
        flash(f"Unable to prepare confirmation: {e}", "error")
        return redirect(url_for("queue_campaign"))

    if context["lint_has_errors"]:
        flash("Resolve lint errors before queuing the campaign.", "error")
        return redirect(url_for("confirm", file=file, subject=subject, batch_size=batch_size, delay_seconds=delay_seconds, cooldown_minutes=cooldown_minutes))

    # Validate restricted hours: both or neither, and valid
    start_s = (restrict_start or "").strip() or None
    end_s = (restrict_end or "").strip() or None
    if start_s is not None and end_s is not None:
        if _parse_time_string(start_s) is None or _parse_time_string(end_s) is None:
            flash("Restricted hours must be valid times (e.g. 10:00 and 22:00).", "error")
            return redirect(url_for("queue_campaign"))
        if _parse_time_string(start_s) == _parse_time_string(end_s):
            flash("Start and end times cannot be the same.", "error")
            return redirect(url_for("queue_campaign"))
    elif start_s is not None or end_s is not None:
        flash("Provide both start and end times for restricted hours, or leave both empty.", "error")
        return redirect(url_for("queue_campaign"))

    active = dbmod.fetch_active_send()
    if active:
        flash("A campaign is already queued or in progress.", "error")
        return redirect(url_for("campaign_history_detail", send_id=active["SEND_ID"]))

    mode = getattr(g, "db_mode", CUSTOMER_MODE_DEFAULT)
    recipients = context["recipients"]
    total = len(recipients)
    send_id = secrets.token_hex(16)

    # Store restricted send window in UTC so server (UTC) can compare directly
    restrict_start_utc = _pacific_time_str_to_utc(restrict_start) if restrict_start else None
    restrict_end_utc = _pacific_time_str_to_utc(restrict_end) if restrict_end else None

    try:
        dbmod.insert_campaign_send(
            send_id, file, subject, None, mode, total,
            batch_size=batch_size, delay_ms=delay_ms, cooldown_seconds=cooldown_seconds,
            restrict_start=restrict_start_utc,
            restrict_end=restrict_end_utc,
        )
        dbmod.bulk_insert_send_recipients(send_id, recipients)
        dbmod.activate_campaign_send(send_id)
    except Exception as exc:
        app.logger.exception("Failed to queue campaign send: %s", exc)
        flash("Unable to queue campaign. Please try again.", "error")
        return redirect(url_for("queue_campaign"))

    sess = create_send_session(send_id, file, subject, mode, total)
    _ensure_scheduler()

    return redirect(url_for("campaign_history_detail", send_id=send_id))


@app.get("/send/<send_id>/status")
def send_status(send_id: str):
    send_row = dbmod.get_send_status(send_id)
    if not send_row:
        flash("Send not found.", "error")
        return redirect(url_for("queue_campaign"))
    return redirect(url_for("campaign_history_detail", send_id=send_id))


@app.get("/send/<send_id>/logs")
def send_logs_json(send_id: str):
    sess = get_send_session(send_id)
    if sess:
        return jsonify({
            "status": sess.status,
            "logs": sess.bus.history,
            "sent": sess.sent_count,
            "failed": sess.failed_count,
            "total": sess.total_count,
        })
    send_row, results = dbmod.fetch_campaign_detail(send_id)
    if not send_row:
        return jsonify({"error": "Send session not found."}), 404
    log_lines = []
    for r in results:
        if r["STATUS"] == "sent":
            log_lines.append(f"✔ Sent to {r['EMAIL']}")
        else:
            err = r.get("ERROR_MESSAGE") or "unknown error"
            log_lines.append(f"✖ Failed for {r['EMAIL']}: {err}")
    sent = int(send_row.get("SENT_COUNT", 0))
    failed = int(send_row.get("FAILED_COUNT", 0))
    total = int(send_row.get("TOTAL_RECIPIENTS", 0))
    log_lines.append(f"Done. Sent {sent}/{total}.")
    return jsonify({"status": send_row.get("STATUS", "completed"), "logs": log_lines, "sent": sent, "failed": failed, "total": total})


@app.get("/send/<send_id>/progress")
def send_progress(send_id: str):
    row = dbmod.get_send_status(send_id)
    if not row:
        return jsonify({"error": "Send not found."}), 404
    counts = dbmod.count_send_results(send_id)
    total = int(row.get("TOTAL_RECIPIENTS") or 0)
    sent = int(row.get("SENT_COUNT") or 0)
    failed = int(row.get("FAILED_COUNT") or 0)
    pending = counts.get("pending", 0)
    delay_ms = int(row.get("DELAY_MS") or 0)
    restrict_start_s = (row.get("RESTRICT_START") or "").strip() or None
    restrict_end_s = (row.get("RESTRICT_END") or "").strip() or None

    batch_size = int(row.get("BATCH_SIZE") or 0)
    cooldown_seconds = int(row.get("COOLDOWN_SECONDS") or 0)
    last_batch_at = row.get("LAST_BATCH_AT")
    now_utc = datetime.now(UTC)
    seconds_until_first_batch = 0.0
    if pending > 0 and cooldown_seconds > 0 and isinstance(last_batch_at, datetime):
        # Last batch at from DB is typically naive UTC; make it comparable to now_utc
        lb = last_batch_at if last_batch_at.tzinfo else last_batch_at.replace(tzinfo=UTC)
        next_batch_at = lb + timedelta(seconds=cooldown_seconds)
        if next_batch_at > now_utc:
            seconds_until_first_batch = (next_batch_at - now_utc).total_seconds()

    eta_utc_iso = None
    status = row["STATUS"]
    if status in ("running", "paused", "queued") and pending > 0 and delay_ms >= 0:
        eta_utc = estimate_completion_utc(
            pending,
            delay_ms,
            restrict_start_s,
            restrict_end_s,
            batch_size=batch_size,
            cooldown_seconds=cooldown_seconds,
            seconds_until_first_batch=seconds_until_first_batch,
        )
        if eta_utc:
            eta_utc_iso = eta_utc.isoformat()

    payload = {
        "send_id": send_id,
        "status": status,
        "total": total,
        "sent": sent,
        "failed": failed,
        "pending": pending,
        "batch_size": int(row.get("BATCH_SIZE") or 0),
        "delay_ms": delay_ms,
        "cooldown_seconds": int(row.get("COOLDOWN_SECONDS") or 0),
        "started_at": (row.get("STARTED_AT").isoformat() + "Z") if row.get("STARTED_AT") else None,
        "finished_at": (row.get("FINISHED_AT").isoformat() + "Z") if row.get("FINISHED_AT") else None,
        "last_batch_at": (row.get("LAST_BATCH_AT").isoformat() + "Z") if row.get("LAST_BATCH_AT") else None,
        "restrict_start": restrict_start_s or "",
        "restrict_end": restrict_end_s or "",
        "restrict_start_display": _utc_time_str_to_pacific_display(restrict_start_s) if restrict_start_s else "",
        "restrict_end_display": _utc_time_str_to_pacific_display(restrict_end_s) if restrict_end_s else "",
        "eta_utc_iso": eta_utc_iso,
    }
    return jsonify(payload)


@app.post("/send/<send_id>/pause")
def pause_send_route(send_id: str):
    changed = dbmod.pause_send(send_id)
    if not changed:
        return jsonify({"ok": False, "message": "Send is not currently running."}), 409
    sess = get_send_session(send_id)
    if sess:
        sess.status = "paused"
        sess.bus.emit("⏸ Send paused by operator")
    return jsonify({"ok": True, "status": "paused"})


@app.post("/send/<send_id>/resume")
def resume_send_route(send_id: str):
    changed = dbmod.resume_send(send_id)
    if not changed:
        return jsonify({"ok": False, "message": "Send is not currently paused."}), 409
    sess = get_send_session(send_id)
    if sess:
        sess.status = "running"
        sess.bus.emit("▶ Send resumed by operator")
    _ensure_scheduler()
    return jsonify({"ok": True, "status": "running"})


@app.post("/send/<send_id>/cancel")
def cancel_send_route(send_id: str):
    changed = dbmod.cancel_send(send_id)
    if not changed:
        return jsonify({"ok": False, "message": "Send cannot be cancelled in its current state."}), 409
    sess = get_send_session(send_id)
    if sess:
        finish_send_session(send_id, "cancelled", sess.sent_count, sess.failed_count)
        sess.bus.emit("✖ Send cancelled by operator")
    return jsonify({"ok": True, "status": "cancelled"})


@app.patch("/send/<send_id>/controls")
def update_send_controls_route(send_id: str):
    data = request.get_json(silent=True) or {}
    batch_size = data.get("batch_size")
    delay_ms = data.get("delay_ms")
    cooldown_seconds = data.get("cooldown_seconds")
    if batch_size is not None:
        batch_size = max(1, int(batch_size))
    if delay_ms is not None:
        delay_ms = max(0, int(delay_ms))
    if cooldown_seconds is not None:
        cooldown_seconds = max(0, int(cooldown_seconds))
    row = dbmod.get_send_status(send_id)
    if not row:
        return jsonify({"ok": False, "message": "Send not found."}), 404
    if row["STATUS"] not in ("running", "paused", "queued"):
        return jsonify({"ok": False, "message": "Send is already finished."}), 409
    dbmod.update_send_controls(send_id, batch_size=batch_size, delay_ms=delay_ms, cooldown_seconds=cooldown_seconds)
    sess = get_send_session(send_id)
    if sess and sess.bus:
        parts = []
        if batch_size is not None:
            parts.append(f"batch_size={batch_size}")
        if delay_ms is not None:
            parts.append(f"delay={delay_ms}ms")
        if cooldown_seconds is not None:
            parts.append(f"cooldown={_format_cooldown(cooldown_seconds)}")
        if parts:
            sess.bus.emit(f"⚙ Controls updated: {', '.join(parts)}")
    return jsonify({"ok": True})


@app.get("/send/<send_id>/recipients")
def send_recipients_route(send_id: str):
    status_filter = request.args.get("status")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    rows, total = dbmod.fetch_send_recipients_paginated(send_id, status_filter=status_filter, limit=limit, offset=offset)
    result = []
    for r in rows:
        entry = {
            "id": r["ID"], "email": r["EMAIL"], "firstname": r.get("FIRSTNAME"),
            "lastname": r.get("LASTNAME"), "status": r["STATUS"], "error": r.get("ERROR_MESSAGE"),
        }
        at = r.get("ATTEMPTED_AT")
        entry["attempted_at"] = at.isoformat() if at else None
        result.append(entry)
    return jsonify({"recipients": result, "total": total, "limit": limit, "offset": offset})


@app.get("/scheduler/health")
def scheduler_health():
    thread_alive = _scheduler_thread is not None and _scheduler_thread.is_alive()
    if _scheduler_last_tick is not None:
        seconds_since = time_module.monotonic() - _scheduler_last_tick
    else:
        seconds_since = None
    thread_recent = (
        thread_alive and seconds_since is not None and seconds_since < (SCHEDULER_POLL_INTERVAL * 2)
    )
    try:
        active_send = dbmod.fetch_active_send()
    except Exception:
        active_send = None
    alive = thread_recent or (active_send is not None)
    return jsonify({
        "alive": alive, "thread_alive": thread_alive, "thread_recent": thread_recent,
        "has_active_campaign": active_send is not None,
        "seconds_since_last_tick": round(seconds_since, 1) if seconds_since is not None else None,
        "poll_interval": SCHEDULER_POLL_INTERVAL,
    })


@app.get("/api/active-send")
def active_send_api():
    row = dbmod.fetch_active_send()
    if not row:
        return jsonify({"send_id": None})
    return jsonify({
        "send_id": row["SEND_ID"], "campaign_file": row["CAMPAIGN_FILE"],
        "subject": row.get("SUBJECT"), "campaign_name": row.get("CAMPAIGN_NAME"),
        "status": row["STATUS"], "total_recipients": int(row.get("TOTAL_RECIPIENTS") or 0),
        "sent_count": int(row.get("SENT_COUNT") or 0), "failed_count": int(row.get("FAILED_COUNT") or 0),
    })


@app.get("/api/customer-stats")
def customer_subscription_stats_api():
    """Return subscriber / total / unsubscribed counts for the current DB mode (session)."""
    try:
        stats = dbmod.fetch_customer_subscription_stats()
    except Exception as exc:
        app.logger.warning("Unable to load customer subscription stats: %s", exc)
        return jsonify({"error": "Unable to load stats."}), 500
    return jsonify(
        {
            "subscribed": stats["subscribed"],
            "total": stats["total"],
            "unsubscribed": stats["unsubscribed"],
        }
    )


@app.get("/api/recipients/count")
def recipients_count_api():
    """Return the count of subscribed recipients, optionally filtered by tag names."""
    tag_names_raw = request.args.get("tag_names", "").strip()
    tag_names = [n.strip() for n in tag_names_raw.split(",") if n.strip()] if tag_names_raw else None
    try:
        rows = dbmod.fetch_subscribed_customers(tag_names=tag_names)
        return jsonify({"count": len(rows)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/recipients/list")
def recipients_list_api():
    """Return subscribed recipients for confirm preview, optionally filtered by tag names. Includes tags per recipient."""
    tag_names_raw = request.args.get("tag_names", "").strip()
    tag_names = [n.strip() for n in tag_names_raw.split(",") if n.strip()] if tag_names_raw else None
    try:
        rows = dbmod.fetch_subscribed_customers(tag_names=tag_names) or []
        if rows:
            table = dbmod.get_customer_table_name()
            custids = [r["CUSTID"] for r in rows]
            tags_by_cust = dbmod.fetch_tags_for_customers(table, custids)
            for r in rows:
                r["tags"] = tags_by_cust.get(r["CUSTID"], [])
        for r in rows:
            if "tags" not in r:
                r["tags"] = []
        out = [
            {
                "id": r["CUSTID"],
                "firstname": r.get("FIRSTNAME") or "",
                "lastname": r.get("LASTNAME") or "",
                "email": r.get("EMAIL") or "",
                "tags": [{"id": t.get("id"), "name": t.get("name", "")} for t in r.get("tags", [])],
            }
            for r in rows
        ]
        return jsonify({"recipients": out})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/logs/stream")
def logs_stream():
    token = (request.args.get("token") or "").strip()
    payload = _validate_log_stream_token(token)
    if not payload:
        return Response("Unauthorized", status=401)
    send_id = payload.get("send_id")
    if not send_id:
        return Response(
            stream_with_context(GLOBAL_BUS.stream()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    sess = get_send_session(send_id)
    if not sess:
        return Response("Send session not found or expired", status=404)
    subscriber_q = sess.bus.subscribe()
    return Response(
        stream_with_context(sess.bus.stream(subscriber_q)),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Campaign history ─────────────────────────────────────────────


@app.get("/history")
def campaign_history():
    """Redirect to home (campaigns list); preserve query params."""
    return redirect(url_for("index", **request.args))


@app.post("/history/<send_id>/archive")
def archive_campaign(send_id: str):
    """Mark a campaign send as archived so it no longer appears on the front page."""
    try:
        updated = dbmod.archive_campaign_send(send_id)
    except Exception as exc:
        app.logger.exception("Failed to archive campaign %s: %s", send_id, exc)
        flash("Unable to archive campaign.", "error")
        return redirect(url_for("index", **request.args))
    if updated:
        flash("Campaign archived. It will no longer appear in the list.", "success")
    else:
        flash("Campaign not found or already archived.", "error")
    return redirect(url_for("index", **request.args))


@app.get("/history/<send_id>")
def campaign_history_detail(send_id: str):
    try:
        send_row, results = dbmod.fetch_campaign_detail(send_id)
    except Exception as exc:
        app.logger.exception("Failed to load campaign detail: %s", exc)
        flash("Unable to load campaign detail.", "error")
        return redirect(url_for("campaign_history"))

    if not send_row:
        flash("Campaign send not found.", "error")
        return redirect(url_for("campaign_history"))

    status_filter = request.args.get("status")
    if status_filter and status_filter not in ("sent", "failed", "pending"):
        status_filter = None

    filtered_results = results
    if status_filter:
        filtered_results = [r for r in results if r["STATUS"] == status_filter]

    # Stored restrict times are UTC; surface Pacific for display
    restrict_start_display = ""
    restrict_end_display = ""
    if send_row.get("RESTRICT_START") and send_row.get("RESTRICT_END"):
        restrict_start_display = _utc_time_str_to_pacific_display((send_row.get("RESTRICT_START") or "").strip())
        restrict_end_display = _utc_time_str_to_pacific_display((send_row.get("RESTRICT_END") or "").strip())

    return render_template(
        "history_detail.html",
        send=send_row,
        results=filtered_results,
        all_results=results,
        status_filter=status_filter or "all",
        restrict_start_display=restrict_start_display,
        restrict_end_display=restrict_end_display,
    )


# ── Scheduler ────────────────────────────────────────────────────


def _ensure_scheduler():
    global _scheduler_thread
    if _scheduler_thread is not None and _scheduler_thread.is_alive():
        return
    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    _scheduler_thread.start()


def _scheduler_loop():
    global _scheduler_last_tick
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    while True:
        time_module.sleep(SCHEDULER_POLL_INTERVAL)
        _scheduler_last_tick = time_module.monotonic()
        try:
            evict_stale_sessions()
            with app.app_context():
                sends = dbmod.fetch_ready_sends()
                for send_row in sends:
                    send_id = send_row["SEND_ID"]
                    if not dbmod.claim_send(send_id, worker_id):
                        continue
                    try:
                        _process_one_batch(send_row)
                    except Exception:
                        app.logger.exception("Error processing batch for send %s", send_id)
                    finally:
                        dbmod.release_claim(send_id)
        except Exception:
            app.logger.exception("Scheduler tick failed; will retry next tick")


def _process_one_batch(send_row: dict):
    send_id = send_row["SEND_ID"]
    file = send_row["CAMPAIGN_FILE"]
    subject = send_row.get("SUBJECT") or ""
    mode = send_row.get("MODE", CUSTOMER_MODE_DEFAULT)
    batch_size = int(send_row.get("BATCH_SIZE") or 25)
    delay_ms = int(send_row.get("DELAY_MS") or 0)
    sent_count = int(send_row.get("SENT_COUNT") or 0)
    failed_count = int(send_row.get("FAILED_COUNT") or 0)

    sess = get_send_session(send_id)
    bus = sess.bus if sess else None

    def emit(text: str):
        if bus:
            bus.emit(text)

    # If restricted send hours are set, wait until we're inside the window (Pacific)
    restrict_start_s = (send_row.get("RESTRICT_START") or "").strip() or None
    restrict_end_s = (send_row.get("RESTRICT_END") or "").strip() or None
    if restrict_start_s and restrict_end_s:
        r_start = _parse_time_string(restrict_start_s)
        r_end = _parse_time_string(restrict_end_s)
        if r_start is not None and r_end is not None and r_start != r_end:
            waited = _sleep_until_in_window(r_start, r_end)
            if waited and bus:
                bus.emit("Resumed within restricted send window.")

    batch = dbmod.fetch_pending_recipients(send_id, limit=batch_size)
    if not batch:
        emit(f"Done. Sent {sent_count}/{send_row.get('TOTAL_RECIPIENTS', 0)}.")
        dbmod.update_campaign_send_finished(send_id, "completed", sent_count, failed_count)
        if sess:
            finish_send_session(send_id, "completed", sent_count, failed_count)
        return

    dbmod.set_customer_table_mode(mode)
    try:
        candidate = resolve_campaign_path(file)
        raw_html = load_campaign_html(candidate)
        raw_html = ensure_unsubscribe(raw_html)

        smtp = SmtpClient()
        emit(f"Batch: {len(batch)} recipients (batch_size={batch_size}, delay={delay_ms}ms)")

        with smtp.open_connection() as conn:
            for r in batch:
                result_id = r["ID"]
                to_addr = r["EMAIL"].strip()
                firstname = r.get("FIRSTNAME")
                lastname = r.get("LASTNAME")
                custid = r.get("CUSTID")

                try:
                    token = dbmod.ensure_unsubscribe_token(custid, None)
                except Exception as e:
                    emit(f"✖ Missing unsubscribe token for {to_addr}: {e}")
                    failed_count += 1
                    dbmod.mark_recipient_failed(result_id, str(e))
                    continue

                html = render_for_recipient(raw_html, firstname, lastname, token, mode=mode)
                try:
                    msg = smtp.build_message(to_addr, subject, html)
                    conn.send(msg, delay_ms=delay_ms)
                    sent_count += 1
                    emit(f"✔ Sent to {to_addr}")
                    dbmod.mark_recipient_sent(result_id)
                except Exception as e:
                    failed_count += 1
                    emit(f"✖ Failed for {to_addr}: {e}")
                    dbmod.mark_recipient_failed(result_id, str(e))

        dbmod.update_send_progress(send_id, sent_count, failed_count)
        if sess:
            sess.sent_count = sent_count
            sess.failed_count = failed_count

        remaining = dbmod.fetch_pending_recipients(send_id, limit=1)
        if not remaining:
            total = int(send_row.get("TOTAL_RECIPIENTS") or 0)
            emit(f"Done. Sent {sent_count}/{total}.")
            dbmod.update_campaign_send_finished(send_id, "completed", sent_count, failed_count)
            if sess:
                finish_send_session(send_id, "completed", sent_count, failed_count)
    finally:
        dbmod.clear_customer_table_mode()


def _format_cooldown(seconds: int) -> str:
    if seconds <= 0:
        return "none"
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    remaining = seconds % 60
    if remaining:
        return f"{minutes}m {remaining}s"
    return f"{minutes}m"


def _format_duration(seconds: int) -> str:
    if seconds < 60:
        return "under 1 minute"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    if hours and minutes:
        return f"~{hours}h {minutes}m"
    if hours:
        return f"~{hours}h"
    return f"~{minutes}m"


def _is_gunicorn():
    return "gunicorn" in os.getenv("SERVER_SOFTWARE", "")


with app.app_context():
    try:
        dbmod.ensure_tag_tables()
    except Exception as exc:
        print(f"WARNING: Could not create tag tables: {exc}", file=sys.stderr)
    try:
        dbmod.ensure_campaign_tables()
    except Exception as exc:
        print(f"WARNING: Could not create campaign history tables: {exc}", file=sys.stderr)

    server_software = os.getenv("SERVER_SOFTWARE", "").strip()
    if SEND_SCHEDULER_ENABLED and (_is_gunicorn() or APP_ENV != "production"):
        app.logger.info("Starting send scheduler thread")
        _ensure_scheduler()
    else:
        app.logger.info("Send scheduler startup skipped")


if __name__ == "__main__":
    if SEND_SCHEDULER_ENABLED:
        app.logger.info("Starting send scheduler thread in __main__")
        _ensure_scheduler()
    app.run(debug=True, use_reloader=False, threaded=True)
