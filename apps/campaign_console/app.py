from __future__ import annotations
import csv, io, math, os, pathlib, re, secrets, socket, sys, threading, time
from datetime import datetime, timedelta
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
    send_from_directory,
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
from mailer.sse import (
    create_send_session,
    get_send_session,
    finish_send_session,
    evict_stale_sessions,
)

def _normalized_app_env() -> str:
    value = os.getenv("APP_ENV", "development") or "development"
    return value.strip().lower() or "development"

APP_ENV = _normalized_app_env()


def _env_flag(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip().lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    return default


SEND_SCHEDULER_ENABLED = _env_flag("SEND_SCHEDULER_ENABLED", True)

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
CAMPAIGN_IMAGES_DIR = pathlib.Path(os.getenv("CAMPAIGN_IMAGES_DIR", str(APP_ROOT / "campaign_images")))
CAMPAIGN_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
MAX_IMAGE_SIZE_BYTES = int(os.getenv("MAX_IMAGE_SIZE_BYTES", str(5 * 1024 * 1024)))
DISK_QUOTA_BYTES = int(os.getenv("DISK_QUOTA_BYTES", str(1024 * 1024 * 1024)))
DEFAULT_INDIVIDUAL_EMAIL_TEMPLATE = os.getenv("WELCOME_EMAIL_TEMPLATE", "welcome.html")
LOGIN_SESSION_KEY = "auth_user_id"
MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("AUTH_MAX_FAILED_ATTEMPTS", "5"))
LOCKOUT_MINUTES = int(os.getenv("AUTH_LOCKOUT_MINUTES", "15"))
SESSION_LIFETIME_HOURS = int(os.getenv("AUTH_SESSION_HOURS", "12"))
APP_PORTAL_HOSTNAME = os.getenv("APP_PORTAL_HOSTNAME", "console.casadelpollo.com")
MIN_PASSWORD_LENGTH = int(os.getenv("AUTH_MIN_PASSWORD_LENGTH", "12"))
PUBLIC_ENDPOINTS = {"login", "static", "logs_stream", "campaign_images"}
CUSTOMER_MODE_SESSION_KEY = "customer_table_mode"
CUSTOMER_MODE_DEFAULT = "production"
CUSTOMER_MODE_CHOICES = {"production", "test"}
LOG_STREAM_TOKEN_TTL_SECONDS = int(os.getenv("LOG_STREAM_TOKEN_TTL_SECONDS", "3600"))
LOG_STREAM_TOKEN_SALT = "logs-stream-token"
SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
SCHEDULER_POLL_INTERVAL = 5
_scheduler_thread: threading.Thread | None = None
_scheduler_last_tick: float | None = None
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


def _sanitize_image_filename(raw_name: str) -> str:
    """Normalize and validate image filenames."""
    candidate = (raw_name or "").strip()
    if not candidate:
        raise ValueError("Please provide a file name.")
    filename = secure_filename(candidate)
    if not filename:
        raise ValueError("Invalid file name.")
    _stem, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext not in ALLOWED_IMAGE_EXTS:
        allowed = ", ".join(sorted(ALLOWED_IMAGE_EXTS))
        raise ValueError(f"Image must be one of: {allowed}")
    return filename


def _image_public_url(filename: str) -> str:
    """Build the public URL for a campaign image."""
    scheme = "https" if _is_production_env() else request.scheme
    return f"{scheme}://{APP_PORTAL_HOSTNAME}/campaign-images/{filename}"


def _dir_size_bytes(*dirs: pathlib.Path) -> int:
    """Sum the size of all files in the given directories."""
    total = 0
    for d in dirs:
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.is_file():
                total += f.stat().st_size
    return total


def _human_bytes(n: int) -> str:
    """Format byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} GB"

def default_controls():
    return {
    "batch_size": int(os.getenv("DEFAULT_BATCH_SIZE", "25")),
    "delay_ms": int(os.getenv("DEFAULT_BATCH_DELAY_MS", "500")),
    "batch_cooldown_seconds": int(os.getenv("DEFAULT_BATCH_COOLDOWN_SECONDS", "1200")),
    }


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


def _generate_log_stream_token(mode: str, send_id: str) -> str:
    payload = {
        "purpose": "logs-stream",
        "mode": mode or CUSTOMER_MODE_DEFAULT,
        "send_id": send_id,
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
    return {
        "id": row.get("CUSTID"),
        "firstname": row.get("FIRSTNAME") or "",
        "lastname": row.get("LASTNAME") or "",
        "email": row.get("EMAIL") or "",
        "company": row.get("COMPANY") or "",
        "phone": row.get("PHONE") or "",
        "comments": row.get("COMMENTS") or "",
        "is_subscribed": _bool_from_db(row.get("IS_SUBSCRIBED")),
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


@app.get("/users")
def list_operators():
    """Return the list of operator accounts as JSON."""
    try:
        rows = dbmod.list_service_users()
    except Exception as exc:
        app.logger.exception("Unable to list operators: %s", exc)
        return jsonify({"ok": False, "message": "Unable to load admin list."}), 500

    users = []
    for row in rows:
        last_login = row.get("last_login_at")
        users.append({
            "id": row["id"],
            "username": row["username"],
            "role": row.get("role", "admin"),
            "is_active": bool(row.get("is_active")),
            "last_login_at": last_login.isoformat() if last_login else None,
        })
    return jsonify({"ok": True, "users": users})


@app.post("/users/password")
def change_own_password():
    """Change the current user's password."""
    redirect_target = url_for("index")
    wants_json = _wants_json_response()

    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    new_password_confirm = request.form.get("new_password_confirm") or ""

    if not current_password or not new_password:
        msg = "All password fields are required."
        if wants_json:
            return jsonify({"ok": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(redirect_target)

    if new_password != new_password_confirm:
        msg = "New passwords do not match."
        if wants_json:
            return jsonify({"ok": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(redirect_target)

    if len(new_password) < MIN_PASSWORD_LENGTH:
        msg = f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        if wants_json:
            return jsonify({"ok": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(redirect_target)

    # Re-fetch the full user row (with password hash) to verify current password.
    try:
        user_row = dbmod.fetch_user_by_username(g.user["username"])
    except Exception as exc:
        app.logger.exception("Unable to fetch user for password change: %s", exc)
        msg = "Unable to change password right now. Please try again."
        if wants_json:
            return jsonify({"ok": False, "message": msg}), 500
        flash(msg, "error")
        return redirect(redirect_target)

    if not user_row or not _password_matches(user_row, current_password):
        msg = "Current password is incorrect."
        if wants_json:
            return jsonify({"ok": False, "message": msg}), 403
        flash(msg, "error")
        return redirect(redirect_target)

    try:
        hashed = generate_password_hash(new_password, method="pbkdf2:sha256", salt_length=16)
    except Exception as exc:
        app.logger.exception("Failed to hash new password: %s", exc)
        msg = "Unable to hash password."
        if wants_json:
            return jsonify({"ok": False, "message": msg}), 500
        flash(msg, "error")
        return redirect(redirect_target)

    try:
        dbmod.update_service_user_password(
            g.user["id"],
            password_hash=hashed,
            password_algo="pbkdf2_sha256",
        )
    except Exception as exc:
        app.logger.exception("Unable to update password: %s", exc)
        msg = "Unable to change password right now. Please try again."
        if wants_json:
            return jsonify({"ok": False, "message": msg}), 500
        flash(msg, "error")
        return redirect(redirect_target)

    msg = "Password changed successfully."
    if wants_json:
        return jsonify({"ok": True, "message": msg})
    flash(msg, "success")
    return redirect(redirect_target)


@app.post("/campaigns/upload")
def upload_campaign():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    upload = request.files.get("campaign_file")
    desired_name = (request.form.get("filename") or "").strip()

    if not upload or not upload.filename:
        msg = "Choose an HTML file to upload."
        if is_ajax:
            return jsonify({"ok": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("index"))

    try:
        filename = _sanitize_campaign_filename(desired_name or upload.filename)
    except ValueError as e:
        if is_ajax:
            return jsonify({"ok": False, "message": str(e)}), 400
        flash(str(e), "error")
        return redirect(url_for("index"))

    target_path = (CAMPAIGNS_DIR / filename).resolve()
    base = CAMPAIGNS_DIR.resolve()
    if base not in target_path.parents:
        msg = "Invalid upload path."
        if is_ajax:
            return jsonify({"ok": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("index"))

    if target_path.exists():
        msg = "A campaign with that name already exists."
        if is_ajax:
            return jsonify({"ok": False, "message": msg}), 409
        flash(msg, "error")
        return redirect(url_for("index"))

    try:
        CAMPAIGNS_DIR.mkdir(parents=True, exist_ok=True)
        upload.save(target_path)
    except Exception as e:
        msg = f"Unable to save campaign: {e}"
        if is_ajax:
            return jsonify({"ok": False, "message": msg}), 500
        flash(msg, "error")
        return redirect(url_for("index"))

    msg = f"Uploaded {filename}. It is now available in the campaign list."
    if is_ajax:
        return jsonify({"ok": True, "message": msg, "filename": filename})
    flash(msg, "success")
    return redirect(url_for("index"))


@app.get("/api/campaigns")
def api_list_campaigns():
    return jsonify(list_campaign_files())


@app.delete("/api/campaigns/<filename>")
def api_delete_campaign(filename):
    filename = (filename or "").strip()
    if not filename:
        return jsonify({"ok": False, "message": "No filename provided."}), 400

    base = CAMPAIGNS_DIR.resolve()
    target_path = (CAMPAIGNS_DIR / filename).resolve()

    if base not in target_path.parents:
        return jsonify({"ok": False, "message": "Invalid file path."}), 400

    if not target_path.is_file():
        return jsonify({"ok": False, "message": "File not found."}), 404

    try:
        target_path.unlink()
    except Exception as e:
        app.logger.exception("Unable to delete campaign %s: %s", filename, e)
        return jsonify({"ok": False, "message": f"Unable to delete file: {e}"}), 500

    return jsonify({"ok": True, "message": f"Deleted {filename}."})


# ── campaign images ──────────────────────────────────────────────


@app.get("/campaign-images/<filename>")
def campaign_images(filename):
    """Serve an uploaded campaign image (public, no auth)."""
    safe = secure_filename(filename)
    if not safe:
        abort(404)
    return send_from_directory(CAMPAIGN_IMAGES_DIR, safe, max_age=86400)


@app.get("/api/campaign-images")
def api_list_campaign_images():
    images = []
    for f in sorted(CAMPAIGN_IMAGES_DIR.iterdir(), key=lambda p: p.name.lower()):
        if f.is_file() and f.suffix.lower() in ALLOWED_IMAGE_EXTS:
            images.append({
                "filename": f.name,
                "url": _image_public_url(f.name),
                "size_bytes": f.stat().st_size,
            })
    return jsonify(images)


@app.post("/api/campaign-images/upload")
def api_upload_campaign_image():
    upload = request.files.get("image_file")
    desired_name = (request.form.get("filename") or "").strip()

    if not upload or not upload.filename:
        return jsonify({"ok": False, "message": "Choose an image file to upload."}), 400

    try:
        filename = _sanitize_image_filename(desired_name or upload.filename)
    except ValueError as e:
        return jsonify({"ok": False, "message": str(e)}), 400

    upload.seek(0, 2)
    size = upload.tell()
    upload.seek(0)
    if size > MAX_IMAGE_SIZE_BYTES:
        limit_mb = MAX_IMAGE_SIZE_BYTES / (1024 * 1024)
        return jsonify({"ok": False, "message": f"Image exceeds {limit_mb:.0f} MB limit."}), 400

    target_path = (CAMPAIGN_IMAGES_DIR / filename).resolve()
    base = CAMPAIGN_IMAGES_DIR.resolve()
    if base not in target_path.parents:
        return jsonify({"ok": False, "message": "Invalid upload path."}), 400

    if target_path.exists():
        return jsonify({"ok": False, "message": "An image with that name already exists."}), 409

    try:
        upload.save(target_path)
    except Exception as e:
        app.logger.exception("Unable to save image %s: %s", filename, e)
        return jsonify({"ok": False, "message": f"Unable to save image: {e}"}), 500

    return jsonify({
        "ok": True,
        "message": f"Uploaded {filename}.",
        "filename": filename,
        "url": _image_public_url(filename),
    })


@app.delete("/api/campaign-images/<filename>")
def api_delete_campaign_image(filename):
    filename = (filename or "").strip()
    if not filename:
        return jsonify({"ok": False, "message": "No filename provided."}), 400

    base = CAMPAIGN_IMAGES_DIR.resolve()
    target_path = (CAMPAIGN_IMAGES_DIR / filename).resolve()

    if base not in target_path.parents:
        return jsonify({"ok": False, "message": "Invalid file path."}), 400

    if not target_path.is_file():
        return jsonify({"ok": False, "message": "File not found."}), 404

    try:
        target_path.unlink()
    except Exception as e:
        app.logger.exception("Unable to delete image %s: %s", filename, e)
        return jsonify({"ok": False, "message": f"Unable to delete file: {e}"}), 500

    return jsonify({"ok": True, "message": f"Deleted {filename}."})


@app.get("/api/disk-usage")
def api_disk_usage():
    used = _dir_size_bytes(CAMPAIGNS_DIR, CAMPAIGN_IMAGES_DIR)
    return jsonify({
        "used_bytes": used,
        "total_bytes": DISK_QUOTA_BYTES,
        "used_human": _human_bytes(used),
        "total_human": _human_bytes(DISK_QUOTA_BYTES),
        "percent": round(used / DISK_QUOTA_BYTES * 100, 1) if DISK_QUOTA_BYTES else 0,
    })


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
    per_page = _parse_int(request.args.get("per_page"), 25, minimum=1, maximum=100)
    page = _parse_int(request.args.get("page"), 1, minimum=1, maximum=1000)
    offset = (page - 1) * per_page
    try:
        rows, total = dbmod.fetch_customers_paginated(
        search=search_term,
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
    try:
        stats = dbmod.count_customer_stats()
    except Exception:
        stats = {"total_customers": 0, "total_subscribers": 0}
    return jsonify({"customers": serialized, "pagination": pagination, "search": search_term or "", "stats": stats})


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

    _maybe_send_welcome_email(row["CUSTID"], is_subscribed=is_subscribed)

    return jsonify({"customer": _serialize_customer(row)}), 201


@app.post("/api/customers/import")
def import_customers_csv():
    """Bulk-import customers from an uploaded CSV file."""
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "No file provided."}), 400

    filename = secure_filename(uploaded.filename)
    if not filename.lower().endswith(".csv"):
        return jsonify({"error": "Only .csv files are accepted."}), 400

    try:
        raw = uploaded.stream.read()
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return jsonify({"error": "File is not valid UTF-8 text."}), 400

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return jsonify({"error": "CSV file is empty or has no header row."}), 400

    # Build a case-insensitive mapping from the CSV headers to canonical names.
    canonical = {
        "email": "email",
        "firstname": "firstname",
        "first_name": "firstname",
        "first name": "firstname",
        "lastname": "lastname",
        "last_name": "lastname",
        "last name": "lastname",
        "company": "company",
        "phone": "phone",
        "comments": "comments",
    }
    header_map: dict[str, str] = {}
    for field in reader.fieldnames:
        key = field.strip().lower()
        if key in canonical:
            header_map[field] = canonical[key]

    # Ensure the required 'email' column is present.
    if "email" not in header_map.values():
        return jsonify({
            "error": "CSV is missing the required 'email' column.",
            "found_columns": list(reader.fieldnames),
        }), 400

    created = 0
    skipped = 0
    errors: list[dict] = []

    for row_num, row in enumerate(reader, start=2):  # row 1 is the header
        # Remap CSV columns to canonical field names.
        mapped: dict[str, str] = {}
        for csv_col, canon in header_map.items():
            value = (row.get(csv_col) or "").strip()
            if value:
                mapped[canon] = value

        email_raw = mapped.get("email", "")
        if not email_raw:
            skipped += 1
            errors.append({"row": row_num, "email": "", "reason": "Missing email."})
            continue

        try:
            email = validate_email(email_raw).email
        except EmailNotValidError as exc:
            skipped += 1
            errors.append({"row": row_num, "email": email_raw, "reason": f"Invalid email: {exc}"})
            continue

        try:
            dbmod.create_customer(
                email=email,
                firstname=mapped.get("firstname"),
                lastname=mapped.get("lastname"),
                company=mapped.get("company"),
                phone=mapped.get("phone"),
                comments=mapped.get("comments"),
            )
            created += 1
        except dbmod.DuplicateCustomerError:
            skipped += 1
            errors.append({"row": row_num, "email": email, "reason": "Duplicate email."})
        except Exception as exc:
            app.logger.exception("CSV import row %d failed", row_num)
            skipped += 1
            errors.append({"row": row_num, "email": email, "reason": str(exc)})

    return jsonify({
        "created": created,
        "skipped": skipped,
        "errors": errors,
    }), 200


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


@app.post("/api/customers/scan")
def scan_customers_api():
    """Scan the customer table for duplicate emails and invalid addresses."""
    try:
        duplicate_groups = dbmod.find_duplicate_emails()
    except Exception as e:
        app.logger.exception("Failed to scan for duplicate emails")
        return jsonify({"error": f"Unable to scan for duplicates: {e}"}), 500

    serialized_groups: dict[str, list[dict]] = {}
    for email_key, rows in duplicate_groups.items():
        serialized_groups[email_key] = [_serialize_customer(r) for r in rows]

    invalid_emails: list[dict] = []
    try:
        all_customers = dbmod.fetch_all_customers()
    except Exception as e:
        app.logger.exception("Failed to fetch customers for email validation")
        return jsonify({"error": f"Unable to validate emails: {e}"}), 500

    for row in all_customers:
        email_raw = (row.get("EMAIL") or "").strip()
        if not email_raw:
            invalid_emails.append({
                **_serialize_customer(row),
                "reason": "Email address is empty.",
            })
            continue
        try:
            validate_email(email_raw)
        except EmailNotValidError as exc:
            invalid_emails.append({
                **_serialize_customer(row),
                "reason": str(exc),
            })

    return jsonify({
        "duplicates": serialized_groups,
        "invalid_emails": invalid_emails,
    })


@app.post("/api/customers/clean")
def clean_customers_api():
    """Delete duplicate and invalid customer records chosen by the user."""
    payload = request.get_json(silent=True) or {}
    keep_ids = payload.get("keep_ids") or {}
    delete_invalid_ids = payload.get("delete_invalid_ids") or []

    if not isinstance(keep_ids, dict):
        return jsonify({"error": "keep_ids must be an object mapping email to the ID to keep."}), 400
    if not isinstance(delete_invalid_ids, list):
        return jsonify({"error": "delete_invalid_ids must be a list of customer IDs."}), 400

    deleted = 0
    errors: list[str] = []

    # Re-fetch duplicate groups to ensure we only delete actual duplicates.
    try:
        duplicate_groups = dbmod.find_duplicate_emails()
    except Exception as e:
        app.logger.exception("Failed to re-fetch duplicates during clean")
        return jsonify({"error": f"Unable to load duplicates: {e}"}), 500

    for email_key, keep_id in keep_ids.items():
        try:
            keep_id = int(keep_id)
        except (TypeError, ValueError):
            errors.append(f"Invalid keep ID for {email_key}.")
            continue

        group = duplicate_groups.get(email_key.strip().lower(), [])
        if not group:
            continue

        group_ids = {r["CUSTID"] for r in group}
        if keep_id not in group_ids:
            errors.append(f"ID {keep_id} is not part of the duplicate group for {email_key}.")
            continue

        for row in group:
            if row["CUSTID"] == keep_id:
                continue
            try:
                dbmod.delete_customer(row["CUSTID"])
                deleted += 1
            except dbmod.CustomerNotFoundError:
                pass
            except Exception as exc:
                app.logger.exception("Failed to delete CUSTID %s during clean", row["CUSTID"])
                errors.append(f"Failed to delete ID {row['CUSTID']}: {exc}")

    for cid in delete_invalid_ids:
        try:
            cid = int(cid)
        except (TypeError, ValueError):
            errors.append(f"Invalid customer ID in delete_invalid_ids: {cid}")
            continue
        try:
            dbmod.delete_customer(cid)
            deleted += 1
        except dbmod.CustomerNotFoundError:
            pass
        except Exception as exc:
            app.logger.exception("Failed to delete invalid CUSTID %s during clean", cid)
            errors.append(f"Failed to delete ID {cid}: {exc}")

    return jsonify({
        "deleted": deleted,
        "errors": errors,
    })


@app.get("/api/individual-emails")
def list_individual_emails_api():
    try:
        templates = list_individual_email_templates()
    except Exception as e:
        app.logger.exception("Failed to list individual emails")
        return jsonify({"error": f"Unable to load individual emails: {e}"}), 500
    return jsonify({"templates": templates})


@app.post("/api/individual-emails/upload")
def upload_individual_email():
    upload = request.files.get("template_file")
    desired_name = (request.form.get("filename") or "").strip()

    if not upload or not upload.filename:
        return jsonify({"ok": False, "message": "Choose an HTML file to upload."}), 400

    try:
        filename = _sanitize_campaign_filename(desired_name or upload.filename)
    except ValueError as e:
        return jsonify({"ok": False, "message": str(e)}), 400

    INDIVIDUAL_EMAILS_DIR.mkdir(parents=True, exist_ok=True)
    target_path = (INDIVIDUAL_EMAILS_DIR / filename).resolve()
    base = INDIVIDUAL_EMAILS_DIR.resolve()
    if base not in target_path.parents:
        return jsonify({"ok": False, "message": "Invalid upload path."}), 400

    if target_path.exists():
        return jsonify({"ok": False, "message": "A template with that name already exists."}), 409

    try:
        upload.save(target_path)
    except Exception as e:
        app.logger.exception("Unable to save individual email template %s: %s", filename, e)
        return jsonify({"ok": False, "message": f"Unable to save template: {e}"}), 500

    return jsonify({"ok": True, "message": f"Uploaded {filename}.", "filename": filename})


@app.delete("/api/individual-emails/<filename>")
def api_delete_individual_email(filename):
    filename = (filename or "").strip()
    if not filename:
        return jsonify({"ok": False, "message": "No filename provided."}), 400

    INDIVIDUAL_EMAILS_DIR.mkdir(parents=True, exist_ok=True)
    base = INDIVIDUAL_EMAILS_DIR.resolve()
    target_path = (INDIVIDUAL_EMAILS_DIR / filename).resolve()

    if base not in target_path.parents:
        return jsonify({"ok": False, "message": "Invalid file path."}), 400

    if not target_path.is_file():
        return jsonify({"ok": False, "message": "File not found."}), 404

    try:
        target_path.unlink()
    except Exception as e:
        app.logger.exception("Unable to delete individual email template %s: %s", filename, e)
        return jsonify({"ok": False, "message": f"Unable to delete file: {e}"}), 500

    return jsonify({"ok": True, "message": f"Deleted {filename}."})


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


def _build_confirm_context(file: str, subject: str | None, batch_size: int, delay_ms: int, cooldown_seconds: int | None = None):
    """Assemble the template context for the confirm page."""
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

    recipients = dbmod.fetch_subscribed_customers() or []
    recipient_count = len(recipients)
    num_batches = max(1, math.ceil(recipient_count / batch_size)) if recipient_count else 0
    total_cooldown = max(0, num_batches - 1) * cooldown_seconds
    estimated_seconds = total_cooldown + recipient_count * (delay_ms / 1000)

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
        "lint_report": lint_report,
        "lint_has_errors": lint_has_errors,
        "lint_has_warnings": lint_has_warnings,
        "preview_html": preview_html,
        "preview_error": preview_error,
        "estimated_send_time": _format_duration(int(estimated_seconds)),
    }

@app.get("/confirm")
def confirm():
    file = (request.args.get("file") or "").strip()
    subject = request.args.get("subject")
    campaign_name = (request.args.get("campaign_name") or "").strip() or None
    defaults = default_controls()
    batch_size = int(request.args.get("batch_size", defaults["batch_size"]))
    # Interpret delay as seconds in the UI, convert to ms for internal use.
    delay_seconds = _parse_int(request.args.get("delay_seconds"), int(defaults["delay_ms"] / 1000), minimum=0)
    delay_ms = delay_seconds * 1000
    # Interpret cooldown as minutes in the UI, convert to seconds for internal use.
    cooldown_minutes = _parse_int(
        request.args.get("cooldown_minutes"),
        int(defaults["batch_cooldown_seconds"] / 60),
        minimum=0,
    )
    cooldown_seconds = cooldown_minutes * 60

    if not file:
        flash("No campaign file was selected.", "error")
        return redirect(url_for("index"))
    try:
        context = _build_confirm_context(file, subject, batch_size, delay_ms, cooldown_seconds)
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
        flash("Resolve lint errors before queuing the campaign.", "error")
        return redirect(url_for("index"))

    return render_template(
        "confirm.html",
        **context,
        campaign_name=campaign_name,
        sending=False,
        log_stream_token=None,
    )


@app.post("/send")
@app.post("/queue")
def queue_campaign():
    file = (request.form.get("file") or "").strip()
    subject = request.form.get("subject")
    campaign_name = (request.form.get("campaign_name") or "").strip() or None
    defaults = default_controls()
    batch_size = int(request.form.get("batch_size", defaults["batch_size"]))
    # Form accepts delay in seconds and cooldown in minutes; normalize to internal units.
    delay_seconds = _parse_int(request.form.get("delay_seconds"), int(defaults["delay_ms"] / 1000), minimum=0)
    delay_ms = delay_seconds * 1000
    cooldown_minutes = _parse_int(
        request.form.get("cooldown_minutes"),
        int(defaults["batch_cooldown_seconds"] / 60),
        minimum=0,
    )
    cooldown_seconds = cooldown_minutes * 60

    if not file:
        flash("No campaign file was selected.", "error")
        return redirect(url_for("index"))

    active = dbmod.fetch_active_send()
    if active:
        flash("A campaign is already queued or in progress.", "error")
        return redirect(url_for("send_status", send_id=active["SEND_ID"]))

    try:
        context = _build_confirm_context(file, subject, batch_size, delay_ms, cooldown_seconds)
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
        flash("Resolve lint errors before queuing the campaign.", "error")
        return redirect(
            url_for(
                "confirm",
                file=file,
                subject=subject,
                batch_size=batch_size,
                delay_ms=delay_ms,
            )
        )

    mode = getattr(g, "db_mode", CUSTOMER_MODE_DEFAULT)
    recipients = context["recipients"]
    total = len(recipients)
    send_id = secrets.token_hex(16)

    try:
        dbmod.insert_campaign_send(
            send_id,
            file,
            subject,
            campaign_name,
            mode,
            total,
            batch_size=batch_size,
            delay_ms=delay_ms,
            cooldown_seconds=cooldown_seconds,
        )
        dbmod.bulk_insert_send_recipients(send_id, recipients)
        dbmod.activate_campaign_send(send_id)
    except Exception as exc:
        app.logger.exception("Failed to queue campaign send: %s", exc)
        flash("Unable to queue campaign. Please try again.", "error")
        return redirect(url_for("index"))

    sess = create_send_session(send_id, file, subject, mode, total)
    _ensure_scheduler()

    return redirect(url_for("send_status", send_id=send_id))


@app.get("/send/<send_id>/status")
def send_status(send_id: str):
    send_row = dbmod.get_send_status(send_id)
    if not send_row:
        flash("Send not found.", "error")
        return redirect(url_for("index"))

    file = send_row["CAMPAIGN_FILE"]
    subject = send_row.get("SUBJECT")
    campaign_name = send_row.get("CAMPAIGN_NAME")
    mode = send_row.get("MODE", CUSTOMER_MODE_DEFAULT)
    session_status = send_row.get("STATUS", "completed")

    preview_html = None
    preview_error = None
    try:
        candidate = resolve_campaign_path(file)
        raw_html = load_campaign_html(candidate)
        raw_html = ensure_unsubscribe(raw_html)
        preview_html = render_for_test(raw_html, mode=mode)
    except Exception as e:
        preview_error = f"Unable to render campaign preview: {e}"

    return render_template(
        "confirm.html",
        file=file,
        subject=subject,
        campaign_name=campaign_name,
        send_id=send_id,
        send_status=session_status,
        sending=True,
        preview_html=preview_html,
        preview_error=preview_error,
        batch_size=int(send_row.get("BATCH_SIZE") or 25),
        delay_ms=int(send_row.get("DELAY_MS") or 0),
        cooldown_seconds=int(send_row.get("COOLDOWN_SECONDS") or 0),
        recipient_count=int(send_row.get("TOTAL_RECIPIENTS") or 0),
        sent_count=int(send_row.get("SENT_COUNT") or 0),
        failed_count=int(send_row.get("FAILED_COUNT") or 0),
        lint_report={},
        lint_has_errors=False,
        lint_has_warnings=False,
        recipients=[],
        estimated_send_time=None,
    )


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

    return jsonify({
        "status": send_row.get("STATUS", "completed"),
        "logs": log_lines,
        "sent": sent,
        "failed": failed,
        "total": total,
    })


@app.get("/send/<send_id>/progress")
def send_progress(send_id: str):
    """Return accurate real-time progress from the database."""
    row = dbmod.get_send_status(send_id)
    if not row:
        return jsonify({"error": "Send not found."}), 404
    counts = dbmod.count_send_results(send_id)
    return jsonify({
        "send_id": send_id,
        "status": row["STATUS"],
        "total": int(row.get("TOTAL_RECIPIENTS") or 0),
        "sent": int(row.get("SENT_COUNT") or 0),
        "failed": int(row.get("FAILED_COUNT") or 0),
        "pending": counts.get("pending", 0),
        "batch_size": int(row.get("BATCH_SIZE") or 0),
        "delay_ms": int(row.get("DELAY_MS") or 0),
        "cooldown_seconds": int(row.get("COOLDOWN_SECONDS") or 0),
        "started_at": row.get("STARTED_AT").isoformat() if row.get("STARTED_AT") else None,
        "finished_at": row.get("FINISHED_AT").isoformat() if row.get("FINISHED_AT") else None,
        "last_batch_at": row.get("LAST_BATCH_AT").isoformat() if row.get("LAST_BATCH_AT") else None,
    })


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
    """Update batch_size, delay_ms, or cooldown_seconds mid-flight."""
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

    dbmod.update_send_controls(
        send_id,
        batch_size=batch_size,
        delay_ms=delay_ms,
        cooldown_seconds=cooldown_seconds,
    )
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
    """Paginated list of recipients with their statuses."""
    status_filter = request.args.get("status")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    rows, total = dbmod.fetch_send_recipients_paginated(
        send_id, status_filter=status_filter, limit=limit, offset=offset,
    )
    result = []
    for r in rows:
        entry = {
            "id": r["ID"],
            "email": r["EMAIL"],
            "firstname": r.get("FIRSTNAME"),
            "lastname": r.get("LASTNAME"),
            "status": r["STATUS"],
            "error": r.get("ERROR_MESSAGE"),
        }
        at = r.get("ATTEMPTED_AT")
        entry["attempted_at"] = at.isoformat() if at else None
        result.append(entry)
    return jsonify({"recipients": result, "total": total, "limit": limit, "offset": offset})


@app.get("/scheduler/health")
def scheduler_health():
    """Return scheduler heartbeat for dashboard indicator."""
    thread_alive = _scheduler_thread is not None and _scheduler_thread.is_alive()
    if _scheduler_last_tick is not None:
        seconds_since = time.monotonic() - _scheduler_last_tick
    else:
        seconds_since = None
    alive = thread_alive and seconds_since is not None and seconds_since < (SCHEDULER_POLL_INTERVAL * 2)
    return jsonify({
        "alive": alive,
        "seconds_since_last_tick": round(seconds_since, 1) if seconds_since is not None else None,
        "poll_interval": SCHEDULER_POLL_INTERVAL,
        "thread_alive": thread_alive,
    })


@app.get("/api/active-send")
def active_send_api():
    """Return the currently running/queued send for the dashboard banner."""
    row = dbmod.fetch_active_send()
    if not row:
        return jsonify({"send_id": None})
    return jsonify({
        "send_id": row["SEND_ID"],
        "campaign_file": row["CAMPAIGN_FILE"],
        "subject": row.get("SUBJECT"),
        "campaign_name": row.get("CAMPAIGN_NAME"),
        "status": row["STATUS"],
        "total_recipients": int(row.get("TOTAL_RECIPIENTS") or 0),
        "sent_count": int(row.get("SENT_COUNT") or 0),
        "failed_count": int(row.get("FAILED_COUNT") or 0),
    })


def _ensure_scheduler():
    """Start the scheduler thread if it is not already running."""
    global _scheduler_thread
    if _scheduler_thread is not None and _scheduler_thread.is_alive():
        return
    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    _scheduler_thread.start()


def _scheduler_loop():
    """Persistent background loop that polls MySQL for sends needing work."""
    global _scheduler_last_tick
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    while True:
        time.sleep(SCHEDULER_POLL_INTERVAL)
        _scheduler_last_tick = time.monotonic()
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
    """Process a single batch for one send. Called by the scheduler."""
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


@app.get("/logs/stream")
def logs_stream():
    token = (request.args.get("token") or "").strip()
    payload = _validate_log_stream_token(token)
    if not payload:
        return Response("Unauthorized", status=401)
    send_id = payload.get("send_id")
    if not send_id:
        return Response("Missing send_id in token", status=400)
    sess = get_send_session(send_id)
    if not sess:
        return Response("Send session not found or expired", status=404)
    subscriber_q = sess.bus.subscribe()
    return Response(
        stream_with_context(sess.bus.stream(subscriber_q)),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Campaign history ─────────────────────────────────────────────


@app.get("/history")
def campaign_history():
    mode_filter = request.args.get("mode")
    if mode_filter and mode_filter not in CUSTOMER_MODE_CHOICES:
        mode_filter = None
    try:
        sends = dbmod.fetch_campaign_history(mode_filter=mode_filter)
    except Exception as exc:
        app.logger.exception("Failed to load campaign history: %s", exc)
        sends = []
    return render_template("history.html", sends=sends, mode_filter=mode_filter or "all")


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
    if status_filter and status_filter not in ("sent", "failed"):
        status_filter = None

    filtered_results = results
    if status_filter:
        filtered_results = [r for r in results if r["STATUS"] == status_filter]

    return render_template(
        "history_detail.html",
        send=send_row,
        results=filtered_results,
        all_results=results,
        status_filter=status_filter or "all",
    )



def _is_gunicorn():
    return "gunicorn" in os.getenv("SERVER_SOFTWARE", "")


with app.app_context():
    try:
        dbmod.ensure_campaign_tables()
    except Exception as exc:
        print(f"WARNING: Could not create campaign history tables: {exc}", file=sys.stderr)

    server_software = os.getenv("SERVER_SOFTWARE", "").strip()
    if SEND_SCHEDULER_ENABLED and (_is_gunicorn() or APP_ENV != "production"):
        app.logger.info(
            "Starting send scheduler thread",
            extra={
                "app_env": APP_ENV,
                "server_software": server_software,
                "scheduler_enabled": SEND_SCHEDULER_ENABLED,
            },
        )
        _ensure_scheduler()
    else:
        app.logger.info(
            "Send scheduler startup skipped",
            extra={
                "app_env": APP_ENV,
                "server_software": server_software,
                "scheduler_enabled": SEND_SCHEDULER_ENABLED,
            },
        )


if __name__ == "__main__":
    server_software = os.getenv("SERVER_SOFTWARE", "").strip()
    if SEND_SCHEDULER_ENABLED:
        app.logger.info(
            "Starting send scheduler thread in __main__",
            extra={
                "app_env": APP_ENV,
                "server_software": server_software,
                "scheduler_enabled": SEND_SCHEDULER_ENABLED,
            },
        )
        _ensure_scheduler()
    else:
        app.logger.info(
            "Send scheduler disabled by SEND_SCHEDULER_ENABLED in __main__",
            extra={
                "app_env": APP_ENV,
                "server_software": server_software,
                "scheduler_enabled": SEND_SCHEDULER_ENABLED,
            },
        )
    app.run(debug=True, use_reloader=False, threaded=True)
