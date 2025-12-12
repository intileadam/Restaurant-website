from __future__ import annotations
import math, os, pathlib, threading
from flask import Flask, render_template, request, redirect, url_for, Response, stream_with_context, flash, jsonify
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
from werkzeug.utils import secure_filename

from mailer import db as dbmod
from mailer.smtp import SmtpClient
from mailer.lint import lint_html
from mailer.render import load_campaign_html, ensure_unsubscribe, render_for_recipient, render_for_test
from mailer.sse import GLOBAL_BUS

load_dotenv() # Load .env at startup

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "dev-secret")

CAMPAIGNS_DIR = pathlib.Path(__file__).parent / "campaigns"
ALLOWED_CAMPAIGN_EXTS = {".html", ".htm"}


def list_campaign_files():
    return sorted([f.name for f in CAMPAIGNS_DIR.glob("*.html")])


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

def default_controls():
    return {
    "batch_size": int(os.getenv("DEFAULT_BATCH_SIZE", "100")),
    "delay_ms": int(os.getenv("DEFAULT_BATCH_DELAY_MS", "200")),
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
    if request.headers.get("X-Requested-With", "").lower() == "xmlhttprequest":
        return True
    accepts = request.accept_mimetypes
    return accepts["application/json"] >= accepts["text/html"]


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


@app.get("/")
def index():
    return render_template("index.html", campaign_files=list_campaign_files(), defaults=default_controls())


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
        rendered = render_for_test(html_with_unsub)
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
        if subscriber and subscriber_token:
            html = render_for_recipient(
            raw_html,
            subscriber.get("FIRSTNAME"),
            subscriber.get("LASTNAME"),
            subscriber_token,
            )
        else:
            html = render_for_test(raw_html)
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
        dbmod.create_customer(
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

    return jsonify({"customer": _serialize_customer(row)}), 201


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


def _build_confirm_context(file: str, subject: str | None, batch_size: int, delay_ms: int):
    """Assemble the template context for the confirm page."""
    campaign_path = resolve_campaign_path(file)
    raw_html = load_campaign_html(campaign_path)
    lint_report = lint_html(raw_html)
    lint_has_errors = bool(lint_report.get("errors"))
    lint_has_warnings = bool(lint_report.get("warnings"))

    preview_html = None
    preview_error = None
    try:
        preview_html = render_for_test(ensure_unsubscribe(raw_html))
    except Exception as e:
        preview_error = f"Unable to render campaign preview: {e}"

    recipients = dbmod.fetch_subscribed_customers() or []
    return {
        "file": file,
        "subject": subject,
        "recipient_count": len(recipients),
        "recipients": recipients,
        "batch_size": batch_size,
        "delay_ms": delay_ms,
        "lint_report": lint_report,
        "lint_has_errors": lint_has_errors,
        "lint_has_warnings": lint_has_warnings,
        "preview_html": preview_html,
        "preview_error": preview_error,
    }

@app.get("/confirm")
def confirm():
    file = (request.args.get("file") or "").strip()
    subject = request.args.get("subject")
    batch_size = int(request.args.get("batch_size", default_controls()["batch_size"]))
    delay_ms = int(request.args.get("delay_ms", default_controls()["delay_ms"]))

    if not file:
        flash("No campaign file was selected.", "error")
        return redirect(url_for("index"))
    try:
        context = _build_confirm_context(file, subject, batch_size, delay_ms)
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

    return render_template("confirm.html", **context, sending=False)


@app.post("/send")
def send_to_customers():
    file = (request.form.get("file") or "").strip()
    subject = request.form.get("subject")
    batch_size = int(request.form.get("batch_size", default_controls()["batch_size"]))
    delay_ms = int(request.form.get("delay_ms", default_controls()["delay_ms"]))

    if not file:
        flash("No campaign file was selected.", "error")
        return redirect(url_for("index"))
    try:
        context = _build_confirm_context(file, subject, batch_size, delay_ms)
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
            )
        )

    # Kick off a background thread that does the sending and emits logs.
    threading.Thread(target=_send_worker, args=(file, subject, batch_size, delay_ms), daemon=True).start()
    context["sending"] = True
    return render_template("confirm.html", **context)


def _send_worker(file: str, subject: str, batch_size: int, delay_ms: int):
    try:
        candidate = resolve_campaign_path(file)
        raw_html = load_campaign_html(candidate)
        raw_html = ensure_unsubscribe(raw_html)
        if "{{ unsubscribe_url }}" not in raw_html and "{{ UNSUBSCRIBE_URL }}" not in raw_html:
            GLOBAL_BUS.emit("⚠ No unsubscribe placeholder present after ensure_unsubscribe()")
        smtp = SmtpClient()
        rows = dbmod.fetch_subscribed_customers()
        total = len(rows)
        GLOBAL_BUS.emit(f"Starting send: {total} recipients; batch_size={batch_size}; delay={delay_ms}ms")


        sent = 0
        idx = 0
        while idx < total:
            batch = rows[idx: idx + batch_size]
            GLOBAL_BUS.emit(f"Batch {idx//batch_size + 1}: {len(batch)} recipients")
            for r in batch:
                to_addr = r["EMAIL"].strip()
                try:
                    token = dbmod.ensure_unsubscribe_token(r.get("CUSTID"), r.get("UNSUBSCRIBE_TOKEN"))
                except Exception as e:
                    GLOBAL_BUS.emit(f"✖ Missing unsubscribe token for {to_addr}: {e}")
                    continue

                html = render_for_recipient(raw_html, r.get("FIRSTNAME"), r.get("LASTNAME"), token)
                try:
                    msg = smtp.build_message(to_addr, subject, html)
                    smtp.send(msg, delay_ms=delay_ms)
                    sent += 1
                    GLOBAL_BUS.emit(f"✔ Sent to {to_addr}")
                except Exception as e:
                    GLOBAL_BUS.emit(f"✖ Failed for {to_addr}: {e}")
            idx += batch_size
        GLOBAL_BUS.emit(f"Done. Sent {sent}/{total}.")
    except Exception as e:
        GLOBAL_BUS.emit(f"Fatal error: {e}")

@app.get("/logs/stream")
def logs_stream():
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
