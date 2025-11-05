from __future__ import annotations
import os, pathlib, threading
from flask import Flask, render_template, request, redirect, url_for, Response, stream_with_context, flash
from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError

from mailer import db as dbmod
from mailer.smtp import SmtpClient
from mailer.lint import lint_html
from mailer.render import load_campaign_html, ensure_unsubscribe, render_for_recipient, render_for_test
from mailer.sse import GLOBAL_BUS

load_dotenv() # Load .env at startup

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "dev-secret")

CAMPAIGNS_DIR = pathlib.Path(__file__).parent / "campaigns"


def list_campaign_files():
    return sorted([f.name for f in CAMPAIGNS_DIR.glob("*.html")])

def default_controls():
    return {
    "batch_size": int(os.getenv("DEFAULT_BATCH_SIZE", "100")),
    "delay_ms": int(os.getenv("DEFAULT_BATCH_DELAY_MS", "200")),
    }


@app.get("/")
def index():
    return render_template("index.html", campaign_files=list_campaign_files(), defaults=default_controls())


@app.get("/preview")
def preview():
    file = request.args.get("file")
    subject = request.args.get("subject", "")
    if not file:
        return redirect(url_for("index"))
    html = load_campaign_html(CAMPAIGNS_DIR / file)
    return render_template("preview.html", file=file, subject=subject, html=html, lint=None)


@app.post("/lint")
def lint_route():
    file = request.form.get("file")
    html = load_campaign_html(CAMPAIGNS_DIR / file)
    report = lint_html(html)
    return render_template("preview.html", file=file, subject=request.form.get("subject", ""), html=html, lint=report)


@app.post("/send-test")
def send_test():
    # Pull fields safely and normalize
    file_field = (request.form.get("file") or "").strip()  # ensure not None
    subject = (request.form.get("subject") or "").strip() or "Test Campaign"
    email_raw = (request.form.get("email") or "").strip()

    # Basic presence checks first
    if not file_field:
        flash("No campaign file was selected.", "error")
        return redirect(url_for("index"))
    if not email_raw:
        flash("Please enter a test email address.", "error")
        return redirect(url_for("index"))

    # Validate & normalize email
    try:
        email_obj = validate_email(email_raw)
        to_addr = email_obj.email  # normalized
    except EmailNotValidError as e:
        flash(f"Invalid email: {e}", "error")
        return redirect(url_for("index"))

    # Resolve campaign path safely
    try:
        base = CAMPAIGNS_DIR.resolve()
        candidate = (base / file_field).resolve()

        # Prevent path traversal and ensure file exists
        if base not in candidate.parents and candidate != base:
            flash("Invalid campaign path.", "error")
            return redirect(url_for("index"))
        if not candidate.is_file():
            flash("Campaign file not found.", "error")
            return redirect(url_for("index"))
    except Exception as e:
        flash(f"Error resolving campaign file: {e}", "error")
        return redirect(url_for("index"))

    # Load and render the campaign (catch template/HTML errors)
    try:
        raw_html = load_campaign_html(candidate)
        html = render_for_test(raw_html)
    except Exception as e:
        flash(f"Error preparing campaign HTML: {e}", "error")
        return redirect(url_for("index"))

    # Build + send the email (guard against None/invalid inputs)
    try:
        smtp = SmtpClient()  # or SmtpClient.from_env()
        msg = smtp.build_message(to_addr, subject, html)
    except Exception as e:
        flash(f"Error creating email message: {e}", "error")
        return redirect(url_for("index"))

    try:
        smtp.send(msg)
        flash(f"Test email sent to {to_addr}.", "success")
    except Exception as e:
        flash(f"Failed to send test: {e}", "error")

    return redirect(url_for("index"))


@app.get("/confirm")
def confirm():
    file = request.args.get("file")
    subject = request.args.get("subject")
    batch_size = int(request.args.get("batch_size", default_controls()["batch_size"]))
    delay_ms = int(request.args.get("delay_ms", default_controls()["delay_ms"]))


    recipients = dbmod.fetch_subscribed_customers()
    return render_template("confirm.html", file=file, subject=subject,
                           recipient_count=len(recipients), batch_size=batch_size, delay_ms=delay_ms)


@app.post("/send")
def send_to_customers():
    file = request.form.get("file")
    subject = request.form.get("subject")
    batch_size = int(request.form.get("batch_size", default_controls()["batch_size"]))
    delay_ms = int(request.form.get("delay_ms", default_controls()["delay_ms"]))

    # Kick off a background thread that does the sending and emits logs.
    threading.Thread(target=_send_worker, args=(file, subject, batch_size, delay_ms), daemon=True).start()
    return render_template("sent.html", file=file, subject=subject)


def _send_worker(file: str, subject: str, batch_size: int, delay_ms: int):
    try:
        raw_html = load_campaign_html(CAMPAIGNS_DIR / file)
        raw_html = ensure_unsubscribe(raw_html)
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
                html = render_for_recipient(raw_html, r.get("FIRSTNAME"), r.get("LASTNAME"), r.get("UNSUBSCRIBE_TOKEN"))
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