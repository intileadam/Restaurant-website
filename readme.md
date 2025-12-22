# Casa del Pollo Restaurant Website & Email Campaign Tool

This repository pairs a modern restaurant landing page with a bespoke email campaign dashboard used by Casa del Pollo. It began as a fork of Atul's open-source restaurant template and now includes a full workflow for uploading HTML campaigns, linting them for email best practices, sending tests, and blasting the subscriber list with batched throttling and live logs.

## Credits & Inspiration

Original design and front-end structure by [atulcodex](https://github.com/atulcodex). Please support his work —_buy him a coffee!_

[![Atul - Buy Me A Coffee](https://i.ibb.co/7rR9S4L/buy-me-a-coffee.png)](https://www.buymeacoffee.com/atulcodex)

## Restaurant Landing Page

Perfect for restaurants, cafes, bakeries, pubs, catering, or any food business.

- [x] Single-page layout with smooth sections
- [x] Easy color and typography tweaks
- [x] Clean CSS structure (no heavy frameworks)
- [x] Responsive, fast, and validated HTML5/CSS3
- [x] Zero third-party dependencies
- [x] Modern transitions and lightweight assets

## Casa del Pollo — Email Campaign Web App

A Flask-based dashboard (see `app.py`) turns the static site into a mini ESP tailored for Casa del Pollo’s team.

### What it does

- Lists every HTML file in `campaigns/`, lets you upload new exports, and renders responsive previews inside the browser.
- Runs a lightweight linter (`mailer/lint.py`) that blocks live sends until HTML errors are fixed and highlights common email-client issues.
- Sends ad-hoc tests to any address after validating and merging sample unsubscribe data.
- Streams confirmation data, batch progress, and SMTP success/failure logs to the browser in real time using Server-Sent Events.
- Sends full campaigns to the subscribers stored in MySQL (`CUSTOMERS`), throttled by batch size and inter-send delay controls.
- Provides a REST-ish API (`/api/customers`) plus UI forms to add, edit, and delete subscribers without touching SQL.
- Ships a dedicated unsubscribe microservice (`unsubscribe_service/`) that flips `IS_SUBSCRIBED` and honors unique `UNSUBSCRIBE_TOKEN`s injected into every message.

### Run it locally (email campaign quick start)

1. **Clone & install Python deps**
   ```bash
   git clone https://github.com/<your-user>/Restaurant-website.git
   cd Restaurant-website
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Create `.env` safely** — copy `.env.example` to a location **outside** any web-accessible directory and fill in every placeholder with real credentials. Keep the file out of git (`.gitignore` already blocks it) and rotate secrets immediately if it ever leaks. For development you can place it in the repo root, but never upload the real `.env` to production servers.

3. **Prep MySQL** — create a database and the subscriber table the app expects:
   ```sql
   CREATE TABLE CUSTOMERS (
     CUSTID INT AUTO_INCREMENT PRIMARY KEY,
     FIRSTNAME VARCHAR(255) NOT NULL,
     LASTNAME VARCHAR(255) NOT NULL,
     EMAIL VARCHAR(320) NOT NULL UNIQUE,
     COMPANY VARCHAR(255) NOT NULL,
     PHONE VARCHAR(32) NOT NULL,
     COMMENTS TEXT NOT NULL,
     IS_SUBSCRIBED TINYINT(1) NOT NULL DEFAULT 1,
     UNSUBSCRIBE_TOKEN CHAR(64) NOT NULL
   );
   ```
   Use the dashboard’s “Add subscriber” form or `POST /api/customers` to seed a few rows if you don’t want to insert them manually.

4. **Run the dashboard**
   ```bash
   ./scripts/run_campaign_local.sh
   # or: FLASK_APP=app.py python -m flask run --host 127.0.0.1 --port 8080
   ```

5. **Visit** `http://127.0.0.1:8080` and keep an eye on your terminal for Flask logs.

### macOS Dock launcher

Shipping the repo now includes a ready-to-use app bundle at `macos/Casa del Pollo Launcher.app` so non-technical teammates can start the campaign tool the same way they launch Safari or Mail.

1. Open Finder, drag `macos/Casa del Pollo Launcher.app` to `/Applications` (or the Desktop) and then into the Dock to “pin” it. The Dock keeps a reference to that copy, so it will survive Git pulls.
2. Double-click the icon to run the same `run_campaign_local.command` logic without having to hunt through the repo; we'll pop open a Terminal window with the live logs so you can see what the app is doing, and the launcher will prompt for the project folder the first time and remember it.
3. To stop the server later, click the Dock icon again and pick “Stop Server” in the dialog, or press `⌘Q` while the launcher is running.
4. On first launch macOS will prompt for access to Desktop/Documents/Downloads plus “control Finder.” Click **OK** so the launcher can find the repo; if you deny, re-open the app and allow when the alerts return.
5. Finder launches don’t show Terminal output, so check `~/Library/Application Support/CasaDelPolloCampaign/launcher.log` (or `/var/folders/.../CasaDelPolloCampaign/launcher.log` if macOS forces the temporary path) whenever you need to troubleshoot; the launcher mirrors everything it prints there.
6. If you change `run_campaign_local.command`, run `macos/update_launcher_bundle.sh` and commit the refreshed app bundle so everyone gets the update on their next pull.

### Give it a try — typical workflow

1. **Drop a campaign**: export HTML from your email designer (e.g., Bee, Figma-to-HTML) and place it in `campaigns/` or use the “Upload HTML” button.
2. **Preview & lint**: select the file in Step 1. The app injects an unsubscribe footer if you forgot one, renders it, and shows lint results. Fix errors before moving on.
3. **Send yourself a test**: Step 2 collects subject + email, validates the address, renders merge tags (`{{ first_name }}`, `{{ unsubscribe_url }}`), and sends via your SMTP creds.
4. **Review the live send**: Step 3 opens `/confirm` showing the rendered preview, lint summary, and a sample of recipients pulled from MySQL. Adjust batch size or delay as needed.
5. **Go live**: click “Yes, send to customers.” A background thread (`_send_worker`) walks the subscriber list, throttles based on your controls, and writes every event to the live log stream so you can watch progress (and failures) in real time.
6. **Test unsubscribe**: each email contains a `UNSUBSCRIBE_URL` parameterized with that row’s token. Start `php -S 127.0.0.1:8000 -t unsubscribe_service unsubscribe_service/index.php` locally (or deploy it — see below), then click the link in your test message to confirm opt-outs flip `IS_SUBSCRIBED` back to 0.

Before committing or deploying, run `scripts/preflight.sh` to ensure `.env` is untracked, no obvious secrets slipped into sources, and that no `.log` files live inside the unsubscribe docroot.

### Subscriber data & unsubscribe service

- The campaign app only reads subscriber rows; writes happen through the dashboard/API or through the unsubscribe microservice. That keeps marketing sends auditable and ensures compliance.
- `unsubscribe_service/` is a tiny PHP app that runs separately (the repo includes an .htaccess router for DreamHost). Follow `unsubscribe_instructions.md` for deployment notes and environment variables.
- Environment parity matters: both apps load from `.env`, so keep DB + SMTP creds in sync across environments (local, staging, production).

### Helpful commands & docs

- `scripts/run_campaign_local.sh` — convenience script for launching Flask on `127.0.0.1:8080`.
- `python -m flask shell` — useful for poking at `mailer.db` helpers.
- `unsubscribe_instructions.md` — step-by-step notes for deploying the opt-out service on DreamHost/PHP.
- `campaigns/menu.html` — sample HTML email you can use immediately after setup.

That’s it! Customize the restaurant landing page, wire up your SMTP + MySQL credentials, and you’ll have a private little ESP tailored to Casa del Pollo’s campaigns.
