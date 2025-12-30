# DreamHost Deployment — Unsubscribe Service (PHP)

> The unsubscribe microservice runs as a lightweight PHP front controller.

## 0) Prereqs
- DreamHost account with a user that can upload files (SSH or SFTP).
- MySQL database + credentials (hostname, DB name, user, password).
- PHP 8.x selected for the subdomain (recommended in DreamHost panel).

## 1) Add the subdomain
1. DreamHost Panel → **Websites** → **Manage Websites** → **Add Hosting to a Domain / Sub-Domain**.
2. Enter `unsubscribe.casadelpollo.com`.
3. Pick PHP (FastCGI) — do **not** enable Passenger.
4. Enable Let’s Encrypt (HTTPS) and save.
5. DreamHost creates `/home/<dhuser>/unsubscribe.casadelpollo.com/` as the doc root.

## 2) Upload the service files
From your local repo root, copy these items into the subdomain’s doc root. **Do not** upload `.env`, log files, or any hidden files:

- `apps/unsubscribe_service/index.php`
- `apps/unsubscribe_service/.htaccess` (routes `/unsubscribe`, `/resubscribe`, `/healthz`)
- `apps/unsubscribe_service/templates/` (HTML/PHP views)
- `vendor/` (for `vlucas/phpdotenv`)
- `composer.json` and `composer.lock` (optional, for clarity)

Example (replace `dhuser` and server name as needed):
```bash
scp -r apps/unsubscribe_service vendor composer.* dhuser@server.dreamhost.com:/home/dhuser/unsubscribe.casadelpollo.com
```

## 3) Configure environment (outside the docroot)
1. Create a private directory outside the web root to hold secrets, e.g. `/home/<dhuser>/config`.
2. Copy `apps/unsubscribe_service/.env.example` to `/home/<dhuser>/config/cdp-unsubscribe.env` and fill in the DB credentials (same values the Flask console uses):
```ini
APP_ENV=production
DB_HOST=mysql.casadelpollo.com
DB_PORT=3306
DB_USER=your_mysql_user
DB_PASS=rotate_me_now
DB_NAME=restaurant_db
```
3. Tell Apache/PHP where to find that file by editing `/home/<dhuser>/unsubscribe.casadelpollo.com/.htaccess` (uncomment and update the provided line):
   ```
   SetEnv CDP_UNSUB_ENV_FILE /home/<dhuser>/config/cdp-unsubscribe.env
   ```
4. (Optional) To keep audit/error logs in a different private folder, set `CDP_UNSUB_STORAGE_DIR` in the same manner.
5. Never place `.env` inside the docroot; the bundled `.htaccess` blocks dotfiles/logs, but keeping them outside removes the risk entirely.

For local testing, the service automatically loads `apps/unsubscribe_service/.env`, so you can run `php -S 127.0.0.1:8000 -t apps/unsubscribe_service apps/unsubscribe_service/index.php` without touching Apache variables.

Run `scripts/preflight.sh` locally before every deploy to confirm `.env` stays untracked and that no `.log` files sneak into `apps/unsubscribe_service/`.

## 4) Test on the server
- Health check: `https://unsubscribe.casadelpollo.com/healthz` should return `ok`.
- Unsubscribe flow: `https://unsubscribe.casadelpollo.com/unsubscribe?token=TESTTOKEN`
- Resubscribe flow: `https://unsubscribe.casadelpollo.com/resubscribe?token=TESTTOKEN`
- Confirm hardening: `curl -i https://unsubscribe.casadelpollo.com/.env` and `curl -i https://unsubscribe.casadelpollo.com/php-error.log` should both return `403`/`404`.

If you change files, re-upload them; no Passenger restart is needed for PHP.

## 5) Point emails at the subdomain
Set these in the campaign app’s `.env` so generated links hit the PHP service:
```ini
BASE_URL_PUBLIC=https://unsubscribe.casadelpollo.com
UNSUBSCRIBE_PATH=/unsubscribe
```
