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
From your local repo root, copy these items into the subdomain’s doc root:

- `unsubscribe_service/index.php`
- `unsubscribe_service/.htaccess` (routes `/unsubscribe`, `/resubscribe`, `/healthz`)
- `unsubscribe_service/templates/` (HTML/PHP views)
- `vendor/` (for `vlucas/phpdotenv`)
- `composer.json` and `composer.lock` (optional, for clarity)

Example (replace `dhuser` and server name as needed):
```bash
scp -r unsubscribe_service vendor composer.* dhuser@server.dreamhost.com:/home/dhuser/unsubscribe.casadelpollo.com
```

## 3) Configure environment
Create `/home/<dhuser>/unsubscribe.casadelpollo.com/.env` with your production DB values:
```ini
DB_HOST=mysql.casadelpollo.com
DB_PORT=3306
DB_USER=your_mysql_user
DB_PASS=your_mysql_password   # DB_PASSWORD also works if you prefer
DB_NAME=restaurant_db
```

## 4) Test on the server
- Health check: `https://unsubscribe.casadelpollo.com/healthz` should return `ok`.
- Unsubscribe flow: `https://unsubscribe.casadelpollo.com/unsubscribe?token=TESTTOKEN`
- Resubscribe flow: `https://unsubscribe.casadelpollo.com/resubscribe?token=TESTTOKEN`

If you change files, re-upload them; no Passenger restart is needed for PHP.

## 5) Point emails at the subdomain
Set these in the campaign app’s `.env` so generated links hit the PHP service:
```ini
BASE_URL_PUBLIC=https://unsubscribe.casadelpollo.com
UNSUBSCRIBE_PATH=/unsubscribe
```
