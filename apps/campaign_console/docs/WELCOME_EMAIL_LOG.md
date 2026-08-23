# Welcome / one-off email send log — deploy checklist

## What this adds

- MySQL table `INDIVIDUAL_EMAIL_SENDS` for console one-offs, console auto-welcomes, and website signup welcomes
- Campaign Console nav item **Welcome log** at `/welcome-log`
- Confirmation when manually re-sending the welcome template to someone who already received it
- Auto-welcome from the console is skipped if a welcome was already logged

## Manual steps you must do

### 1. Create the table (or let the console create it)

**Preferred:** redeploy/restart the campaign console. On startup it runs `ensure_individual_email_tables()` and creates the table if missing.

**If you deploy website PHP before the console has started**, create the table manually in MySQL (DreamHost phpMyAdmin or CLI):

```sql
CREATE TABLE IF NOT EXISTS INDIVIDUAL_EMAIL_SENDS (
    ID             BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    CUSTID         INT          NULL,
    EMAIL          VARCHAR(320) NOT NULL,
    FIRSTNAME      VARCHAR(255) NULL,
    LASTNAME       VARCHAR(255) NULL,
    TEMPLATE_FILE  VARCHAR(255) NOT NULL,
    SUBJECT        VARCHAR(500) NULL,
    SOURCE         VARCHAR(40)  NOT NULL,
    MODE           VARCHAR(20)  NOT NULL DEFAULT 'production',
    STATUS         VARCHAR(20)  NOT NULL DEFAULT 'sent',
    ERROR_MESSAGE  TEXT         NULL,
    SENT_AT        DATETIME     NOT NULL,
    INDEX idx_indiv_email (EMAIL),
    INDEX idx_indiv_cust_template (CUSTID, TEMPLATE_FILE),
    INDEX idx_indiv_sent_at (SENT_AT),
    INDEX idx_indiv_source (SOURCE)
);
```

### 2. Deploy the website signup update

Upload/deploy the updated `apps/website/mailing-list-signup.php` to the live DreamHost site.

Until this file is live:

- Website signups still send welcome emails
- Those sends **will not** appear in Welcome log

After deploy, new signups log rows with `SOURCE = website_signup` and `TEMPLATE_FILE = welcome-email.html`.

### 3. Deploy / restart the campaign console

Ship the console app changes and restart so:

- The table ensure runs
- `/welcome-log` and the send APIs are available
- Auto-welcome skip + re-send confirmation work

### 4. Sanity-check env

**Console** (`.env`):

- `WELCOME_EMAIL_TEMPLATE` should match the template used for welcomes (usually `welcome.html`)

**Website** (DreamHost `.env` next to the signup PHP):

- Existing `DB_*` and SMTP vars must keep working (logging reuses the same DB connection)

### 5. Expect no historical backfill

Only sends that happen **after** deploy appear in the log. Past DreamHost / Sent-folder mail is not imported.

## Quick verification

1. Restart console → open **Welcome log** (empty is OK)
2. Send a manual one-off from Customers → row appears with source **Manual**
3. Submit a test signup on the website (or wait for a real one) → row with **Website signup**
4. Try sending `welcome.html` again to that customer → confirmation dialog before send
