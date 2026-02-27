# Resumable Send: Known Concerns & Remediation Status

Review of the resumable campaign send implementation. All concerns below have been
addressed by the scheduler-based queue architecture introduced in this revision.

---

## 1. Bug: Auto-resume runs during preflight import

**Status:** RESOLVED

**Original problem:** The Render start command runs `python -c "import app"` as a preflight check, triggering module-level `_auto_resume_interrupted_sends()` and potentially sending duplicate emails.

**Resolution:** `_auto_resume_interrupted_sends()` has been removed entirely. The persistent scheduler thread is only started when running under Gunicorn (`"gunicorn" in os.getenv("SERVER_SOFTWARE", "")`) or in development mode. The preflight import no longer triggers any background work.

---

## 2. SENT_COUNT only updates when the send finishes

**Status:** RESOLVED

**Original problem:** `CAMPAIGN_SENDS.SENT_COUNT` and `FAILED_COUNT` were only written in the `finally` block of `_send_worker`, leaving the DB stale during multi-hour sends.

**Resolution:** The scheduler calls `update_send_progress()` after every batch, writing `SENT_COUNT`, `FAILED_COUNT`, and `LAST_BATCH_AT` to the DB immediately. The `GET /send/<id>/progress` endpoint reads directly from the DB, so counts are always accurate regardless of restarts or sign-outs.

---

## 3. Multiple Gunicorn workers would cause duplicate sends

**Status:** RESOLVED

**Original problem:** Each Gunicorn worker would independently call `_auto_resume_interrupted_sends()`, spawning duplicate worker threads for the same send.

**Resolution:** The scheduler uses `CLAIMED_BY` and `CLAIMED_AT` columns with an atomic `claim_send()` query. Only one worker can claim a send at a time. Stale claims (>5 minutes) are automatically reclaimed, handling the case where a worker crashes mid-batch.

---

## 4. No way to cancel a running send

**Status:** RESOLVED

**Original problem:** Once "Send" was clicked, there was no mechanism to stop the send.

**Resolution:** Three new endpoints provide full lifecycle control:
- `POST /send/<id>/pause` — sets `STATUS = 'paused'`; scheduler skips paused sends
- `POST /send/<id>/resume` — sets `STATUS = 'running'`; scheduler picks it up
- `POST /send/<id>/cancel` — sets `STATUS = 'cancelled'`; remaining recipients stay as `pending` for audit

The send status page includes Pause, Resume, and Cancel buttons.

---

## 5. In-memory session leak

**Status:** RESOLVED

**Original problem:** `SEND_SESSIONS` dict grew with every send and was never cleaned up.

**Resolution:** `_evict_stale_sessions()` removes sessions that finished more than 30 minutes ago (configurable via `SESSION_TTL_SECONDS`). Eviction runs each time a new session is created.

---

## 6. No progress API for external monitoring

**Status:** RESOLVED

**Original problem:** The only ways to monitor a send were the SSE live stream (requires an open browser and the same process) or the history page (only shows final results).

**Resolution:** `GET /send/<id>/progress` returns accurate real-time counts directly from the DB, including sent, failed, pending, status, and current control parameters. `GET /send/<id>/recipients` returns a paginated list of all recipients with their statuses. Both work reliably across sign-outs, restarts, and redeployments.

---

## Architecture Summary

The send system now uses a **persistent scheduler thread** that polls MySQL every ~5 seconds, replacing per-send daemon threads. Key changes:

- **Queue model:** `POST /queue` bulk-inserts all recipients into `CAMPAIGN_SEND_RESULTS` with `STATUS = 'pending'`, then sets `CAMPAIGN_SENDS.STATUS = 'running'`. No thread is spawned — the scheduler picks it up.
- **Timer-based batching:** The scheduler checks `NOW() - LAST_BATCH_AT >= COOLDOWN_SECONDS` to decide if a new batch is due. No `time.sleep(cooldown)` in the send path.
- **Live-adjustable controls:** `BATCH_SIZE`, `DELAY_MS`, and `COOLDOWN_SECONDS` are read fresh from the DB on each scheduler tick. Changes via `PATCH /send/<id>/controls` take effect on the next batch.
- **DB is the source of truth:** All state lives in MySQL. SSE log streaming is supplementary — the progress page works fully from DB polling.
