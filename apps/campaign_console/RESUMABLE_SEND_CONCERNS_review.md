## Resumable Send Remediation – Adversarial Review

**Scope:** Brownfield review of the resumable send changes as documented in `RESUMABLE_SEND_CONCERNS.md` against the current implementation in `apps/campaign_console` (notably `app.py`, `mailer/db.py`, and `mailer/sse.py`).  
**Note:** The referenced plan file `mysql-backed_send_queue_29eea7af.plan.md` is not present at the given path, so this review is against the code and concern document only.

---

### 1. Auto-resume runs during preflight import

- **Claimed resolution:** `_auto_resume_interrupted_sends()` removed; scheduler thread only started under Gunicorn or in non-production environments.
- **Implementation check:**
  - No references to `_auto_resume_interrupted_sends` or similar auto-resume functions outside the concerns doc.
  - `app.py` defines `_is_gunicorn()` and starts the scheduler inside `with app.app_context(): ... if _is_gunicorn() or APP_ENV != "production": _ensure_scheduler()`.
  - `_ensure_scheduler()` is only invoked:
    - From the `with app.app_context()` block under the Gunicorn/non-production guard.
    - From `__main__` when running the app directly.
    - From runtime endpoints that explicitly call `_ensure_scheduler()` (`/send/<id>/resume`, queueing a new send, and some startup paths).
- **Adversarial concerns:**
  - This design assumes `APP_ENV` is correctly set to `"production"` in the Render/Gunicorn preflight import path; if misconfigured (e.g., defaulting to development), the import would start the scheduler even during preflight.
  - It also assumes `SERVER_SOFTWARE` reliably contains `"gunicorn"` only in live worker processes. If another process sets that value in preflight checks, the scheduler would start.
- **Verdict:** **Resolution is functionally correct given proper environment configuration**, but it is **environment-sensitive**. Consider hardening with:
  - A separate explicit env flag such as `ENABLE_SEND_SCHEDULER=1` checked in addition to `APP_ENV` and `SERVER_SOFTWARE`.
  - Logging when the scheduler starts, including `SERVER_SOFTWARE`, `APP_ENV`, and the calling path, to detect unexpected startup contexts.

---

### 2. `SENT_COUNT`/`FAILED_COUNT` only update when send finishes

- **Claimed resolution:** The scheduler updates progress after every batch; `/send/<id>/progress` reads directly from the DB.
- **Implementation check:**
  - `mailer/db.py`:
    - `update_send_progress(send_id, sent_count, failed_count)` updates `SENT_COUNT`, `FAILED_COUNT`, and `LAST_BATCH_AT` on `CAMPAIGN_SENDS`.
    - `count_send_results(send_id)` aggregates `pending/sent/failed` from `CAMPAIGN_SEND_RESULTS`.
  - `app.py`:
    - `_process_one_batch()` updates per-recipient rows (`mark_recipient_sent` / `mark_recipient_failed`) as each email is attempted.
    - After processing the batch, it calls `dbmod.update_send_progress(send_id, sent_count, failed_count)`.
    - `/send/<id>/progress` uses `get_send_status` and `count_send_results` to expose counts and control parameters.
- **Adversarial concerns:**
  - `sent_count` / `failed_count` are kept in memory inside `_process_one_batch` and written after the batch. If the process crashes mid-batch, DB counts may be stale even though some recipients have updated statuses; however, `/send/<id>/progress` also reports `pending`, `sent`, and `failed` from the results table, so callers can derive truth from those counts.
  - There is no explicit reconciliation step to realign `SENT_COUNT`/`FAILED_COUNT` with the aggregated results after a failure; the counters remain best-effort, not strictly derived.
- **Verdict:** **The core issue (no mid-flight visibility) is addressed.** For stronger robustness:
  - Consider a periodic reconciliation job that recalculates `SENT_COUNT`/`FAILED_COUNT` from `CAMPAIGN_SEND_RESULTS` for long-running or interrupted sends.

---

### 3. Multiple Gunicorn workers causing duplicate sends

- **Claimed resolution:** `CLAIMED_BY`/`CLAIMED_AT` with an atomic `claim_send()` gate processing to a single worker at a time, with 5-minute stale claim eviction.
- **Implementation check:**
  - `mailer/db.py`:
    - `ensure_campaign_tables()` creates `CLAIMED_BY` and `CLAIMED_AT` columns.
    - `fetch_ready_sends()` selects only `STATUS = 'running'` sends whose cooldown has elapsed.
    - `claim_send(send_id, worker_id)`:
      - `UPDATE CAMPAIGN_SENDS SET CLAIMED_BY = %s, CLAIMED_AT = UTC_TIMESTAMP()`
      - Guarded by `WHERE SEND_ID = %s AND STATUS = 'running' AND (CLAIMED_BY IS NULL OR CLAIMED_BY = %s OR TIMESTAMPDIFF(SECOND, CLAIMED_AT, UTC_TIMESTAMP()) > 300)`.
      - Returns `True` iff `rowcount > 0`.
    - `release_claim(send_id)` clears `CLAIMED_BY` and `CLAIMED_AT` after each batch.
  - `app.py`:
    - `_scheduler_loop()` runs in each process, but for each `send_row` it calls `claim_send` and only processes a batch if the claim succeeds.
- **Adversarial concerns:**
  - Two workers can concurrently call `fetch_ready_sends()` and see the same rows, but the `UPDATE`-with-guard ensures only one actually claims at the DB level.
  - The stale-claim window (300 seconds) is fixed; in pathological slow-batch scenarios (e.g., SMTP hangs), another worker might reclaim and start sending again while the original worker is still alive but blocked. This could, in theory, cause overlapping sends if the original process resumes and continues with stale knowledge.
- **Verdict:** **The design correctly avoids duplicate processing in normal conditions and on clean crashes.** Residual risk remains if:
  - A worker hangs without progress but keeps the process alive longer than expected.
  - Network-level partial failures cause long delays.  
  Mitigations to consider:
  - Shorten or make the stale-claim window configurable per environment.
  - Track per-batch heartbeat timestamps in a separate field and base staleness on “time since last successful batch” rather than just `CLAIMED_AT`.

---

### 4. No way to cancel a running send

- **Claimed resolution:** New pause/resume/cancel endpoints and UI controls; scheduler respects `STATUS`.
- **Implementation check:**
  - `mailer/db.py`:
    - `pause_send(send_id)` updates `STATUS` from `running` to `paused`.
    - `resume_send(send_id)` updates `STATUS` from `paused` to `running`.
    - `cancel_send(send_id)` updates `STATUS` to `cancelled` (and sets `FINISHED_AT`) for `STATUS IN ('running', 'paused', 'queued')`.
  - `app.py`:
    - `/send/<id>/pause`, `/send/<id>/resume`, `/send/<id>/cancel` endpoints exist and return structured JSON with conflict handling.
    - Endpoints also update in-memory `SendSession` state and emit SSE messages.
    - `_scheduler_loop()` only processes sends with `STATUS = 'running'` from `fetch_ready_sends()`, so paused/cancelled sends are not picked up for new batches.
- **Adversarial concerns:**
  - Cancellation is cooperative and batch-granular: if you cancel mid-batch, in-flight SMTP operations will still complete; “remaining recipients” is defined as “not yet dequeued by the current batch”.
  - There is no explicit DB-level “hard stop” for the current batch; if SMTP is slow or stuck, operator expectations (“cancel now”) may not match behavior (“cancel after this batch fully finishes or errors”).
  - UI-level guarantees (e.g., buttons present and wired correctly) are assumed from the doc; the backend supports them but there is no automated acceptance test asserting end-to-end semantics.
- **Verdict:** **The basic lifecycle controls are correctly implemented.** For stricter semantics:
  - Document in user-facing copy that cancellation is batch-granular, not per-email instantaneous.
  - Optionally add a per-recipient timeout or overall batch watchdog to bound how long a “cancelled” send can continue trying in-flight deliveries.

---

### 5. In-memory session leak

- **Claimed resolution:** `_evict_stale_sessions()` removes sessions finished more than 30 minutes ago; eviction runs each time a new session is created.
- **Implementation check:**
  - `mailer/sse.py`:
    - `SESSION_TTL_SECONDS = 1800` (30 minutes).
    - `SEND_SESSIONS` is a global dict of `SendSession`s; `finish_send_session` sets `finished_at = time.monotonic()` and marks the bus as done.
    - `_evict_stale_sessions()` walks `SEND_SESSIONS` and deletes entries whose `finished_at` is older than `SESSION_TTL_SECONDS`.
    - `create_send_session()` calls `_evict_stale_sessions()` after inserting a new session.
- **Adversarial concerns:**
  - Eviction only runs when **new** sends are created. If an operator never starts a new send after a long-running one finishes, stale sessions will persist in memory indefinitely. This is bounded by the number of sends per process lifetime, but it is not strictly TTL-enforced over wall-clock time.
  - There is no explicit cap on the number of concurrent sessions or overall memory footprint for `SEND_SESSIONS` beyond TTL + operational patterns.
- **Verdict:** **The leak during continuous usage (many sends) is addressed; memory will not grow unbounded over time in normal operations.** For a more robust guarantee:
  - Consider running `_evict_stale_sessions()` on any periodic path, e.g., inside `_scheduler_loop()` or via a lightweight timer, to enforce TTL even when no new sends are created.

---

### 6. No progress API for external monitoring

- **Claimed resolution:** `/send/<id>/progress` and `/send/<id>/recipients` backed by DB state.
- **Implementation check:**
  - `/send/<id>/progress`:
    - Fetches `CAMPAIGN_SENDS` row via `get_send_status`.
    - Aggregates recipient counts via `count_send_results`.
    - Returns `status`, `total`, `sent`, `failed`, `pending`, and control parameters plus timestamps (`started_at`, `finished_at`, `last_batch_at`).
  - `/send/<id>/recipients`:
    - Uses `fetch_send_recipients_paginated` with optional `status` filter.
    - Returns IDs, email, names, status, error messages, and `ATTEMPTED_AT`.
- **Adversarial concerns:**
  - Progress API is read-only, which is good, but there is no explicit rate-limiting or auth boundary discussed here; the security model depends on broader app auth (e.g., session-based admin access). Any exposure of these endpoints outside authenticated console routes should be audited separately.
  - If a send is cancelled, `FINISHED_AT` is set but `SENT_COUNT`/`FAILED_COUNT` may not equal the total aggregated recipient counts if the cancel occurred mid-batch (see Section 2). External consumers should treat recipient counts as canonical.
- **Verdict:** **The lack of a progress API is fully remediated.** Further hardening could include:
  - Explicit documentation that `sent + failed + pending` from recipients is canonical, and `SENT_COUNT`/`FAILED_COUNT` are summarized convenience fields.

---

### 7. Scheduler architecture & DB as source of truth

- **Claimed architecture summary:** Persistent scheduler thread, DB-based queue model, timer-based batching, live-adjustable controls, and DB as source of truth.
- **Implementation check:**
  - **Persistent scheduler:**
    - `_scheduler_loop()` is a daemon thread with a `SCHEDULER_POLL_INTERVAL` of 5 seconds.
    - It uses `fetch_ready_sends` + `claim_send` + `release_claim` to process one batch at a time per send, across workers.
  - **Queue model:**
    - `insert_campaign_send` + `bulk_insert_send_recipients` pre-populate `CAMPAIGN_SEND_RESULTS` with `STATUS = 'pending'`.
    - No per-send daemon threads are spawned; one global scheduler loop handles all sends.
  - **Timer-based batching:**
    - `fetch_ready_sends` enforces cooldown via `TIMESTAMPDIFF(SECOND, LAST_BATCH_AT, UTC_TIMESTAMP()) >= COALESCE(COOLDOWN_SECONDS, 0)`.
    - `_process_one_batch` itself does not `sleep` between batches; delay is implemented via the scheduler poll interval and `delay_ms` inside SMTP send calls.
  - **Live-adjustable controls:**
    - `/send/<id>/controls` validates and updates `BATCH_SIZE`, `DELAY_MS`, `COOLDOWN_SECONDS` using `update_send_controls`.
    - `_process_one_batch` reads these values fresh from `send_row`.
  - **DB as source of truth:**
    - All durable state for sends and recipients is in MySQL (`CAMPAIGN_SENDS`, `CAMPAIGN_SEND_RESULTS`).
    - SSE log streaming and `SendSession` are supplementary, in-memory views over DB-backed progress.
- **Adversarial concerns:**
  - The scheduler thread is a single point of throughput; if you need high concurrency under heavy campaigns, this design may become CPU-bound or I/O-bound in one process. Scaling out horizontally is mediated by Gunicorn worker count + `claim_send`, which may be sufficient but should be load-tested.
  - Failure modes of the scheduler thread itself (e.g., repeated exceptions) are logged but not actively recovered beyond “retry next tick”; there is no backoff or alerting at this layer.
- **Verdict:** **Implementation is consistent with the documented architecture.** Operational limits now depend on:
  - Proper tuning of `BATCH_SIZE`, `DELAY_MS`, and `COOLDOWN_SECONDS`.
  - Gunicorn worker count and DB performance.

---

### Summary Assessment

- **Overall:** The remediation described in `RESUMABLE_SEND_CONCERNS.md` **largely matches the current codebase** and addresses the original brownfield issues without obvious correctness regressions.
- **Key residual risks:** Environment-sensitive scheduler startup, fixed 5-minute stale-claim window, best-effort summary counters vs. canonical per-recipient counts, and TTL eviction only on new sessions.
- **Recommended follow-ups:**
  1. Add an explicit feature flag for scheduler startup and log scheduler activation context.
  2. Make the stale-claim timeout configurable and consider a heartbeat-based staleness metric.
  3. Document E2E semantics for cancel/pause, especially batch-granularity behavior.
  4. Wire `_evict_stale_sessions()` into a periodic path (e.g., scheduler loop) to enforce TTL independently of new sends.

