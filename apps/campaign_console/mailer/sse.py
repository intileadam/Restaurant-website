"""Server-Sent Events helpers with per-session history, replay, and multi-subscriber support."""
from __future__ import annotations
import queue
import threading
import time
import secrets
from dataclasses import dataclass, field
from datetime import datetime


SESSION_TTL_SECONDS = 1800  # 30 minutes after completion


class EventBus:
    """Per-session event bus that stores history and supports multiple subscribers."""

    def __init__(self):
        self._lock = threading.Lock()
        self._history: list[str] = []
        self._subscribers: list[queue.Queue] = []
        self._done = False

    def emit(self, text: str):
        with self._lock:
            self._history.append(text)
            for q in self._subscribers:
                q.put(text)

    def mark_done(self):
        with self._lock:
            self._done = True
            for q in self._subscribers:
                q.put(None)

    @property
    def done(self) -> bool:
        return self._done

    @property
    def history(self) -> list[str]:
        with self._lock:
            return list(self._history)

    def subscribe(self) -> queue.Queue:
        """Create a new subscriber queue that receives history replay + future messages."""
        q: queue.Queue = queue.Queue()
        with self._lock:
            for msg in self._history:
                q.put(msg)
            if self._done:
                q.put(None)
            else:
                self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def stream(self, q: queue.Queue):
        """Generator for Flask Response — yields SSE frames from a subscriber queue."""
        try:
            while True:
                msg = q.get()
                if msg is None:
                    yield "data: __DONE__\n\n"
                    break
                yield f"data: {msg}\n\n"
        finally:
            self.unsubscribe(q)


@dataclass
class SendSession:
    """Tracks a single campaign send operation."""
    send_id: str
    file: str
    subject: str | None
    mode: str
    status: str = "running"
    sent_count: int = 0
    failed_count: int = 0
    total_count: int = 0
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: float | None = None  # monotonic time when finished
    bus: EventBus = field(default_factory=EventBus)


_sessions_lock = threading.Lock()
SEND_SESSIONS: dict[str, SendSession] = {}
ACTIVE_SEND_ID: str | None = None


def create_send_session(
    send_id: str,
    file: str,
    subject: str | None,
    mode: str,
    total: int,
) -> SendSession:
    """Create a new send session and register it as the active send."""
    global ACTIVE_SEND_ID
    sess = SendSession(
        send_id=send_id,
        file=file,
        subject=subject,
        mode=mode,
        total_count=total,
    )
    with _sessions_lock:
        SEND_SESSIONS[send_id] = sess
        ACTIVE_SEND_ID = send_id
    _evict_stale_sessions()
    return sess


def register_send_session(sess: SendSession):
    """Register a pre-built session (used for auto-resume on startup)."""
    global ACTIVE_SEND_ID
    with _sessions_lock:
        SEND_SESSIONS[sess.send_id] = sess
        ACTIVE_SEND_ID = sess.send_id


def get_send_session(send_id: str) -> SendSession | None:
    with _sessions_lock:
        return SEND_SESSIONS.get(send_id)


def get_active_send_id() -> str | None:
    return ACTIVE_SEND_ID


def clear_active_send():
    global ACTIVE_SEND_ID
    with _sessions_lock:
        ACTIVE_SEND_ID = None


def finish_send_session(send_id: str, status: str, sent: int, failed: int):
    """Mark a session as finished and clear the active flag."""
    global ACTIVE_SEND_ID
    sess = get_send_session(send_id)
    if not sess:
        return
    sess.status = status
    sess.sent_count = sent
    sess.failed_count = failed
    sess.finished_at = time.monotonic()
    sess.bus.mark_done()
    with _sessions_lock:
        if ACTIVE_SEND_ID == send_id:
            ACTIVE_SEND_ID = None


def _evict_stale_sessions():
    """Remove sessions that finished more than SESSION_TTL_SECONDS ago."""
    now = time.monotonic()
    with _sessions_lock:
        stale = [
            sid for sid, sess in SEND_SESSIONS.items()
            if sess.finished_at is not None
            and (now - sess.finished_at) > SESSION_TTL_SECONDS
        ]
        for sid in stale:
            del SEND_SESSIONS[sid]


def evict_stale_sessions():
    """Public helper to evict stale sessions on a periodic cadence."""
    _evict_stale_sessions()
