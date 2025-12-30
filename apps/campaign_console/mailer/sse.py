"""Server-Sent Events helpers to stream logs to the browser.
Usage: return Response(stream_with_context(generator()), mimetype='text/event-stream')
"""
from __future__ import annotations
import queue, threading


class EventBus:
    def __init__(self):
        self.q = queue.Queue()


    def emit(self, text: str):
        self.q.put(text)


    def stream(self):
        # Generator for Flask Response
        while True:
            msg = self.q.get()
            yield f"data: {msg}\n\n"


# Singleton bus per /send session (simple for single-user local runs).
GLOBAL_BUS = EventBus()