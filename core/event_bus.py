import threading
import time
import json
from collections import defaultdict

_listeners = defaultdict(list)
_event_log = []
_lock = threading.Lock()

MAX_EVENT_LOG = 10000


def emit_event(event_type: str, data: dict):
    """Event yayınla - tüm listener'lara gönder"""
    event = {
        "type": event_type,
        "data": data,
        "timestamp": time.time(),
    }

    with _lock:
        _event_log.append(event)
        if len(_event_log) > MAX_EVENT_LOG:
            _event_log.pop(0)

        for callback in _listeners.get(event_type, []):
            try:
                callback(event)
            except:
                pass

        # Wildcard listeners
        for callback in _listeners.get("*", []):
            try:
                callback(event)
            except:
                pass


def on_event(event_type: str, callback):
    """Event listener kaydet"""
    with _lock:
        _listeners[event_type].append(callback)


def get_recent_events(limit: int = 100, event_type: str = None) -> list:
    """Son event'leri getir (dashboard için)"""
    with _lock:
        events = _event_log[-limit:]
        if event_type:
            events = [e for e in events if e["type"] == event_type]
        return events