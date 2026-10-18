"""Shared throttle and concurrency bound for in-process HTTP probes.

CLI scanners already receive ``-rl``/``-c`` flags. The Python-based web tools
must respect the same configured limits so autonomous probing cannot exceed the
declared rate.
"""
import threading
import time

from src.adaptix.config import config

_lock = threading.Lock()
_last = {}
_semaphore = None
_semaphore_size = None


def _limits():
    return config('scope.yaml').get('limits', {})


def throttle():
    rate = float(_limits().get('rate_per_second', 1) or 1)
    interval = 1.0 / max(rate, 0.001)
    with _lock:
        now = time.monotonic()
        scheduled = max(now, _last.get('global', 0.0) + interval)
        _last['global'] = scheduled
        wait = scheduled - now
    if wait > 0:
        time.sleep(wait)


def _concurrency_semaphore():
    global _semaphore, _semaphore_size
    size = max(1, int(_limits().get('concurrent_requests', 1) or 1))
    with _lock:
        if _semaphore is None or _semaphore_size != size:
            _semaphore = threading.BoundedSemaphore(size)
            _semaphore_size = size
        return _semaphore


class slot:
    """Bound concurrent in-process probes to the configured limit."""

    def __enter__(self):
        _concurrency_semaphore().acquire()
        return self

    def __exit__(self, *exc):
        _concurrency_semaphore().release()
        return False
