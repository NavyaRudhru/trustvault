
import threading
import time


MAX_FAILED_ATTEMPTS = 5
WINDOW_SECONDS = 15 * 60

# Key: (client IP address, normalized username)
# Value: (window start time, failed attempt count)
_failed_attempts: dict[tuple[str, str], tuple[float, int]] = {}
_lock = threading.Lock()


def is_login_rate_limited(client_ip: str, username: str) -> bool:
    """Return True when this IP and username exceeded the failure limit."""
    key = (client_ip, username.strip().casefold())
    now = time.monotonic()

    with _lock:
        record = _failed_attempts.get(key)

        if record is None:
            return False

        window_start, attempts = record

        if now - window_start >= WINDOW_SECONDS:
            _failed_attempts.pop(key, None)
            return False

        return attempts >= MAX_FAILED_ATTEMPTS


def record_failed_login(client_ip: str, username: str) -> None:
    """Record a failed login attempt within the current time window."""
    key = (client_ip, username.strip().casefold())
    now = time.monotonic()

    with _lock:
        record = _failed_attempts.get(key)

        if record is None or now - record[0] >= WINDOW_SECONDS:
            _failed_attempts[key] = (now, 1)
        else:
            window_start, attempts = record
            _failed_attempts[key] = (window_start, attempts + 1)


def clear_failed_logins(client_ip: str, username: str) -> None:
    """Clear the failure counter after a successful login."""
    key = (client_ip, username.strip().casefold())

    with _lock:
        _failed_attempts.pop(key, None)


def reset_rate_limits() -> None:
    """Clear counters for isolated tests and local development."""
    with _lock:
        _failed_attempts.clear()
