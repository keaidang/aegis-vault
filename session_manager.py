import secrets
import threading
import time


class SessionStore:
    def __init__(self, ttl_seconds: int):
        self.ttl_seconds = ttl_seconds
        self._sessions = {}
        self._lock = threading.RLock()

    def create(self, user: str, private_key) -> tuple[str, dict]:
        now = int(time.time())
        session_id = secrets.token_urlsafe(32)
        session = {
            "user": user,
            "private_key": private_key,
            "csrf_token": secrets.token_urlsafe(24),
            "created_at": now,
            "expires_at": now + self.ttl_seconds,
        }
        with self._lock:
            self._sessions[session_id] = session
        return session_id, session.copy()

    def get(self, session_id: str | None) -> dict | None:
        if not session_id:
            return None
        now = int(time.time())
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            if session["expires_at"] <= now:
                self._sessions.pop(session_id, None)
                return None
            session["expires_at"] = now + self.ttl_seconds
            return session.copy()

    def destroy(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)

    def invalidate_user(self, username: str) -> None:
        with self._lock:
            stale_ids = [
                session_id
                for session_id, session in self._sessions.items()
                if session["user"] == username
            ]
            for session_id in stale_ids:
                self._sessions.pop(session_id, None)

    def cleanup(self) -> None:
        now = int(time.time())
        with self._lock:
            expired_ids = [
                session_id
                for session_id, session in self._sessions.items()
                if session["expires_at"] <= now
            ]
            for session_id in expired_ids:
                self._sessions.pop(session_id, None)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 600, lockout_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._records = {}
        self._lock = threading.RLock()

    def check(self, scope: str, key: str) -> int:
        now = int(time.time())
        with self._lock:
            record = self._records.get((scope, key))
            if not record:
                return 0
            if record["locked_until"] > now:
                return record["locked_until"] - now
            if now - record["window_start"] > self.window_seconds:
                self._records.pop((scope, key), None)
                return 0
            return 0

    def failure(self, scope: str, key: str) -> int:
        now = int(time.time())
        with self._lock:
            record = self._records.get((scope, key))
            if not record or now - record["window_start"] > self.window_seconds:
                record = {"count": 0, "window_start": now, "locked_until": 0}

            record["count"] += 1
            if record["count"] >= self.max_attempts:
                record["locked_until"] = now + self.lockout_seconds
                record["count"] = 0
                record["window_start"] = now

            self._records[(scope, key)] = record
            return max(0, record["locked_until"] - now)

    def reset(self, scope: str, key: str) -> None:
        with self._lock:
            self._records.pop((scope, key), None)
