import copy
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path


def _default_state_db_path() -> Path:
    data_dir = Path(os.getenv("AEGIS_DATA_DIR", "./data"))
    return Path(os.getenv("AEGIS_STATE_DB", str(data_dir / "runtime_state.sqlite3")))


class SessionStore:
    def __init__(self, ttl_seconds: int, db_path: str | Path | None = None):
        self.ttl_seconds = ttl_seconds
        self.db_path = Path(db_path) if db_path else _default_state_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                data TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    @staticmethod
    def _fingerprint(client_ip: str | None, user_agent: str | None) -> str | None:
        if not (client_ip or user_agent):
            return None
        fingerprint_str = f"{client_ip}:{user_agent}"
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()

    def create(
        self,
        user: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
        mode: str = "vault",
    ) -> tuple[str, dict]:
        now = int(time.time())
        session_id = secrets.token_urlsafe(32)
        session = {
            "user": user,
            "mode": mode,
            "csrf_token": secrets.token_urlsafe(24),
            "created_at": now,
            "expires_at": now + self.ttl_seconds,
            "client_ip": client_ip,
            "client_fingerprint": self._fingerprint(client_ip, user_agent),
        }
        with self._lock:
            self._conn.execute(
                "INSERT INTO sessions (session_id, user, expires_at, data) VALUES (?, ?, ?, ?)",
                (session_id, user, session["expires_at"], json.dumps(session, ensure_ascii=False)),
            )
            self._conn.commit()
        return session_id, copy.deepcopy(session)

    def get(self, session_id: str | None, client_ip: str | None = None, user_agent: str | None = None) -> dict | None:
        if not session_id:
            return None
        now = int(time.time())
        with self._lock:
            row = self._conn.execute(
                "SELECT data, expires_at FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if not row:
                return None
            if int(row[1]) <= now:
                self._conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                self._conn.commit()
                return None

            session = json.loads(row[0])
            current_fingerprint = self._fingerprint(client_ip, user_agent)
            if session.get("client_fingerprint") and current_fingerprint and session["client_fingerprint"] != current_fingerprint:
                session["_fingerprint_mismatch"] = True

            session["expires_at"] = now + self.ttl_seconds
            self._conn.execute(
                "UPDATE sessions SET expires_at = ?, data = ? WHERE session_id = ?",
                (session["expires_at"], json.dumps(session, ensure_ascii=False), session_id),
            )
            self._conn.commit()
            return copy.deepcopy(session)

    def _mutate_session(self, session_id: str | None, mutator) -> None:
        if not session_id:
            return
        with self._lock:
            row = self._conn.execute("SELECT data FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if not row:
                return
            session = json.loads(row[0])
            changed = mutator(session)
            if changed:
                self._conn.execute(
                    "UPDATE sessions SET expires_at = ?, data = ? WHERE session_id = ?",
                    (int(session.get("expires_at", 0)), json.dumps(session, ensure_ascii=False), session_id),
                )
                self._conn.commit()

    def set_active_note(self, session_id: str | None, note_id: str, note: dict) -> None:
        def mutator(session: dict) -> bool:
            session["active_note"] = {"note_id": note_id, "note": copy.deepcopy(note)}
            return True

        self._mutate_session(session_id, mutator)

    def get_active_note(self, session_id: str | None, note_id: str | None = None) -> dict | None:
        if not session_id:
            return None
        with self._lock:
            row = self._conn.execute("SELECT data FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if not row:
                return None
            session = json.loads(row[0])
            active_note = session.get("active_note")
            if not isinstance(active_note, dict):
                return None
            if note_id is not None and active_note.get("note_id") != note_id:
                return None
            return copy.deepcopy(active_note)

    def clear_active_note(self, session_id: str | None, note_id: str | None = None) -> None:
        def mutator(session: dict) -> bool:
            active_note = session.get("active_note")
            if not isinstance(active_note, dict):
                return False
            if note_id is not None and active_note.get("note_id") != note_id:
                return False
            session.pop("active_note", None)
            return True

        self._mutate_session(session_id, mutator)

    def destroy(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            self._conn.commit()

    def invalidate_user(self, username: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE user = ?", (username,))
            self._conn.commit()

    def cleanup(self) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            self._conn.commit()

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions")
            self._conn.commit()


class RateLimiter:
    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 600,
        lockout_seconds: int = 900,
        db_path: str | Path | None = None,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.db_path = Path(db_path) if db_path else _default_state_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limits (
                scope TEXT NOT NULL,
                key TEXT NOT NULL,
                count INTEGER NOT NULL,
                window_start INTEGER NOT NULL,
                locked_until INTEGER NOT NULL,
                PRIMARY KEY (scope, key)
            )
            """
        )
        self._conn.commit()

    def check(self, scope: str, key: str) -> int:
        now = int(time.time())
        with self._lock:
            record = self._conn.execute(
                "SELECT count, window_start, locked_until FROM rate_limits WHERE scope = ? AND key = ?",
                (scope, key),
            ).fetchone()
            if not record:
                return 0
            _, window_start, locked_until = record
            if locked_until > now:
                return locked_until - now
            if now - window_start > self.window_seconds:
                self._conn.execute("DELETE FROM rate_limits WHERE scope = ? AND key = ?", (scope, key))
                self._conn.commit()
            return 0

    def failure(self, scope: str, key: str) -> int:
        now = int(time.time())
        with self._lock:
            record = self._conn.execute(
                "SELECT count, window_start, locked_until FROM rate_limits WHERE scope = ? AND key = ?",
                (scope, key),
            ).fetchone()
            if not record or now - int(record[1]) > self.window_seconds:
                count = 0
                window_start = now
                locked_until = 0
            else:
                count, window_start, locked_until = map(int, record)

            count += 1
            if count >= self.max_attempts:
                locked_until = now + self.lockout_seconds
                count = 0
                window_start = now

            self._conn.execute(
                """
                INSERT INTO rate_limits (scope, key, count, window_start, locked_until)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(scope, key) DO UPDATE SET
                    count = excluded.count,
                    window_start = excluded.window_start,
                    locked_until = excluded.locked_until
                """,
                (scope, key, count, window_start, locked_until),
            )
            self._conn.commit()
            return max(0, locked_until - now)

    def reset(self, scope: str, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM rate_limits WHERE scope = ? AND key = ?", (scope, key))
            self._conn.commit()
