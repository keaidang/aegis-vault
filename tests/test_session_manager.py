import tempfile
import unittest
from pathlib import Path

from session_manager import RateLimiter, SessionStore


class SessionManagerTests(unittest.TestCase):
    def test_session_persists_in_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "state.sqlite3"
            store = SessionStore(ttl_seconds=60, db_path=db_path)
            session_id, session = store.create("admin", client_ip="127.0.0.1", user_agent="ua")

            reloaded_store = SessionStore(ttl_seconds=60, db_path=db_path)
            reloaded = reloaded_store.get(session_id, client_ip="127.0.0.1", user_agent="ua")

            self.assertIsNotNone(reloaded)
            self.assertEqual(reloaded["user"], session["user"])

    def test_rate_limit_persists_in_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "state.sqlite3"
            limiter = RateLimiter(max_attempts=2, window_seconds=60, lockout_seconds=30, db_path=db_path)
            self.assertEqual(limiter.failure("login", "127.0.0.1"), 0)
            retry_after = limiter.failure("login", "127.0.0.1")
            self.assertGreater(retry_after, 0)

            reloaded_limiter = RateLimiter(max_attempts=2, window_seconds=60, lockout_seconds=30, db_path=db_path)
            self.assertGreater(reloaded_limiter.check("login", "127.0.0.1"), 0)


if __name__ == "__main__":
    unittest.main()
