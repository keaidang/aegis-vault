import json
import unittest

from audit_logger import _compute_chain_hash, _parse_audit_line


class AuditLoggerTests(unittest.TestCase):
    def test_parse_logging_formatted_audit_line(self):
        event = {
            "timestamp": "2026-04-24T16:20:45.833025Z",
            "event_type": "AUTH_LOGOUT",
            "user": "admin",
            "client_ip": "127.0.0.1",
            "success": True,
            "details": {},
            "_hash": "abc",
            "_chain_hash": _compute_chain_hash("abc"),
        }
        line = f"2026-04-25 00:20:45,833 - AUDIT - INFO - {json.dumps(event)}"

        parsed = _parse_audit_line(line)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["event_type"], "AUTH_LOGOUT")
        self.assertEqual(parsed["user"], "admin")

    def test_parse_jsonl_audit_line(self):
        event = {
            "timestamp": "2026-04-24T16:20:45.833025Z",
            "event_type": "FILE_UPLOADED",
            "user": "admin",
            "client_ip": "127.0.0.1",
            "success": True,
            "details": {"filename": "a.txt"},
            "_hash": "abc",
            "_chain_hash": _compute_chain_hash("abc"),
        }

        parsed = _parse_audit_line(json.dumps(event))

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["event_type"], "FILE_UPLOADED")

    def test_parse_ignores_non_audit_lines(self):
        self.assertIsNone(_parse_audit_line("INFO: app started"))


if __name__ == "__main__":
    unittest.main()
