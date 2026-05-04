"""
审计日志系统 - JSONL 格式记录安全事件，支持链式哈希防篡改。
"""
import hashlib
import json
import os
import threading
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_DIR", "./data")) / "audit.log"
AUDIT_LOG_HASH_PATH = Path(os.getenv("AUDIT_LOG_DIR", "./data")) / "audit.hash"
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

audit_lock = threading.RLock()


class AuditEvent:
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILED = "AUTH_LOGIN_FAILED"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    CHECKIN_SUCCESS = "CHECKIN_SUCCESS"
    CHECKIN_FAILED = "CHECKIN_FAILED"
    DURESS_TRIGGERED = "DURESS_TRIGGERED"
    FILE_UPLOADED = "FILE_UPLOADED"
    FILE_DOWNLOADED = "FILE_DOWNLOADED"
    FILE_DELETED = "FILE_DELETED"
    NOTE_ACCESS_SUCCESS = "NOTE_ACCESS_SUCCESS"
    NOTE_ACCESS_FAILED = "NOTE_ACCESS_FAILED"
    NOTE_FEATURE_UPDATED = "NOTE_FEATURE_UPDATED"
    NOTE_SAVED = "NOTE_SAVED"
    NOTE_DELETED = "NOTE_DELETED"
    NOTE_ATTACHMENT_UPLOADED = "NOTE_ATTACHMENT_UPLOADED"
    NOTE_ATTACHMENT_DOWNLOADED = "NOTE_ATTACHMENT_DOWNLOADED"
    NOTE_ATTACHMENT_DELETED = "NOTE_ATTACHMENT_DELETED"
    AUDIT_VIEWED = "AUDIT_VIEWED"
    SYSTEM_DESTROYED = "SYSTEM_DESTROYED"
    SYSTEM_RESET = "SYSTEM_RESET"
    USER_CREATED = "USER_CREATED"
    USER_PASSWORD_UPDATED = "USER_PASSWORD_UPDATED"
    CHECKIN_CODE_UPDATED = "CHECKIN_CODE_UPDATED"
    DURESS_CODE_UPDATED = "DURESS_CODE_UPDATED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    INVALID_REQUEST = "INVALID_REQUEST"


def _compute_chain_hash(current_hash: str, previous_hash: str = "") -> str:
    return hashlib.sha256(f"{previous_hash}:{current_hash}".encode()).hexdigest()


def _event_hash(event_data: dict) -> str:
    event_json = json.dumps(event_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(event_json.encode()).hexdigest()


def _get_previous_chain_hash() -> str:
    if not AUDIT_LOG_HASH_PATH.exists():
        return ""
    try:
        return AUDIT_LOG_HASH_PATH.read_text().strip()
    except OSError:
        return ""


def _parse_audit_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        event = json.loads(line)
        return event if isinstance(event, dict) else None
    except json.JSONDecodeError:
        pass

    # Backward compatibility for previous Python logging format:
    # "time - AUDIT - INFO - {json}"
    if " - AUDIT - " not in line:
        return None
    try:
        payload = line.split(" - AUDIT - ", 1)[1].strip()
        if " - " in payload:
            payload = payload.split(" - ", 1)[1].strip()
        event = json.loads(payload)
    except (json.JSONDecodeError, IndexError):
        return None
    return event if isinstance(event, dict) else None


def _write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    os.replace(tmp_path, path)


def log_event(
    event_type: str,
    user: str | None = None,
    client_ip: str | None = None,
    details: dict | None = None,
    success: bool = True,
) -> None:
    with audit_lock:
        event_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "user": user or "anonymous",
            "client_ip": client_ip or "unknown",
            "success": success,
            "details": details or {},
        }
        event_hash = _event_hash(event_data)
        chain_hash = _compute_chain_hash(event_hash, _get_previous_chain_hash())
        event_data["_hash"] = event_hash
        event_data["_chain_hash"] = chain_hash

        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(event_data, ensure_ascii=False, separators=(",", ":")) + "\n")
            log_file.flush()
            os.fsync(log_file.fileno())
        _write_text_atomic(AUDIT_LOG_HASH_PATH, chain_hash)


def verify_audit_chain() -> bool:
    if not AUDIT_LOG_PATH.exists():
        return True

    try:
        with audit_lock:
            previous_chain_hash = ""
            parsed_count = 0
            for line in AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines():
                event = _parse_audit_line(line)
                if event is None:
                    continue
                parsed_count += 1
                event_hash = event.get("_hash", "")
                chain_hash = event.get("_chain_hash", "")
                if chain_hash != _compute_chain_hash(event_hash, previous_chain_hash):
                    return False
                previous_chain_hash = chain_hash
            return parsed_count > 0 or AUDIT_LOG_PATH.stat().st_size == 0
    except OSError:
        return False


def get_audit_logs(limit: int = 100, event_type: str | None = None) -> list[dict]:
    if not AUDIT_LOG_PATH.exists():
        return []

    logs = []
    with audit_lock:
        try:
            lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []

    for line in reversed(lines[-limit * 10:]):
        event = _parse_audit_line(line)
        if event is None:
            continue
        if event_type is None or event.get("event_type") == event_type:
            logs.append(event)
        if len(logs) >= limit:
            break
    return logs
