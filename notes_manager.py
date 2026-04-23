import json
import threading
import time
import uuid
from pathlib import Path

from crypto import BASE_DIR, CryptoManager


NOTES_CONFIG_PATH = BASE_DIR / "notes_config.json"
NOTES_LOCK = threading.RLock()


class NotesManager:
    @staticmethod
    def _load_config() -> dict:
        if not NOTES_CONFIG_PATH.exists():
            return {"enabled_users": []}
        try:
            with open(NOTES_CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    enabled_users = data.get("enabled_users", [])
                    if isinstance(enabled_users, list):
                        return {"enabled_users": [str(item) for item in enabled_users]}
        except Exception:
            pass
        return {"enabled_users": []}

    @staticmethod
    def _save_config(config: dict) -> None:
        NOTES_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(NOTES_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)

    @staticmethod
    def is_enabled(username: str) -> bool:
        CryptoManager.validate_username(username)
        with NOTES_LOCK:
            config = NotesManager._load_config()
            return username in config["enabled_users"]

    @staticmethod
    def set_enabled(username: str, enabled: bool) -> None:
        CryptoManager.validate_username(username)
        with NOTES_LOCK:
            config = NotesManager._load_config()
            enabled_users = {item for item in config["enabled_users"] if item in CryptoManager.list_supported_users()}
            if enabled:
                enabled_users.add(username)
            else:
                enabled_users.discard(username)
            NotesManager._save_config({"enabled_users": sorted(enabled_users)})

    @staticmethod
    def note_keys_exist(username: str) -> bool:
        return (
            CryptoManager.get_note_key_path(username).exists()
            and CryptoManager.get_note_public_key_path(username).exists()
        )

    @staticmethod
    def has_any_notes(username: str) -> bool:
        notes_root = CryptoManager.get_notes_root(username)
        return any(path.is_dir() for path in notes_root.iterdir())

    @staticmethod
    def ensure_note_access(username: str, password: str):
        if not NotesManager.is_enabled(username):
            return None
        return CryptoManager.load_note_private_key(username, password)

    @staticmethod
    def authenticate(password: str) -> dict | None:
        if not password:
            return None
        for username in CryptoManager.list_supported_users():
            if not NotesManager.is_enabled(username):
                continue
            try:
                private_key = CryptoManager.load_note_private_key(username, password)
            except ValueError:
                private_key = None
            if private_key is not None:
                return {"user": username}
        return None

    @staticmethod
    def list_note_entries(username: str) -> list[dict]:
        notes_root = CryptoManager.get_notes_root(username)
        entries = []
        for index, note_dir in enumerate(
            sorted((path for path in notes_root.iterdir() if path.is_dir()), key=lambda item: item.name, reverse=True),
            start=1,
        ):
            encrypted_path = note_dir / "note.aes"
            try:
                stat_result = encrypted_path.stat() if encrypted_path.exists() else note_dir.stat()
                updated_at = int(stat_result.st_mtime)
                created_at = int(stat_result.st_ctime)
            except OSError:
                updated_at = int(time.time())
                created_at = updated_at

            entries.append(
                {
                    "note_id": note_dir.name,
                    "label": f"加密笔记 {index:02d}",
                    "created_at": created_at,
                    "updated_at": updated_at,
                }
            )
        return entries

    @staticmethod
    def list_notes(username: str, private_key) -> list[dict]:
        notes_root = CryptoManager.get_notes_root(username)
        notes = []
        for note_dir in sorted((path for path in notes_root.iterdir() if path.is_dir()), key=lambda item: item.name):
            note_id = note_dir.name
            try:
                note = NotesManager.get_note(username, note_id, private_key)
            except Exception:
                continue
            notes.append(note)
        notes.sort(key=lambda item: item.get("updated_at", 0), reverse=True)
        return notes

    @staticmethod
    def get_note(username: str, note_id: str, private_key) -> dict:
        payload = CryptoManager.decrypt_note_payload(username, note_id, private_key)
        note = json.loads(payload.decode("utf-8"))
        note["note_id"] = note_id
        note.setdefault("title", "未命名笔记")
        note.setdefault("content", "")
        note.setdefault("created_at", int(time.time()))
        note.setdefault("updated_at", note["created_at"])
        note.setdefault("modification_history", [note["updated_at"]])
        note.setdefault("attachments", [])
        return note

    @staticmethod
    def save_note(username: str, note_id: str | None, title: str, content: str, private_key) -> str:
        title = (title or "").strip() or "未命名笔记"
        content = content or ""
        now = int(time.time())

        attachments = []
        created_at = now
        modification_history = [now]
        if note_id:
            existing = NotesManager.get_note(username, note_id, private_key)
            attachments = existing.get("attachments", [])
            created_at = existing.get("created_at", now)
            modification_history = existing.get("modification_history", [created_at])
            modification_history.append(now)
        else:
            note_id = uuid.uuid4().hex

        note = {
            "title": title[:120],
            "content": content[:200000],
            "created_at": created_at,
            "updated_at": now,
            "modification_history": modification_history[-200:],
            "attachments": attachments,
        }
        CryptoManager.encrypt_note_payload(
            json.dumps(note, ensure_ascii=False).encode("utf-8"),
            username=username,
            note_id=note_id,
        )
        return note_id

    @staticmethod
    def delete_note(username: str, note_id: str) -> None:
        note_dir = CryptoManager.get_note_path(username, note_id)
        if not (note_dir / "note.aes").exists():
            raise FileNotFoundError(note_id)
        CryptoManager.secure_delete_path(note_dir, passes=1)

    @staticmethod
    def add_attachment(username: str, note_id: str, filename: str, content: bytes, private_key) -> dict:
        note = NotesManager.get_note(username, note_id, private_key)
        attachment_id = uuid.uuid4().hex
        safe_name = CryptoManager.normalize_filename(filename)
        attachment_path = NotesManager._attachment_path(username, note_id, attachment_id)
        CryptoManager.encrypt_payload(
            content,
            public_key_path=CryptoManager.get_note_public_key_path(username),
            target_path=attachment_path,
        )

        attachment = {
            "attachment_id": attachment_id,
            "name": safe_name,
            "size_bytes": len(content),
            "created_at": int(time.time()),
        }
        note.setdefault("attachments", []).append(attachment)
        NotesManager._persist_note(username, note_id, note, private_key)
        return attachment

    @staticmethod
    def list_attachments(username: str, note_id: str, private_key) -> list[dict]:
        note = NotesManager.get_note(username, note_id, private_key)
        return note.get("attachments", [])

    @staticmethod
    def get_attachment(username: str, note_id: str, attachment_id: str, private_key) -> tuple[dict, bytes]:
        note = NotesManager.get_note(username, note_id, private_key)
        attachment = next(
            (item for item in note.get("attachments", []) if item.get("attachment_id") == attachment_id),
            None,
        )
        if not attachment:
            raise FileNotFoundError(attachment_id)
        content = CryptoManager.decrypt_payload(
            NotesManager._attachment_path(username, note_id, attachment_id),
            private_key,
        )
        return attachment, content

    @staticmethod
    def delete_attachment(username: str, note_id: str, attachment_id: str, private_key) -> dict:
        note = NotesManager.get_note(username, note_id, private_key)
        attachments = note.get("attachments", [])
        attachment = next((item for item in attachments if item.get("attachment_id") == attachment_id), None)
        if not attachment:
            raise FileNotFoundError(attachment_id)
        note["attachments"] = [item for item in attachments if item.get("attachment_id") != attachment_id]
        CryptoManager.secure_delete_path(NotesManager._attachment_path(username, note_id, attachment_id), passes=1)
        NotesManager._persist_note(username, note_id, note, private_key)
        return attachment

    @staticmethod
    def _attachment_path(username: str, note_id: str, attachment_id: str) -> Path:
        safe_attachment_id = CryptoManager.normalize_filename(attachment_id)
        attachments_dir = CryptoManager.get_note_path(username, note_id) / "attachments"
        attachments_dir.mkdir(parents=True, exist_ok=True)
        return attachments_dir / f"{safe_attachment_id}.aes"

    @staticmethod
    def _persist_note(username: str, note_id: str, note: dict, private_key) -> None:
        now = int(time.time())
        note["updated_at"] = now
        history = note.setdefault("modification_history", [])
        history.append(now)
        note["modification_history"] = history[-200:]
        CryptoManager.encrypt_note_payload(
            json.dumps(note, ensure_ascii=False).encode("utf-8"),
            username=username,
            note_id=note_id,
        )
