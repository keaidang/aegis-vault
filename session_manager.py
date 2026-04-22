import secrets
import threading
import time
import gc
import hashlib
import ctypes
import os
from cryptography.hazmat.primitives import serialization


def _try_mlock(data: bytes) -> bool:
    """尝试使用 mlock 锁定内存（仅 Linux）"""
    if not hasattr(ctypes, 'CDLL'):
        return False
    try:
        if not hasattr(os, 'uname') or os.uname().sysname != 'Linux':
            return False
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # mlock(addr, len)
        result = libc.mlock(ctypes.c_char_p(data), ctypes.c_size_t(len(data)))
        return result == 0
    except Exception:
        return False


def _try_munlock(data: bytes) -> bool:
    """尝试使用 munlock 解锁内存"""
    if not hasattr(ctypes, 'CDLL'):
        return False
    try:
        if not hasattr(os, 'uname') or os.uname().sysname != 'Linux':
            return False
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # munlock(addr, len)
        result = libc.munlock(ctypes.c_char_p(data), ctypes.c_size_t(len(data)))
        return result == 0
    except Exception:
        return False


class SessionStore:
    def __init__(self, ttl_seconds: int):
        self.ttl_seconds = ttl_seconds
        self._sessions = {}
        self._lock = threading.RLock()

    def create(self, user: str, private_key, client_ip: str | None = None, user_agent: str | None = None) -> tuple[str, dict]:
        now = int(time.time())
        session_id = secrets.token_urlsafe(32)
        
        # 计算客户端特征哈希
        client_fingerprint = None
        if client_ip or user_agent:
            fingerprint_str = f"{client_ip}:{user_agent}"
            client_fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        
        # 尝试 mlock 私钥数据（防止交换到磁盘）
        # 注意：这只对序列化的私钥字节有效
        mlock_success = False
        try:
            if private_key:
                # 获取私钥的 PEM 表示
                from cryptography.hazmat.primitives import serialization
                pem_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                mlock_success = _try_mlock(pem_bytes)
        except Exception:
            pass
        
        session = {
            "user": user,
            "private_key": private_key,
            "csrf_token": secrets.token_urlsafe(24),
            "created_at": now,
            "expires_at": now + self.ttl_seconds,
            "client_ip": client_ip,
            "client_fingerprint": client_fingerprint,
            "_mlock_enabled": mlock_success,
        }
        with self._lock:
            self._sessions[session_id] = session
        return session_id, session.copy()

    def get(self, session_id: str | None, client_ip: str | None = None, user_agent: str | None = None) -> dict | None:
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
            
            # 验证客户端特征
            if client_ip or user_agent:
                fingerprint_str = f"{client_ip}:{user_agent}"
                current_fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()
                if session["client_fingerprint"] and session["client_fingerprint"] != current_fingerprint:
                    # 客户端特征不匹配，标记为异常
                    session["_fingerprint_mismatch"] = True
            
            session["expires_at"] = now + self.ttl_seconds
            return session.copy()

    def destroy(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            session = self._sessions.pop(session_id, None)
            # 安全清除私钥：覆盖敏感数据
            if session and "private_key" in session:
                session["private_key"] = None
            session = None
            gc.collect()  # 强制垃圾回收以清除内存

    def invalidate_user(self, username: str) -> None:
        with self._lock:
            stale_ids = [
                session_id
                for session_id, session in self._sessions.items()
                if session["user"] == username
            ]
            for session_id in stale_ids:
                session = self._sessions.pop(session_id, None)
                # 安全清除私钥
                if session and "private_key" in session:
                    session["private_key"] = None
            gc.collect()  # 强制垃圾回收

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
            # 安全清除所有私钥
            for session_id, session in self._sessions.items():
                if "private_key" in session:
                    session["private_key"] = None
            self._sessions.clear()
            gc.collect()  # 强制垃圾回收


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
