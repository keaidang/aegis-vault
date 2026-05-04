import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

# 加载配置
load_dotenv()

# 基础路径配置
BASE_DIR = Path(os.getenv("AEGIS_DATA_DIR", "./data"))
KEY_DIR = BASE_DIR / "keys"
VAULT_DIR = BASE_DIR / "vault"
STATUS_FILE = BASE_DIR / "status.json"
STATUS_HMAC_FILE = BASE_DIR / "status.hmac"
NOTES_CONFIG_FILE = BASE_DIR / "notes_config.json"
CHECKIN_HASH_PATH = KEY_DIR / "checkin.hash"
DURESS_HASH_PATH = KEY_DIR / "duress.hash"
SUPPORTED_USERS = ("admin", "user1", "user2", "user3")
STATUS_LOCK = threading.RLock()
DESTROY_LOCK = threading.RLock()
SECRET_HASH_VERSION = "scrypt-v1"
SECRET_SCRYPT_N = int(os.getenv("SECRET_SCRYPT_N", "32768"))
SECRET_SCRYPT_R = int(os.getenv("SECRET_SCRYPT_R", "8"))
SECRET_SCRYPT_P = int(os.getenv("SECRET_SCRYPT_P", "1"))
SECRET_SCRYPT_DKLEN = 32
SECRET_SCRYPT_SALT_BYTES = 16
SECRET_SCRYPT_MAXMEM = int(os.getenv("SECRET_SCRYPT_MAXMEM", str(128 * 1024 * 1024)))
PRIVATE_KEY_FORMAT_VERSION = "aegis-key-v2"

def _load_checkin_timeout_seconds() -> int:
    """读取签到超时时间，优先支持秒级测试配置。"""
    if os.getenv("CHECKIN_TIMEOUT_SECONDS"):
        return max(1, int(os.getenv("CHECKIN_TIMEOUT_SECONDS", "60")))
    if os.getenv("CHECKIN_TIMEOUT_MINUTES"):
        return max(1, int(os.getenv("CHECKIN_TIMEOUT_MINUTES", "1"))) * 60
    return max(1, int(os.getenv("CHECKIN_TIMEOUT", "72"))) * 3600


# 超时时间（默认72小时，可通过 CHECKIN_TIMEOUT_SECONDS 做秒级测试）
CHECKIN_TIMEOUT = _load_checkin_timeout_seconds()

class CryptoManager:
    # 状态文件 HMAC 密钥（与私钥分离）
    _status_hmac_key = None

    @staticmethod
    def _status_key_path() -> Path:
        return KEY_DIR / "status.key"

    @staticmethod
    def _persist_status_key(key: bytes) -> None:
        CryptoManager._atomic_write(CryptoManager._status_key_path(), key, mode=0o600)

    @staticmethod
    def _reset_status_key_cache() -> None:
        CryptoManager._status_hmac_key = None
    
    @staticmethod
    def _get_or_generate_status_key() -> bytes:
        """获取或生成状态文件 HMAC 密钥"""
        if CryptoManager._status_hmac_key:
            if not CryptoManager._status_key_path().exists():
                try:
                    CryptoManager._persist_status_key(CryptoManager._status_hmac_key)
                except Exception:
                    pass
            return CryptoManager._status_hmac_key
        
        # 尝试从文件读取
        status_key_path = CryptoManager._status_key_path()
        if status_key_path.exists():
            try:
                with open(status_key_path, "rb") as f:
                    key = f.read()
                    if len(key) == 32:  # 验证长度
                        CryptoManager._status_hmac_key = key
                        return key
            except Exception:
                pass
        
        # 生成新密钥
        key = os.urandom(32)
        try:
            CryptoManager._persist_status_key(key)
        except Exception:
            pass
        
        CryptoManager._status_hmac_key = key
        return key
    
    @staticmethod
    def _compute_status_hmac(status_data: dict) -> str:
        """计算状态数据的 HMAC"""
        key = CryptoManager._get_or_generate_status_key()
        # 使用 JSON 规范化
        json_str = json.dumps(status_data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        h = hmac.new(key, json_str.encode('utf-8'), hashlib.sha256)
        return h.hexdigest()
    
    @staticmethod
    def _verify_status_hmac(status_data: dict, hmac_hex: str) -> bool:
        """验证状态数据的 HMAC"""
        expected_hmac = CryptoManager._compute_status_hmac(status_data)
        return hmac.compare_digest(expected_hmac, hmac_hex)

    @staticmethod
    def ensure_dirs():
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            KEY_DIR.chmod(0o700)
            VAULT_DIR.chmod(0o700)
        except OSError:
            pass

    @staticmethod
    def _atomic_write(path: Path, data: bytes | str, mode: int = 0o600) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = data.encode("utf-8") if isinstance(data, str) else data
        tmp_name = None
        try:
            with tempfile.NamedTemporaryFile(
                "wb",
                dir=path.parent,
                prefix=f".{path.name}.",
                delete=False,
            ) as tmp_file:
                tmp_name = tmp_file.name
                os.chmod(tmp_name, mode)
                tmp_file.write(payload)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            os.replace(tmp_name, path)
            os.chmod(path, mode)
        except Exception:
            if tmp_name:
                Path(tmp_name).unlink(missing_ok=True)
            raise

    @staticmethod
    def get_user_key_path(username: str):
        CryptoManager.validate_username(username)
        return KEY_DIR / f"{username}.key"

    @staticmethod
    def get_user_public_key_path(username: str):
        CryptoManager.validate_username(username)
        return KEY_DIR / f"{username}.pub"

    @staticmethod
    def get_note_key_path(username: str):
        CryptoManager.validate_username(username)
        return KEY_DIR / f"{username}.notes.key"

    @staticmethod
    def get_note_public_key_path(username: str):
        CryptoManager.validate_username(username)
        return KEY_DIR / f"{username}.notes.pub"

    @staticmethod
    def get_user_vault_path(username: str):
        CryptoManager.validate_username(username)
        path = VAULT_DIR / username
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def list_supported_users():
        return list(SUPPORTED_USERS)

    @staticmethod
    def private_key_is_current_format(key_path: Path) -> bool:
        if not key_path.exists():
            return False
        try:
            record = json.loads(key_path.read_text("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        return record.get("version") == PRIVATE_KEY_FORMAT_VERSION

    @staticmethod
    def requires_reinitialization() -> bool:
        admin_key = KEY_DIR / "admin.key"
        return admin_key.exists() and not CryptoManager.private_key_is_current_format(admin_key)

    @staticmethod
    def validate_username(username: str):
        if username not in SUPPORTED_USERS:
            raise ValueError("不支持的用户")
        return username

    @staticmethod
    def normalize_filename(filename: str) -> str:
        safe_name = Path(filename or "").name
        if not safe_name or safe_name in {".", ".."} or safe_name != filename:
            raise ValueError("非法文件名")
        return safe_name

    @staticmethod
    def get_encrypted_file_path(username: str, filename: str) -> Path:
        safe_name = CryptoManager.normalize_filename(filename)
        vault_path = CryptoManager.get_user_vault_path(username).resolve()
        file_path = (vault_path / safe_name).resolve()
        if file_path.parent != vault_path:
            raise ValueError("非法文件路径")
        return file_path

    @staticmethod
    def get_notes_root(username: str) -> Path:
        notes_root = (CryptoManager.get_user_vault_path(username) / "notes").resolve()
        if notes_root.parent != CryptoManager.get_user_vault_path(username).resolve():
            raise ValueError("非法笔记路径")
        notes_root.mkdir(parents=True, exist_ok=True)
        return notes_root

    @staticmethod
    def get_note_path(username: str, note_id: str) -> Path:
        safe_note_id = CryptoManager.normalize_filename(note_id)
        notes_root = CryptoManager.get_notes_root(username).resolve()
        note_path = (notes_root / safe_note_id).resolve()
        if note_path.parent != notes_root:
            raise ValueError("非法笔记路径")
        note_path.mkdir(parents=True, exist_ok=True)
        return note_path

    @staticmethod
    def _hash_secret(secret: str, salt: bytes | None = None) -> dict:
        salt = salt or os.urandom(SECRET_SCRYPT_SALT_BYTES)
        digest = hashlib.scrypt(
            secret.encode("utf-8"),
            salt=salt,
            n=SECRET_SCRYPT_N,
            r=SECRET_SCRYPT_R,
            p=SECRET_SCRYPT_P,
            dklen=SECRET_SCRYPT_DKLEN,
            maxmem=SECRET_SCRYPT_MAXMEM,
        )
        return {
            "version": SECRET_HASH_VERSION,
            "kdf": "scrypt",
            "n": SECRET_SCRYPT_N,
            "r": SECRET_SCRYPT_R,
            "p": SECRET_SCRYPT_P,
            "dklen": SECRET_SCRYPT_DKLEN,
            "salt": base64.b64encode(salt).decode("ascii"),
            "hash": base64.b64encode(digest).decode("ascii"),
        }

    @staticmethod
    def _encode_secret_hash(secret: str) -> bytes:
        return json.dumps(
            CryptoManager._hash_secret(secret),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _verify_secret_hash(secret: str, stored: bytes) -> bool:
        try:
            record = json.loads(stored.decode("utf-8"))
            if record.get("version") != SECRET_HASH_VERSION or record.get("kdf") != "scrypt":
                return False
            salt = base64.b64decode(record["salt"])
            expected = base64.b64decode(record["hash"])
            digest = hashlib.scrypt(
                secret.encode("utf-8"),
                salt=salt,
                n=int(record["n"]),
                r=int(record["r"]),
                p=int(record["p"]),
                dklen=int(record.get("dklen", SECRET_SCRYPT_DKLEN)),
                maxmem=SECRET_SCRYPT_MAXMEM,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return False

        return hmac.compare_digest(digest, expected)

    @staticmethod
    def _verify_secret_file(path: Path, secret: str) -> bool:
        if not secret or not path.exists():
            return False
        try:
            stored = path.read_bytes()
        except OSError:
            return False
        return CryptoManager._verify_secret_hash(secret, stored)

    @staticmethod
    def _derive_password_key(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=dklen,
            maxmem=SECRET_SCRYPT_MAXMEM,
        )

    @staticmethod
    def _encrypt_private_key_pem(private_key, password: str) -> bytes:
        plain_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        salt = os.urandom(SECRET_SCRYPT_SALT_BYTES)
        nonce = os.urandom(16)
        key = CryptoManager._derive_password_key(
            password,
            salt=salt,
            n=SECRET_SCRYPT_N,
            r=SECRET_SCRYPT_R,
            p=SECRET_SCRYPT_P,
            dklen=SECRET_SCRYPT_DKLEN,
        )
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plain_pem)
        record = {
            "version": PRIVATE_KEY_FORMAT_VERSION,
            "kdf": "scrypt",
            "cipher": "AES-256-GCM",
            "n": SECRET_SCRYPT_N,
            "r": SECRET_SCRYPT_R,
            "p": SECRET_SCRYPT_P,
            "dklen": SECRET_SCRYPT_DKLEN,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _decrypt_private_key_record(data: bytes, password: str):
        try:
            record = json.loads(data.decode("utf-8"))
            if record.get("version") != PRIVATE_KEY_FORMAT_VERSION:
                raise ValueError("unsupported_key_format")
            salt = base64.b64decode(record["salt"])
            nonce = base64.b64decode(record["nonce"])
            tag = base64.b64decode(record["tag"])
            ciphertext = base64.b64decode(record["ciphertext"])
            key = CryptoManager._derive_password_key(
                password,
                salt=salt,
                n=int(record["n"]),
                r=int(record["r"]),
                p=int(record["p"]),
                dklen=int(record.get("dklen", SECRET_SCRYPT_DKLEN)),
            )
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plain_pem = cipher.decrypt_and_verify(ciphertext, tag)
            return serialization.load_pem_private_key(
                plain_pem,
                password=None,
                backend=default_backend(),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("invalid_private_key_password")

    @staticmethod
    def init_admin(password: str, checkin_code: str):
        if KEY_DIR.exists():
            shutil.rmtree(KEY_DIR)
        CryptoManager._reset_status_key_cache()
        CryptoManager.ensure_dirs()
        
        # 创建管理员密钥
        CryptoManager.create_user_keys("admin", password)
        CryptoManager.get_user_vault_path("admin")
        # 存储确认码
        CryptoManager.set_checkin_code(checkin_code)
        # 初始化状态
        CryptoManager.update_checkin()

    @staticmethod
    def create_user_keys(username: str, password: str):
        CryptoManager._create_key_pair(
            private_key_path=CryptoManager.get_user_key_path(username),
            public_key_path=CryptoManager.get_user_public_key_path(username),
            password=password,
            username=username,
        )

    @staticmethod
    def create_note_keys(username: str, password: str):
        CryptoManager._create_key_pair(
            private_key_path=CryptoManager.get_note_key_path(username),
            public_key_path=CryptoManager.get_note_public_key_path(username),
            password=password,
            username=username,
        )

    @staticmethod
    def _create_key_pair(private_key_path: Path, public_key_path: Path, password: str, username: str):
        CryptoManager.validate_username(username)
        CryptoManager.ensure_dirs()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        pem = CryptoManager._encrypt_private_key_pem(private_key, password)
        CryptoManager._atomic_write(private_key_path, pem, mode=0o600)
        
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        CryptoManager._atomic_write(public_key_path, pub_pem, mode=0o644)

    @staticmethod
    def set_checkin_code(code: str):
        if not code: return
        CryptoManager._atomic_write(CHECKIN_HASH_PATH, CryptoManager._encode_secret_hash(code), mode=0o600)

    @staticmethod
    def set_duress_code(code: str):
        if not code: return
        CryptoManager._atomic_write(DURESS_HASH_PATH, CryptoManager._encode_secret_hash(code), mode=0o600)

    @staticmethod
    def verify_checkin(code: str) -> bool:
        return CryptoManager._verify_secret_file(CHECKIN_HASH_PATH, code)

    @staticmethod
    def verify_duress(code: str) -> bool:
        return CryptoManager._verify_secret_file(DURESS_HASH_PATH, code)

    @staticmethod
    def authenticate(password: str):
        if not password: return None
        # 优先检查是否为胁迫密码
        if CryptoManager.verify_duress(password):
            CryptoManager.destroy_all()
            return "DURESS_TRIGGERED"
        
        # 尝试匹配所有可能的密钥
        for user in SUPPORTED_USERS:
            key_path = CryptoManager.get_user_key_path(user)
            if key_path.exists():
                try:
                    CryptoManager._load_private_key(key_path, password)
                    return {"user": user}
                except ValueError:
                    continue
        return None

    @staticmethod
    def load_private_key(username: str, password: str):
        return CryptoManager._load_private_key(CryptoManager.get_user_key_path(username), password)

    @staticmethod
    def load_note_private_key(username: str, password: str):
        return CryptoManager._load_private_key(CryptoManager.get_note_key_path(username), password)

    @staticmethod
    def _load_private_key(key_path: Path, password: str):
        if not password:
            return None
        if not key_path.exists():
            return None
        with open(key_path, "rb") as f:
            return CryptoManager._decrypt_private_key_record(f.read(), password)

    @staticmethod
    def encrypt_file(file_content: bytes, filename: str, username: str):
        CryptoManager.validate_username(username)
        original_filename = CryptoManager.normalize_filename(filename)
        target_path = CryptoManager.get_encrypted_file_path(username, f"{original_filename}.aes")
        CryptoManager.encrypt_payload(
            file_content,
            public_key_path=CryptoManager.get_user_public_key_path(username),
            target_path=target_path,
        )

    @staticmethod
    def decrypt_file(filename: str, username: str, private_key) -> bytes:
        encrypted_path = CryptoManager.get_encrypted_file_path(username, filename)
        return CryptoManager.decrypt_payload(encrypted_path, private_key)

    @staticmethod
    def encrypt_note_payload(payload: bytes, username: str, note_id: str):
        target_path = CryptoManager.get_note_path(username, note_id) / "note.aes"
        CryptoManager.encrypt_payload(
            payload,
            public_key_path=CryptoManager.get_note_public_key_path(username),
            target_path=target_path,
        )

    @staticmethod
    def decrypt_note_payload(username: str, note_id: str, private_key) -> bytes:
        encrypted_path = CryptoManager.get_note_path(username, note_id) / "note.aes"
        return CryptoManager.decrypt_payload(encrypted_path, private_key)

    @staticmethod
    def encrypt_payload(payload: bytes, public_key_path: Path, target_path: Path):
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        aes_key = os.urandom(32)
        enc_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        final_data = len(enc_aes_key).to_bytes(4, 'big') + enc_aes_key + cipher.nonce + tag + ciphertext
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "wb") as f:
            f.write(final_data)

    @staticmethod
    def decrypt_payload(encrypted_path: Path, private_key) -> bytes:
        with open(encrypted_path, "rb") as f:
            data = f.read()

        idx = 4
        enc_key_len = int.from_bytes(data[0:4], 'big')
        enc_aes_key = data[idx : idx + enc_key_len]
        idx += enc_key_len
        nonce = data[idx : idx + 16]
        idx += 16
        tag = data[idx : idx + 16]
        idx += 16
        ciphertext = data[idx:]
        
        aes_key = private_key.decrypt(
            enc_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    @staticmethod
    def delete_encrypted_file(username: str, filename: str):
        target_path = CryptoManager.get_encrypted_file_path(username, filename)
        if not target_path.exists():
            raise FileNotFoundError(filename)
        CryptoManager.secure_delete_path(target_path, passes=1)

    @staticmethod
    def update_checkin():
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        with STATUS_LOCK:
            status_data = {"last_checkin": int(time.time()), "destroyed": False}
            CryptoManager._atomic_write(
                STATUS_FILE,
                json.dumps(status_data, ensure_ascii=False),
                mode=0o600,
            )
            # 计算并存储 HMAC
            status_hmac = CryptoManager._compute_status_hmac(status_data)
            CryptoManager._atomic_write(STATUS_HMAC_FILE, status_hmac, mode=0o600)

    @staticmethod
    def get_status():
        if not STATUS_FILE.exists(): 
            return {"last_checkin": 0, "destroyed": False, "_hmac_valid": False}
        try:
            with STATUS_LOCK:
                with open(STATUS_FILE, "r") as f: 
                    status_data = json.load(f)
                
                # 验证 HMAC
                hmac_valid = False
                if STATUS_HMAC_FILE.exists():
                    try:
                        with open(STATUS_HMAC_FILE, "r") as f:
                            stored_hmac = f.read().strip()
                        hmac_valid = CryptoManager._verify_status_hmac(status_data, stored_hmac)
                    except Exception:
                        pass
                
                # 如果 HMAC 验证失败，触发销毁（防篡改）
                if not hmac_valid and STATUS_HMAC_FILE.exists():
                    # 状态文件可能被篡改，标记为无效并触发销毁
                    return {"last_checkin": 0, "destroyed": True, "_hmac_valid": False, "_tampered": True}
                
                status_data["_hmac_valid"] = hmac_valid
                return status_data
        except Exception: 
            return {"last_checkin": 0, "destroyed": False, "_hmac_valid": False}

    @staticmethod
    def _shred_file(path: Path, passes: int):
        if not path.exists() or not path.is_file():
            return

        if shutil.which("shred"):
            subprocess.run(
                ["shred", "-u", "-z", "-n", str(passes), str(path)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if path.exists():
            path.unlink(missing_ok=True)

    @staticmethod
    def _shred_tree(root: Path, passes: int):
        if not root.exists():
            return
        for path in sorted((p for p in root.rglob("*") if p.is_file()), reverse=True):
            CryptoManager._shred_file(path, passes)

    @staticmethod
    def secure_delete_path(path: Path, passes: int = 1):
        if path.is_file():
            CryptoManager._shred_file(path, passes)
            return

        if path.is_dir():
            CryptoManager._shred_tree(path, passes)
            shutil.rmtree(path, ignore_errors=True)

    @staticmethod
    def destroy_all():
        with DESTROY_LOCK:
            if KEY_DIR.exists():
                CryptoManager._shred_tree(KEY_DIR, 3)
                shutil.rmtree(KEY_DIR, ignore_errors=True)

            if VAULT_DIR.exists():
                CryptoManager._shred_tree(VAULT_DIR, 1)
                shutil.rmtree(VAULT_DIR, ignore_errors=True)

            NOTES_CONFIG_FILE.unlink(missing_ok=True)

            BASE_DIR.mkdir(parents=True, exist_ok=True)
            CryptoManager._reset_status_key_cache()
            with STATUS_LOCK:
                status_data = {"last_checkin": 0, "destroyed": True}
                CryptoManager._atomic_write(
                    STATUS_FILE,
                    json.dumps(status_data, ensure_ascii=False),
                    mode=0o600,
                )
                # 更新 HMAC
                status_hmac = CryptoManager._compute_status_hmac(status_data)
                CryptoManager._atomic_write(STATUS_HMAC_FILE, status_hmac, mode=0o600)
            
            # 这里会由 main.py 中的审计日志记录
            # 避免在 crypto.py 中导入 audit_logger 产生循环依赖

    @staticmethod
    def reset_system():
        with DESTROY_LOCK:
            BASE_DIR.mkdir(parents=True, exist_ok=True)
            if KEY_DIR.exists():
                shutil.rmtree(KEY_DIR, ignore_errors=True)
            CryptoManager._reset_status_key_cache()
            with STATUS_LOCK:
                status_data = {"last_checkin": 0, "destroyed": False}
                CryptoManager._atomic_write(
                    STATUS_FILE,
                    json.dumps(status_data, ensure_ascii=False),
                    mode=0o600,
                )
                # 重置 HMAC
                status_hmac = CryptoManager._compute_status_hmac(status_data)
                CryptoManager._atomic_write(STATUS_HMAC_FILE, status_hmac, mode=0o600)
            if VAULT_DIR.exists():
                shutil.rmtree(VAULT_DIR, ignore_errors=True)
            NOTES_CONFIG_FILE.unlink(missing_ok=True)
            CryptoManager.ensure_dirs()
