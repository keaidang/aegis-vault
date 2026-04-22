import hashlib
import hmac
import json
import os
import shutil
import subprocess
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
CHECKIN_HASH_PATH = KEY_DIR / "checkin.hash"
DURESS_HASH_PATH = KEY_DIR / "duress.hash"
SUPPORTED_USERS = ("admin", "user1", "user2", "user3")
STATUS_LOCK = threading.RLock()
DESTROY_LOCK = threading.RLock()

# 超时时间 (默认72小时)
CHECKIN_TIMEOUT = int(os.getenv("CHECKIN_TIMEOUT", 72)) * 3600

class CryptoManager:
    @staticmethod
    def ensure_dirs():
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        VAULT_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def get_user_key_path(username: str):
        CryptoManager.validate_username(username)
        return KEY_DIR / f"{username}.key"

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
    def _hash_secret(secret: str) -> bytes:
        return hashlib.sha256(secret.encode("utf-8")).digest()

    @staticmethod
    def init_admin(password: str, checkin_code: str):
        if KEY_DIR.exists(): shutil.rmtree(KEY_DIR)
        CryptoManager.ensure_dirs()
        
        # 创建管理员密钥
        CryptoManager.create_user_keys("admin", password)
        # 存储确认码
        CryptoManager.set_checkin_code(checkin_code)
        # 初始化状态
        CryptoManager.update_checkin()

    @staticmethod
    def create_user_keys(username: str, password: str):
        CryptoManager.validate_username(username)
        CryptoManager.ensure_dirs()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        with open(CryptoManager.get_user_key_path(username), "wb") as f: f.write(pem)
        
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(KEY_DIR / f"{username}.pub", "wb") as f: f.write(pub_pem)

    @staticmethod
    def set_checkin_code(code: str):
        if not code: return
        with open(CHECKIN_HASH_PATH, "wb") as f:
            f.write(CryptoManager._hash_secret(code))

    @staticmethod
    def set_duress_code(code: str):
        if not code: return
        with open(DURESS_HASH_PATH, "wb") as f:
            f.write(CryptoManager._hash_secret(code))

    @staticmethod
    def verify_checkin(code: str) -> bool:
        if not code or not CHECKIN_HASH_PATH.exists(): return False
        return hmac.compare_digest(CryptoManager._hash_secret(code), open(CHECKIN_HASH_PATH, "rb").read())

    @staticmethod
    def verify_duress(code: str) -> bool:
        if not code or not DURESS_HASH_PATH.exists(): return False
        return hmac.compare_digest(CryptoManager._hash_secret(code), open(DURESS_HASH_PATH, "rb").read())

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
                    with open(key_path, "rb") as f:
                        serialization.load_pem_private_key(f.read(), password=password.encode(), backend=default_backend())
                    return user
                except: continue
        return None

    @staticmethod
    def encrypt_file(file_content: bytes, filename: str, username: str):
        CryptoManager.validate_username(username)
        original_filename = CryptoManager.normalize_filename(filename)
        pub_key_path = KEY_DIR / f"{username}.pub"
        with open(pub_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        
        aes_key = os.urandom(32)
        enc_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(file_content)
        final_data = len(enc_aes_key).to_bytes(4, 'big') + enc_aes_key + cipher.nonce + tag + ciphertext
        
        target_path = CryptoManager.get_encrypted_file_path(username, f"{original_filename}.aes")
        with open(target_path, "wb") as f:
            f.write(final_data)

    @staticmethod
    def decrypt_file(filename: str, username: str, password: str) -> bytes:
        with open(CryptoManager.get_user_key_path(username), "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=password.encode(), backend=default_backend())

        encrypted_path = CryptoManager.get_encrypted_file_path(username, filename)
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
    def update_checkin():
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        with STATUS_LOCK:
            with open(STATUS_FILE, "w") as f:
                json.dump({"last_checkin": int(time.time()), "destroyed": False}, f)

    @staticmethod
    def get_status():
        if not STATUS_FILE.exists(): return {"last_checkin": 0, "destroyed": False}
        try:
            with STATUS_LOCK:
                with open(STATUS_FILE, "r") as f: return json.load(f)
        except: return {"last_checkin": 0, "destroyed": False}

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
    def destroy_all():
        with DESTROY_LOCK:
            if KEY_DIR.exists():
                CryptoManager._shred_tree(KEY_DIR, 3)
                shutil.rmtree(KEY_DIR, ignore_errors=True)

            if VAULT_DIR.exists():
                CryptoManager._shred_tree(VAULT_DIR, 1)
                shutil.rmtree(VAULT_DIR, ignore_errors=True)

            BASE_DIR.mkdir(parents=True, exist_ok=True)
            with STATUS_LOCK:
                with open(STATUS_FILE, "w") as f:
                    json.dump({"last_checkin": 0, "destroyed": True}, f)

    @staticmethod
    def reset_system():
        with DESTROY_LOCK:
            BASE_DIR.mkdir(parents=True, exist_ok=True)
            with STATUS_LOCK:
                with open(STATUS_FILE, "w") as f:
                    json.dump({"last_checkin": 0, "destroyed": False}, f)
            if KEY_DIR.exists():
                shutil.rmtree(KEY_DIR, ignore_errors=True)
            if VAULT_DIR.exists():
                shutil.rmtree(VAULT_DIR, ignore_errors=True)
            CryptoManager.ensure_dirs()
