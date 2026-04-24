import tempfile
import unittest
from pathlib import Path

import crypto
from crypto import CryptoManager


class CryptoFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_paths = {
            "BASE_DIR": crypto.BASE_DIR,
            "KEY_DIR": crypto.KEY_DIR,
            "VAULT_DIR": crypto.VAULT_DIR,
            "STATUS_FILE": crypto.STATUS_FILE,
            "STATUS_HMAC_FILE": crypto.STATUS_HMAC_FILE,
            "NOTES_CONFIG_FILE": crypto.NOTES_CONFIG_FILE,
            "CHECKIN_HASH_PATH": crypto.CHECKIN_HASH_PATH,
            "DURESS_HASH_PATH": crypto.DURESS_HASH_PATH,
        }
        base_dir = Path(self.tmp.name)
        crypto.BASE_DIR = base_dir
        crypto.KEY_DIR = base_dir / "keys"
        crypto.VAULT_DIR = base_dir / "vault"
        crypto.STATUS_FILE = base_dir / "status.json"
        crypto.STATUS_HMAC_FILE = base_dir / "status.hmac"
        crypto.NOTES_CONFIG_FILE = base_dir / "notes_config.json"
        crypto.CHECKIN_HASH_PATH = crypto.KEY_DIR / "checkin.hash"
        crypto.DURESS_HASH_PATH = crypto.KEY_DIR / "duress.hash"
        CryptoManager._reset_status_key_cache()

    def tearDown(self):
        for name, value in self.old_paths.items():
            setattr(crypto, name, value)
        CryptoManager._reset_status_key_cache()
        self.tmp.cleanup()

    def test_init_login_encrypt_download_and_checkin(self):
        CryptoManager.init_admin("StrongPass-123!", "Checkin-123!")

        self.assertEqual(CryptoManager.authenticate("StrongPass-123!"), {"user": "admin"})
        self.assertTrue(CryptoManager.verify_checkin("Checkin-123!"))
        self.assertFalse(CryptoManager.verify_checkin("wrong"))

        CryptoManager.encrypt_file(b"secret data", "secret.txt", "admin")
        private_key = CryptoManager.load_private_key("admin", "StrongPass-123!")
        self.assertEqual(CryptoManager.decrypt_file("secret.txt.aes", "admin", private_key), b"secret data")


if __name__ == "__main__":
    unittest.main()
