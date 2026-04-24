import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path

import crypto
from crypto import CryptoManager


class SecretHashingTests(unittest.TestCase):
    def setUp(self):
        self._old_n = crypto.SECRET_SCRYPT_N
        self._old_maxmem = crypto.SECRET_SCRYPT_MAXMEM
        crypto.SECRET_SCRYPT_N = 2048
        crypto.SECRET_SCRYPT_MAXMEM = 32 * 1024 * 1024

    def tearDown(self):
        crypto.SECRET_SCRYPT_N = self._old_n
        crypto.SECRET_SCRYPT_MAXMEM = self._old_maxmem

    def test_secret_hash_uses_scrypt_record(self):
        encoded = CryptoManager._encode_secret_hash("Checkin-123!")
        record = json.loads(encoded.decode("utf-8"))

        self.assertEqual(record["version"], "scrypt-v1")
        self.assertEqual(record["kdf"], "scrypt")
        self.assertTrue(CryptoManager._verify_secret_hash("Checkin-123!", encoded))
        self.assertFalse(CryptoManager._verify_secret_hash("wrong", encoded))

    def test_legacy_sha256_digest_is_not_accepted(self):
        legacy_digest = hashlib.sha256("Checkin-123!".encode("utf-8")).digest()

        self.assertFalse(CryptoManager._verify_secret_hash("Checkin-123!", legacy_digest))

    def test_atomic_write_applies_restrictive_mode(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "secret.hash"

            CryptoManager._atomic_write(target, b"secret", mode=0o600)

            self.assertEqual(target.read_bytes(), b"secret")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
