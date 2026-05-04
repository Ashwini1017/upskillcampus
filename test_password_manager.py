from __future__ import annotations

import json
import os
import tempfile
import unittest

from auth import create_master_record, generate_otp_secret, totp_now, verify_master_password, verify_totp
from encryption import EncryptionError, decrypt_secret, encrypt_secret, generate_data_key, unwrap_data_key, wrap_data_key
from password_manager import (
    Vault,
    add_credential,
    delete_credential,
    get_credential,
    load_vault,
    save_vault,
    search_credentials,
    update_credential,
)
from utils import check_password_strength, generate_password, utc_now_s


class TestSecurityPrimitives(unittest.TestCase):
    def test_master_password_pbkdf2(self) -> None:
        record = create_master_record("Str0ng!MasterPass123")
        self.assertTrue(verify_master_password("Str0ng!MasterPass123", record))
        self.assertFalse(verify_master_password("wrong", record))

    def test_encrypt_decrypt_roundtrip(self) -> None:
        dk = generate_data_key()
        token = encrypt_secret(dk, "hello")
        self.assertEqual(decrypt_secret(dk, token), "hello")
        with self.assertRaises(EncryptionError):
            decrypt_secret(generate_data_key(), token)

    def test_wrap_unwrap_data_key(self) -> None:
        dk = generate_data_key()
        material = wrap_data_key("Str0ng!MasterPass123", dk)
        dk2 = unwrap_data_key("Str0ng!MasterPass123", material)
        self.assertEqual(dk2, dk)
        with self.assertRaises(EncryptionError):
            unwrap_data_key("wrong", material)

    def test_totp(self) -> None:
        secret = generate_otp_secret()
        code = totp_now(secret, at_time_s=1_700_000_000)
        self.assertTrue(verify_totp(secret, code, at_time_s=1_700_000_000))
        self.assertFalse(verify_totp(secret, "000000", at_time_s=1_700_000_000))


class TestVaultCrud(unittest.TestCase):
    def test_crud_flow_json_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "vault.json")
            master = "Str0ng!MasterPass123"

            master_record = create_master_record(master)
            data_key = generate_data_key()
            key_material = wrap_data_key(master, data_key)
            vault = Vault(path=path, master=master_record, key_material=key_material, credentials={})

            add_credential(vault, data_key, "example.com", "alice", "Passw0rd!X")
            add_credential(vault, data_key, "example.com", "bob", "Passw0rd!Y")
            save_vault(vault, updated_at=utc_now_s())

            vault2 = load_vault(path)
            self.assertIn("example.com", json.dumps(vault2.credentials))

            item = get_credential(vault2, data_key, "example.com", "alice")
            self.assertEqual(item["password"], "Passw0rd!X")

            update_credential(vault2, data_key, "example.com", "alice", new_password="NewPass!123")
            self.assertEqual(get_credential(vault2, data_key, "example.com", "alice")["password"], "NewPass!123")

            results = search_credentials(vault2, "bob")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["username"].lower(), "bob")

            delete_credential(vault2, "example.com", "bob")
            self.assertEqual(len(search_credentials(vault2, "example.com")), 1)


class TestUtils(unittest.TestCase):
    def test_password_strength(self) -> None:
        ok, issues = check_password_strength("weak")
        self.assertFalse(ok)
        self.assertTrue(issues)

    def test_password_generator(self) -> None:
        pw = generate_password(length=16)
        self.assertEqual(len(pw), 16)


if __name__ == "__main__":
    unittest.main()

