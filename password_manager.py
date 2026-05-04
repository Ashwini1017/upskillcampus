<<<<<<< HEAD
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from auth import MasterAuthRecord
from encryption import VaultKeyMaterial, decrypt_secret, encrypt_secret


class VaultError(Exception):
    """Raised for vault I/O and integrity issues."""


@dataclass
class Vault:
    """
    In-memory representation of the vault JSON structure.

    passwords are encrypted with a data key, never stored in plaintext.
    """

    path: str
    master: MasterAuthRecord
    key_material: VaultKeyMaterial
    credentials: dict[str, dict[str, str]]
    otp_enabled: bool = False
    otp_secret_enc_b64: str | None = None


def _empty_vault_dict() -> dict[str, Any]:
    return {
        "version": 1,
        "master": {"salt_b64": "", "hash_b64": "", "iterations": 0},
        "encryption": {"kek_salt_b64": "", "wrapped_data_key_b64": "", "kdf_iterations": 0},
        "otp": {"enabled": False, "secret_enc_b64": None},
        "credentials": {},
        "meta": {"updated_at": 0},
    }


def load_vault(path: str) -> Vault:
    """
    Load vault JSON from disk.
    """
    if not os.path.exists(path):
        raise VaultError("Vault file not found. Initialize a new vault first.")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        raise VaultError("Vault file is not valid JSON (it may be corrupted).") from e
    except OSError as e:
        raise VaultError("Failed to read vault file.") from e

    try:
        master = raw["master"]
        enc = raw["encryption"]
        otp = raw.get("otp", {"enabled": False, "secret_enc_b64": None})
        creds = raw.get("credentials", {})
        if not isinstance(creds, dict):
            raise TypeError("credentials must be an object")
        return Vault(
            path=path,
            master=MasterAuthRecord(
                salt_b64=master["salt_b64"],
                hash_b64=master["hash_b64"],
                iterations=int(master["iterations"]),
            ),
            key_material=VaultKeyMaterial(
                kek_salt_b64=enc["kek_salt_b64"],
                wrapped_data_key_b64=enc["wrapped_data_key_b64"],
                kdf_iterations=int(enc["kdf_iterations"]),
            ),
            credentials=creds,
            otp_enabled=bool(otp.get("enabled", False)),
            otp_secret_enc_b64=otp.get("secret_enc_b64"),
        )
    except Exception as e:  # noqa: BLE001
        raise VaultError("Vault file has an unexpected structure (it may be corrupted).") from e


def save_vault(vault: Vault, *, updated_at: int) -> None:
    """
    Persist vault to disk with minimal sensitive material exposed.
    """
    data = _empty_vault_dict()
    data["master"] = {
        "salt_b64": vault.master.salt_b64,
        "hash_b64": vault.master.hash_b64,
        "iterations": vault.master.iterations,
    }
    data["encryption"] = {
        "kek_salt_b64": vault.key_material.kek_salt_b64,
        "wrapped_data_key_b64": vault.key_material.wrapped_data_key_b64,
        "kdf_iterations": vault.key_material.kdf_iterations,
    }
    data["otp"] = {"enabled": vault.otp_enabled, "secret_enc_b64": vault.otp_secret_enc_b64}
    data["credentials"] = vault.credentials
    data["meta"]["updated_at"] = updated_at

    tmp = vault.path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, vault.path)
    except OSError as e:
        raise VaultError("Failed to write vault file.") from e
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def normalize_key(website: str, username: str) -> str:
    """Stable key for storing credentials. Keeps JSON structure simple and searchable."""
    return f"{website.strip().lower()}::{username.strip().lower()}"


def add_credential(vault: Vault, data_key: bytes, website: str, username: str, password: str) -> None:
    key = normalize_key(website, username)
    if not website.strip() or not username.strip():
        raise ValueError("Website and username are required.")
    if key in vault.credentials:
        raise ValueError("Credential already exists for this website+username.")
    vault.credentials[key] = {
        "website": website.strip(),
        "username": username.strip(),
        "password": encrypt_secret(data_key, password),
    }


def list_credentials(vault: Vault) -> list[dict[str, str]]:
    """Return list of stored credential metadata (no decrypted passwords)."""
    out: list[dict[str, str]] = []
    for item in vault.credentials.values():
        out.append({"website": item.get("website", ""), "username": item.get("username", "")})
    out.sort(key=lambda x: (x["website"].lower(), x["username"].lower()))
    return out


def get_credential(vault: Vault, data_key: bytes, website: str, username: str) -> dict[str, str]:
    key = normalize_key(website, username)
    if key not in vault.credentials:
        raise KeyError("Credential not found.")
    item = vault.credentials[key]
    return {
        "website": item["website"],
        "username": item["username"],
        "password": decrypt_secret(data_key, item["password"]),
    }


def update_credential(
    vault: Vault,
    data_key: bytes,
    website: str,
    username: str,
    *,
    new_username: str | None = None,
    new_password: str | None = None,
) -> None:
    key = normalize_key(website, username)
    if key not in vault.credentials:
        raise KeyError("Credential not found.")

    item = vault.credentials[key]
    target_username = new_username.strip() if new_username is not None else item["username"]
    target_key = normalize_key(item["website"], target_username)

    if target_key != key and target_key in vault.credentials:
        raise ValueError("Another credential already exists with the new username.")

    if new_username is not None:
        item["username"] = new_username.strip()
    if new_password is not None:
        item["password"] = encrypt_secret(data_key, new_password)

    if target_key != key:
        vault.credentials[target_key] = item
        del vault.credentials[key]


def delete_credential(vault: Vault, website: str, username: str) -> None:
    key = normalize_key(website, username)
    if key not in vault.credentials:
        raise KeyError("Credential not found.")
    del vault.credentials[key]


def search_credentials(vault: Vault, query: str) -> list[dict[str, str]]:
    q = query.strip().lower()
    if not q:
        return []
    results: list[dict[str, str]] = []
    for item in vault.credentials.values():
        website = str(item.get("website", ""))
        username = str(item.get("username", ""))
        if q in website.lower() or q in username.lower():
            results.append({"website": website, "username": username})
    results.sort(key=lambda x: (x["website"].lower(), x["username"].lower()))
    return results

=======
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from auth import MasterAuthRecord
from encryption import VaultKeyMaterial, decrypt_secret, encrypt_secret


class VaultError(Exception):
    """Raised for vault I/O and integrity issues."""


@dataclass
class Vault:
    """
    In-memory representation of the vault JSON structure.

    passwords are encrypted with a data key, never stored in plaintext.
    """

    path: str
    master: MasterAuthRecord
    key_material: VaultKeyMaterial
    credentials: dict[str, dict[str, str]]
    otp_enabled: bool = False
    otp_secret_enc_b64: str | None = None


def _empty_vault_dict() -> dict[str, Any]:
    return {
        "version": 1,
        "master": {"salt_b64": "", "hash_b64": "", "iterations": 0},
        "encryption": {"kek_salt_b64": "", "wrapped_data_key_b64": "", "kdf_iterations": 0},
        "otp": {"enabled": False, "secret_enc_b64": None},
        "credentials": {},
        "meta": {"updated_at": 0},
    }


def load_vault(path: str) -> Vault:
    """
    Load vault JSON from disk.
    """
    if not os.path.exists(path):
        raise VaultError("Vault file not found. Initialize a new vault first.")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        raise VaultError("Vault file is not valid JSON (it may be corrupted).") from e
    except OSError as e:
        raise VaultError("Failed to read vault file.") from e

    try:
        master = raw["master"]
        enc = raw["encryption"]
        otp = raw.get("otp", {"enabled": False, "secret_enc_b64": None})
        creds = raw.get("credentials", {})
        if not isinstance(creds, dict):
            raise TypeError("credentials must be an object")
        return Vault(
            path=path,
            master=MasterAuthRecord(
                salt_b64=master["salt_b64"],
                hash_b64=master["hash_b64"],
                iterations=int(master["iterations"]),
            ),
            key_material=VaultKeyMaterial(
                kek_salt_b64=enc["kek_salt_b64"],
                wrapped_data_key_b64=enc["wrapped_data_key_b64"],
                kdf_iterations=int(enc["kdf_iterations"]),
            ),
            credentials=creds,
            otp_enabled=bool(otp.get("enabled", False)),
            otp_secret_enc_b64=otp.get("secret_enc_b64"),
        )
    except Exception as e:  # noqa: BLE001
        raise VaultError("Vault file has an unexpected structure (it may be corrupted).") from e


def save_vault(vault: Vault, *, updated_at: int) -> None:
    """
    Persist vault to disk with minimal sensitive material exposed.
    """
    data = _empty_vault_dict()
    data["master"] = {
        "salt_b64": vault.master.salt_b64,
        "hash_b64": vault.master.hash_b64,
        "iterations": vault.master.iterations,
    }
    data["encryption"] = {
        "kek_salt_b64": vault.key_material.kek_salt_b64,
        "wrapped_data_key_b64": vault.key_material.wrapped_data_key_b64,
        "kdf_iterations": vault.key_material.kdf_iterations,
    }
    data["otp"] = {"enabled": vault.otp_enabled, "secret_enc_b64": vault.otp_secret_enc_b64}
    data["credentials"] = vault.credentials
    data["meta"]["updated_at"] = updated_at

    tmp = vault.path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, vault.path)
    except OSError as e:
        raise VaultError("Failed to write vault file.") from e
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def normalize_key(website: str, username: str) -> str:
    """Stable key for storing credentials. Keeps JSON structure simple and searchable."""
    return f"{website.strip().lower()}::{username.strip().lower()}"


def add_credential(vault: Vault, data_key: bytes, website: str, username: str, password: str) -> None:
    key = normalize_key(website, username)
    if not website.strip() or not username.strip():
        raise ValueError("Website and username are required.")
    if key in vault.credentials:
        raise ValueError("Credential already exists for this website+username.")
    vault.credentials[key] = {
        "website": website.strip(),
        "username": username.strip(),
        "password": encrypt_secret(data_key, password),
    }


def list_credentials(vault: Vault) -> list[dict[str, str]]:
    """Return list of stored credential metadata (no decrypted passwords)."""
    out: list[dict[str, str]] = []
    for item in vault.credentials.values():
        out.append({"website": item.get("website", ""), "username": item.get("username", "")})
    out.sort(key=lambda x: (x["website"].lower(), x["username"].lower()))
    return out


def get_credential(vault: Vault, data_key: bytes, website: str, username: str) -> dict[str, str]:
    key = normalize_key(website, username)
    if key not in vault.credentials:
        raise KeyError("Credential not found.")
    item = vault.credentials[key]
    return {
        "website": item["website"],
        "username": item["username"],
        "password": decrypt_secret(data_key, item["password"]),
    }


def update_credential(
    vault: Vault,
    data_key: bytes,
    website: str,
    username: str,
    *,
    new_username: str | None = None,
    new_password: str | None = None,
) -> None:
    key = normalize_key(website, username)
    if key not in vault.credentials:
        raise KeyError("Credential not found.")

    item = vault.credentials[key]
    target_username = new_username.strip() if new_username is not None else item["username"]
    target_key = normalize_key(item["website"], target_username)

    if target_key != key and target_key in vault.credentials:
        raise ValueError("Another credential already exists with the new username.")

    if new_username is not None:
        item["username"] = new_username.strip()
    if new_password is not None:
        item["password"] = encrypt_secret(data_key, new_password)

    if target_key != key:
        vault.credentials[target_key] = item
        del vault.credentials[key]


def delete_credential(vault: Vault, website: str, username: str) -> None:
    key = normalize_key(website, username)
    if key not in vault.credentials:
        raise KeyError("Credential not found.")
    del vault.credentials[key]


def search_credentials(vault: Vault, query: str) -> list[dict[str, str]]:
    q = query.strip().lower()
    if not q:
        return []
    results: list[dict[str, str]] = []
    for item in vault.credentials.values():
        website = str(item.get("website", ""))
        username = str(item.get("username", ""))
        if q in website.lower() or q in username.lower():
            results.append({"website": website, "username": username})
    results.sort(key=lambda x: (x["website"].lower(), x["username"].lower()))
    return results

>>>>>>> 165c382 (password manager)
