from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""


@dataclass(frozen=True)
class VaultKeyMaterial:
    """Material stored in the vault file to unlock the data key."""

    kek_salt_b64: str
    wrapped_data_key_b64: str
    kdf_iterations: int


def _derive_fernet_key_from_password(master_password: str, salt: bytes, iterations: int) -> bytes:
    """
    Derive a Fernet key from the master password using PBKDF2-HMAC-SHA256.

    Fernet expects a urlsafe-base64-encoded 32-byte key.
    """
    if iterations < 100_000:
        raise ValueError("KDF iterations too low.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def generate_data_key() -> bytes:
    """Generate a new random Fernet data key."""
    return Fernet.generate_key()


def wrap_data_key(master_password: str, data_key: bytes, *, iterations: int = 310_000) -> VaultKeyMaterial:
    """
    Encrypt (wrap) the random data key with a KEK derived from the master password.
    """
    salt = os.urandom(16)
    kek = _derive_fernet_key_from_password(master_password, salt, iterations)
    wrapped = Fernet(kek).encrypt(data_key)
    return VaultKeyMaterial(
        kek_salt_b64=base64.b64encode(salt).decode("ascii"),
        wrapped_data_key_b64=base64.b64encode(wrapped).decode("ascii"),
        kdf_iterations=iterations,
    )


def unwrap_data_key(master_password: str, material: VaultKeyMaterial) -> bytes:
    """Decrypt (unwrap) the data key using the master password."""
    try:
        salt = base64.b64decode(material.kek_salt_b64)
        wrapped = base64.b64decode(material.wrapped_data_key_b64)
    except Exception as e:  # noqa: BLE001
        raise EncryptionError("Vault key material is corrupted.") from e

    kek = _derive_fernet_key_from_password(master_password, salt, material.kdf_iterations)
    try:
        return Fernet(kek).decrypt(wrapped)
    except InvalidToken as e:
        raise EncryptionError("Failed to unlock vault. Wrong master password or corrupted vault.") from e


def encrypt_secret(data_key: bytes, plaintext: str) -> str:
    """Encrypt plaintext using the data key. Returns base64 text token."""
    token = Fernet(data_key).encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(token).decode("ascii")


def decrypt_secret(data_key: bytes, token_b64: str) -> str:
    """Decrypt a stored token (base64 text) using the data key."""
    try:
        token = base64.b64decode(token_b64)
    except Exception as e:  # noqa: BLE001
        raise EncryptionError("Stored secret is corrupted.") from e
    try:
        plaintext = Fernet(data_key).decrypt(token)
    except InvalidToken as e:
        raise EncryptionError("Decryption failed. Data key mismatch or corrupted data.") from e
    return plaintext.decode("utf-8")

