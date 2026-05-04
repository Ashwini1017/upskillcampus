from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass

from utils import constant_time_equals, utc_now_s


class AuthError(Exception):
    """Raised when authentication fails."""


@dataclass(frozen=True)
class MasterAuthRecord:
    """Data stored to verify a master password without storing it."""

    salt_b64: str
    hash_b64: str
    iterations: int


def create_master_record(master_password: str, *, iterations: int = 310_000) -> MasterAuthRecord:
    """
    Create a PBKDF2-HMAC-SHA256 record for verifying the master password.
    """
    if iterations < 100_000:
        raise ValueError("PBKDF2 iterations too low.")
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, iterations, dklen=32)
    return MasterAuthRecord(
        salt_b64=base64.b64encode(salt).decode("ascii"),
        hash_b64=base64.b64encode(dk).decode("ascii"),
        iterations=iterations,
    )


def verify_master_password(master_password: str, record: MasterAuthRecord) -> bool:
    """Verify the master password against a stored PBKDF2 record."""
    try:
        salt = base64.b64decode(record.salt_b64)
        expected = base64.b64decode(record.hash_b64)
    except Exception:
        raise AuthError("Vault authentication record is corrupted.")
    candidate = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, record.iterations, dklen=32)
    return constant_time_equals(candidate, expected)


def generate_otp_secret() -> str:
    """Generate a base32 OTP secret (for simulation)."""
    # 20 bytes is typical for OTP secrets; base32 is user-friendly.
    raw = os.urandom(20)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """
    RFC4226-style HOTP (used by TOTP). Secret is base32 without padding.
    """
    padding = "=" * ((8 - (len(secret_b32) % 8)) % 8)
    key = base64.b32decode((secret_b32 + padding).encode("ascii"), casefold=True)
    msg = counter.to_bytes(8, "big")
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code_int = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def totp_now(secret_b32: str, *, step_seconds: int = 30, digits: int = 6, at_time_s: int | None = None) -> str:
    """
    Generate a TOTP code for the current time (simulation-friendly).
    """
    t = utc_now_s() if at_time_s is None else at_time_s
    counter = t // step_seconds
    return _hotp(secret_b32, counter, digits=digits)


def verify_totp(
    secret_b32: str,
    code: str,
    *,
    step_seconds: int = 30,
    digits: int = 6,
    allowed_drift_steps: int = 1,
    at_time_s: int | None = None,
) -> bool:
    """
    Verify a TOTP code allowing small clock drift.
    """
    if not code.isdigit() or len(code) != digits:
        return False
    t = utc_now_s() if at_time_s is None else at_time_s
    counter = t // step_seconds
    for delta in range(-allowed_drift_steps, allowed_drift_steps + 1):
        if totp_now(secret_b32, step_seconds=step_seconds, digits=digits, at_time_s=(t + delta * step_seconds)) == code:
            return True
    return False

