from __future__ import annotations

import secrets
import string
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordPolicy:
    """Password strength policy for user-entered passwords."""

    min_length: int = 12
    require_lower: bool = True
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = True


def check_password_strength(password: str, policy: PasswordPolicy = PasswordPolicy()) -> tuple[bool, list[str]]:
    """
    Validate a password against a policy.

    Returns (ok, issues). If ok is False, issues contains user-friendly reasons.
    """
    issues: list[str] = []
    if len(password) < policy.min_length:
        issues.append(f"Password must be at least {policy.min_length} characters long.")
    if policy.require_lower and not any(c.islower() for c in password):
        issues.append("Password must include at least one lowercase letter.")
    if policy.require_upper and not any(c.isupper() for c in password):
        issues.append("Password must include at least one uppercase letter.")
    if policy.require_digit and not any(c.isdigit() for c in password):
        issues.append("Password must include at least one number.")
    if policy.require_symbol and not any(c in string.punctuation for c in password):
        issues.append("Password must include at least one special character.")
    return (len(issues) == 0), issues


def generate_password(
    length: int = 20,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Generate a cryptographically secure random password."""
    if length < 8:
        raise ValueError("Password length must be at least 8.")

    pools: list[str] = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(string.punctuation)
    if not pools:
        raise ValueError("At least one character set must be enabled.")

    # Ensure at least one char from each enabled pool for usability/strength.
    chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def utc_now_s() -> int:
    """Current time as integer seconds since epoch (UTC)."""
    return int(time.time())


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Constant-time equality for bytes."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

