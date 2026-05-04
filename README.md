# Password Manager (Secure CLI, Python)

## Features
- **Master password authentication** using PBKDF2-HMAC-SHA256 (salted, no plaintext storage)
- **Encrypted password storage** using `cryptography` Fernet (no plaintext passwords on disk)
- **CRUD**: add, view (decrypt after login), update, delete
- **Search** by website or username
- **Password strength checker** for master password
- **Password generator** (configurable length)
- **Optional OTP simulation** (TOTP-style code shown at login)
- **Clipboard copy** (standard library `tkinter`)
- **Auto-lock** after inactivity (default 180s)

## Project Structure
- `auth.py`: master password hashing + OTP simulation
- `encryption.py`: Fernet encryption/decryption + key wrapping
- `password_manager.py`: vault JSON persistence + CRUD/search operations
- `utils.py`: strength checker, generator, time helpers
- `main.py`: CLI entry point

## Storage Format
Vault is stored in `vault.json` (created on first run). Credentials look like:

```json
{
  "credentials": {
    "example.com::alice": {
      "website": "example.com",
      "username": "alice",
      "password": "ENCRYPTED_BASE64_TOKEN"
    }
  }
}
```

## Security Notes (Design)
- The vault stores **only**:
  - PBKDF2 record for verifying the master password (salt + hash)
  - A **random data key** wrapped (encrypted) by a key derived from the master password
  - Encrypted credentials
- Passwords are never stored in plaintext.

## Requirements
- Python 3.11+ recommended
- `cryptography`

Install dependency:

```bash
pip install -r requirements.txt
```

## How to Run

```bash
python main.py
```

Optionally specify a custom vault path:

```bash
python main.py "C:\path\to\my_vault.json"
```

## Testing

```bash
python -m unittest -v
```

