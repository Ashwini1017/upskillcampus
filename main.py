from __future__ import annotations

import getpass
import os
import sys
import textwrap
import time
from typing import Optional

import tkinter as tk

from auth import (
    AuthError,
    MasterAuthRecord,
    create_master_record,
    generate_otp_secret,
    totp_now,
    verify_master_password,
    verify_totp,
)
from encryption import EncryptionError, generate_data_key, unwrap_data_key, wrap_data_key
from password_manager import (
    Vault,
    VaultError,
    add_credential,
    delete_credential,
    get_credential,
    list_credentials,
    load_vault,
    save_vault,
    search_credentials,
    update_credential,
)
from utils import PasswordPolicy, check_password_strength, generate_password, utc_now_s


DEFAULT_VAULT_PATH = os.path.join(os.path.dirname(__file__), "vault.json")
AUTO_LOCK_SECONDS = 180


class Session:
    def __init__(self) -> None:
        self.vault: Vault | None = None
        self.data_key: bytes | None = None
        self.last_activity_s: int = utc_now_s()

    def touch(self) -> None:
        self.last_activity_s = utc_now_s()

    def is_locked(self) -> bool:
        return (utc_now_s() - self.last_activity_s) > AUTO_LOCK_SECONDS

    def require_unlocked(self) -> tuple[Vault, bytes]:
        if self.vault is None or self.data_key is None:
            raise RuntimeError("Not logged in.")
        if self.is_locked():
            self.vault = None
            self.data_key = None
            raise RuntimeError("Session auto-locked due to inactivity. Please log in again.")
        self.touch()
        return self.vault, self.data_key


def _print_header() -> None:
    print("\n" + "=" * 60)
    print("Password Manager (Secure CLI)")
    print("=" * 60)


def _input(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
        raise SystemExit(0)


def _pause() -> None:
    _input("\nPress Enter to continue...")


def _copy_to_clipboard(text: str) -> bool:
    """
    Copy to clipboard using Tkinter (standard library).
    This avoids third-party dependencies like pyperclip.
    """
    try:
        root = tk.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        root.destroy()
        return True
    except Exception:
        return False


def initialize_vault(path: str) -> None:
    if os.path.exists(path):
        print("A vault already exists at this path.")
        return

    print("Create a new vault.")
    while True:
        master = getpass.getpass("Create master password: ")
        ok, issues = check_password_strength(master, PasswordPolicy(min_length=12))
        if not ok:
            print("Master password is too weak:")
            for issue in issues:
                print(f"- {issue}")
            continue
        master2 = getpass.getpass("Confirm master password: ")
        if master != master2:
            print("Passwords do not match.")
            continue
        break

    master_record = create_master_record(master)
    data_key = generate_data_key()
    key_material = wrap_data_key(master, data_key)

    # OTP is optional; we store its secret encrypted with data_key.
    enable_otp = _input("Enable OTP simulation (y/N)? ").strip().lower() == "y"
    otp_enabled = False
    otp_secret_enc_b64: str | None = None
    if enable_otp:
        from encryption import encrypt_secret

        otp_secret = generate_otp_secret()
        otp_secret_enc_b64 = encrypt_secret(data_key, otp_secret)
        otp_enabled = True
        print("OTP enabled. (For simulation, the code will be shown at login.)")

    vault = Vault(
        path=path,
        master=master_record,
        key_material=key_material,
        credentials={},
        otp_enabled=otp_enabled,
        otp_secret_enc_b64=otp_secret_enc_b64,
    )
    save_vault(vault, updated_at=utc_now_s())
    print(f"Vault created at: {path}")


def login(path: str, session: Session) -> None:
    try:
        vault = load_vault(path)
    except VaultError as e:
        print(str(e))
        return

    master = getpass.getpass("Master password: ")
    try:
        if not verify_master_password(master, vault.master):
            print("Invalid master password.")
            return
    except (AuthError, Exception) as e:
        print(f"Authentication error: {e}")
        return

    try:
        data_key = unwrap_data_key(master, vault.key_material)
    except EncryptionError as e:
        print(str(e))
        return

    if vault.otp_enabled:
        if not vault.otp_secret_enc_b64:
            print("OTP is enabled but secret is missing. Vault may be corrupted.")
            return
        from encryption import decrypt_secret

        try:
            otp_secret = decrypt_secret(data_key, vault.otp_secret_enc_b64)
        except EncryptionError as e:
            print(f"OTP secret error: {e}")
            return

        # Simulation: show the code as if "sent".
        code = totp_now(otp_secret)
        print(f"[SIMULATION] OTP code: {code} (valid ~30s)")
        entered = _input("Enter OTP: ").strip()
        if not verify_totp(otp_secret, entered):
            print("Invalid OTP.")
            return

    session.vault = vault
    session.data_key = data_key
    session.touch()
    print("Login successful.")


def logout(session: Session) -> None:
    session.vault = None
    session.data_key = None
    print("Logged out.")


def _menu() -> None:
    print(
        textwrap.dedent(
            """
        1) Add credential
        2) View credential (decrypt)
        3) List credentials
        4) Update credential
        5) Delete credential
        6) Search
        7) Generate password
        8) Copy password to clipboard
        9) Save vault
        10) Logout
        0) Exit
        """
        ).strip()
    )


def run_cli(vault_path: str) -> None:
    session = Session()
    if not os.path.exists(vault_path):
        _print_header()
        print("No vault found. Let's initialize one.")
        initialize_vault(vault_path)

    while True:
        _print_header()
        if session.vault is None:
            print("Status: Locked (not logged in)")
            print(f"Vault: {vault_path}")
            print("\n1) Login\n2) Initialize new vault (overwrites)\n0) Exit")
            choice = _input("> ").strip()
            if choice == "1":
                login(vault_path, session)
                _pause()
            elif choice == "2":
                if os.path.exists(vault_path):
                    confirm = _input("This will overwrite the existing vault. Type 'YES' to continue: ").strip()
                    if confirm != "YES":
                        print("Cancelled.")
                        _pause()
                        continue
                    try:
                        os.remove(vault_path)
                    except OSError:
                        print("Failed to remove existing vault.")
                        _pause()
                        continue
                initialize_vault(vault_path)
                _pause()
            elif choice == "0":
                return
            else:
                print("Invalid choice.")
                _pause()
            continue

        # Logged-in menu
        try:
            vault, data_key = session.require_unlocked()
        except RuntimeError as e:
            print(str(e))
            _pause()
            continue

        print(f"Status: Unlocked (auto-lock in {AUTO_LOCK_SECONDS}s idle)")
        _menu()
        choice = _input("> ").strip()

        try:
            if choice == "1":
                website = _input("Website: ")
                username = _input("Username: ")
                mode = _input("Enter password manually (m) or generate (g)? [m/g]: ").strip().lower() or "m"
                if mode == "g":
                    length_s = _input("Length (default 20): ").strip()
                    length = int(length_s) if length_s else 20
                    password = generate_password(length=length)
                    print("Generated password created.")
                else:
                    password = getpass.getpass("Password: ")
                add_credential(vault, data_key, website, username, password)
                print("Credential added.")

            elif choice == "2":
                website = _input("Website: ")
                username = _input("Username: ")
                item = get_credential(vault, data_key, website, username)
                print(f"Website : {item['website']}")
                print(f"Username: {item['username']}")
                print(f"Password: {item['password']}")

            elif choice == "3":
                items = list_credentials(vault)
                if not items:
                    print("No credentials stored.")
                else:
                    for i, it in enumerate(items, 1):
                        print(f"{i}. {it['website']}  |  {it['username']}")

            elif choice == "4":
                website = _input("Website: ")
                username = _input("Username: ")
                new_user = _input("New username (leave blank to keep): ").strip()
                change_pw = _input("Change password (y/N)? ").strip().lower() == "y"
                new_pw: Optional[str] = None
                if change_pw:
                    new_pw = getpass.getpass("New password (leave blank to generate): ")
                    if not new_pw:
                        new_pw = generate_password()
                        print("Generated a new password.")
                update_credential(
                    vault,
                    data_key,
                    website,
                    username,
                    new_username=(new_user if new_user else None),
                    new_password=new_pw,
                )
                print("Credential updated.")

            elif choice == "5":
                website = _input("Website: ")
                username = _input("Username: ")
                confirm = _input("Type 'DELETE' to confirm: ").strip()
                if confirm != "DELETE":
                    print("Cancelled.")
                else:
                    delete_credential(vault, website, username)
                    print("Credential deleted.")

            elif choice == "6":
                q = _input("Search query (website/username): ")
                results = search_credentials(vault, q)
                if not results:
                    print("No matches.")
                else:
                    for i, it in enumerate(results, 1):
                        print(f"{i}. {it['website']}  |  {it['username']}")

            elif choice == "7":
                length_s = _input("Length (default 20): ").strip()
                length = int(length_s) if length_s else 20
                pw = generate_password(length=length)
                print(f"Generated: {pw}")

            elif choice == "8":
                website = _input("Website: ")
                username = _input("Username: ")
                item = get_credential(vault, data_key, website, username)
                if _copy_to_clipboard(item["password"]):
                    print("Password copied to clipboard.")
                else:
                    print("Clipboard copy failed on this system.")

            elif choice == "9":
                save_vault(vault, updated_at=utc_now_s())
                print("Vault saved.")

            elif choice == "10":
                save_vault(vault, updated_at=utc_now_s())
                logout(session)

            elif choice == "0":
                if session.vault is not None:
                    try:
                        save_vault(session.vault, updated_at=utc_now_s())
                    except Exception:
                        pass
                return
            else:
                print("Invalid choice.")

        except (ValueError, KeyError) as e:
            print(f"Error: {e}")
        except VaultError as e:
            print(f"Vault error: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"Unexpected error: {e}")

        session.touch()
        _pause()


def main() -> None:
    vault_path = DEFAULT_VAULT_PATH
    if len(sys.argv) > 1:
        vault_path = sys.argv[1]
    run_cli(vault_path)


if __name__ == "__main__":
    main()

