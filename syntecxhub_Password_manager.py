import os
import json
import base64
from getpass import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


CONFIG_FILE = "config.json"
VAULT_FILE = "vault.enc"


# --------------------------------------------------
# First-time setup
# --------------------------------------------------
def setup_master_password():
    print("\n First time setup")
    print("Create a master password (cannot be recovered later)\n")

    while True:
        pwd1 = getpass("New master password: ")
        pwd2 = getpass("Confirm master password: ")

        if pwd1 == pwd2 and pwd1.strip() != "":
            break
        print("Passwords do not match. Try again.\n")

    salt = os.urandom(16)

    config = {
        "salt": salt.hex(),
        "iterations": 200000
    }

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

    key = derive_key(pwd1, salt, config["iterations"])
    create_empty_vault(key)

    print("\n Setup completed. Vault created successfully.\n")


# --------------------------------------------------
# Key derivation
# --------------------------------------------------
def derive_key(password, salt, iterations):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# --------------------------------------------------
# Vault helpers
# --------------------------------------------------
def create_empty_vault(key):
    f = Fernet(key)
    encrypted = f.encrypt(json.dumps({}).encode())

    with open(VAULT_FILE, "wb") as file:
        file.write(encrypted)


def load_vault(key):
    with open(VAULT_FILE, "rb") as file:
        encrypted = file.read()

    f = Fernet(key)
    decrypted = f.decrypt(encrypted).decode()
    return json.loads(decrypted)


def save_vault(vault, key):
    f = Fernet(key)
    encrypted = f.encrypt(json.dumps(vault).encode())

    with open(VAULT_FILE, "wb") as file:
        file.write(encrypted)


# --------------------------------------------------
# Vault operations
# --------------------------------------------------
def add_entry(vault):
    site = input("Website/App name: ").strip()
    username = input("Username: ").strip()
    password = getpass("Password: ").strip()

    if site == "":
        print("Site name cannot be empty.")
        return

    vault[site] = {
        "username": username,
        "password": password
    }

    print(" Entry added successfully.")


def retrieve_entry(vault):
    site = input("Enter site name: ").strip()

    if site in vault:
        print("\nStored Credentials:")
        print("Username:", vault[site]["username"])
        print("Password:", vault[site]["password"])
    else:
        print(" Entry not found.")


def delete_entry(vault):
    site = input("Enter site name to delete: ").strip()

    if site in vault:
        del vault[site]
        print(" Entry deleted.")
    else:
        print(" Entry not found.")


def search_entries(vault):
    keyword = input("Search keyword: ").lower().strip()
    found = False

    for site in vault:
        if keyword in site.lower():
            print("•", site)
            found = True

    if not found:
        print(" No matching entries found.")


def show_all_entries(vault):
    if not vault:
        print("Vault is empty.")
        return

    print("\nStored Passwords (Table View):\n")
    print(f"{'Website':<20} {'Username':<25} {'Password':<10}")
    print("-" * 60)

    for site, data in vault.items():
        print(f"{site:<20} {data['username']:<25} {'':<10}")


# --------------------------------------------------
# Menu
# --------------------------------------------------
def show_menu():
    print("""
========= PASSWORD MANAGER =========
1. Add new password
2. Retrieve password
3. Delete password
4. Search entries
5. Show all entries (table)
6. Exit
""")


# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    if not os.path.exists(CONFIG_FILE):
        setup_master_password()

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    salt = bytes.fromhex(config["salt"])
    iterations = config["iterations"]

    master_password = getpass("Enter master password: ")
    key = derive_key(master_password, salt, iterations)

    try:
        vault = load_vault(key)
    except Exception:
        print(" Incorrect master password or corrupted vault.")
        return

    while True:
        show_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            add_entry(vault)
            save_vault(vault, key)

        elif choice == "2":
            retrieve_entry(vault)

        elif choice == "3":
            delete_entry(vault)
            save_vault(vault, key)

        elif choice == "4":
            search_entries(vault)

        elif choice == "5":
            show_all_entries(vault)

        elif choice == "6":
            print(" Vault locked. Goodbye.")
            break

        else:
            print("Invalid option. Try again.")


if _name_ == "_main_":
    main()