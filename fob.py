import os
import base64
import hashlib
import sqlite3

from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def bytes_input(prompt):
    return input(prompt).encode("utf-8")


def config_db():
    fob_password = bytes_input("Enter a password to use for fob: ")
    hashed_fob_password = hash_fob_password(fob_password)

    with sqlite3.connect("fob.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO fob_passwords (fob_password) VALUES (?)",
            (hashed_fob_password,)
        )
        cursor.execute(
            "INSERT INTO salts (salt) VALUES (?)",
            (os.urandom(16),)
        )
        conn.commit()


def hash_fob_password(fob_password):
    hash_func = hashlib.sha256()
    hash_func.update(fob_password)
    return hash_func.digest()


def get_hashed_fob_password():
    with sqlite3.connect("fob.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM fob_passwords")
        hashed_fob_password, = cursor.fetchone()
    return hashed_fob_password


def get_salt():
    with sqlite3.connect("fob.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM salts")
        salt, = cursor.fetchone()
    return salt


def create_fernet_obj(fob_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=get_salt(),
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(fob_password))
    return Fernet(key)


def add_password():
    fob_password = bytes_input("Enter fob password: ")
    if hash_fob_password(fob_password) != get_hashed_fob_password():
        # TODO: handle error properly
        quit()

    service_name = input("service name: ")
    service_url = input("service url: ")
    account_name = bytes_input("account name: ")
    password = bytes_input("password: ")

    fernet = create_fernet_obj(fob_password)

    hashed_account_name = fernet.encrypt(account_name)
    hashed_password = fernet.encrypt(password)

    with sqlite3.connect("fob.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO passwords
            (service_name, service_url, account_name, password)
            VALUES (?, ?, ?, ?)""",
            (service_name, service_url, hashed_account_name, hashed_password)
        )
        conn.commit()


def retreive_password(service_name):
    fob_password = bytes_input("Enter fob password: ")
    if hash_fob_password(fob_password) != get_hashed_fob_password():
        # TODO: handle error properly
        quit()

    fernet = create_fernet_obj(fob_password)

    with sqlite3.connect("fob.db") as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM passwords
            WHERE service_name = ?""",
            (service_name,)
        )
        result = cursor.fetchone()
    result = {key: result[key] for key in result.keys()}
    result["account_name"] = fernet.decrypt(result["account_name"])
    result["password"] = fernet.decrypt(result["password"])
    return result


def main():
    pass


if __name__ == "__main__":
    main()
