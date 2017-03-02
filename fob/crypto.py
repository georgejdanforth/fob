import db
import os
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# TODO: Refactor crypto code into here


# TODO: investigate doing this with cryptography instead of hashlib
def hash_fob_password(fob_password):
    hash_func = hashlib.sha256()
    hash_func.update(fob_password)
    return hash_func.digest()


def create_fernet_obj(fob_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=db.select_single("salts"),
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(fob_password))
    return Fernet(key)


def decrypt(fob_password, hashed_data):
    # TODO: Add exception handling
    fernet = create_fernet_obj(fob_password)
    data = fernet.decrypt(hashed_data)
    return data.decode("utf-8")


def encrypt(fob_password, data):
    # TODO: Add exception handling
    fernet = create_fernet_obj(fob_password)
    hashed_data = fernet.encrypt(data)
    return hashed_data
