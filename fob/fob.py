import os

import db
import crypto


def bytes_input(prompt):
    return input(prompt).encode("utf-8")


def config_db():
    fob_password = bytes_input("Enter a password to use for fob: ")
    hashed_fob_password = crypto.hash_fob_password(fob_password)

    db.insert("fob_passwords", "(fob_password)", (hashed_fob_password,))
    db.insert("salts", "(salt)", (os.urandom(16),))


def add_password():
    fob_password = bytes_input("Enter fob password: ")
    if crypto.hash_fob_password(fob_password) != db.select_single("fob_passwords"):
        # TODO: handle error properly
        quit()

    service_name = input("service name: ")
    service_url = input("service url: ")
    account_name = bytes_input("account name: ")
    password = bytes_input("password: ")

    hashed_account_name = crypto.encrypt(fob_password, account_name)
    hashed_password = crypto.encrypt(fob_password, password)

    db.insert(
        "passwords",
        "(service_name, service_url, account_name, password)",
        (service_name, service_url, hashed_account_name, hashed_password)
    )


def retreive_password():
    fob_password = bytes_input("Enter fob password: ")
    service_name = input("Service name: ")
    if crypto.hash_fob_password(fob_password) != db.select_single("fob_passwords"):
        # TODO: handle error properly
        quit()

    result = db.select_row((service_name,))
    if result is None:
        # TODO: handle error properly
        quit()

    result = {key: result[key] for key in result.keys()}
    result["account_name"] = crypto.decrypt(fob_password, result["account_name"])
    result["password"] = crypto.decrypt(fob_password, result["password"])
    return result


def main():
    # TODO: Logic w/ argparse
    print(retreive_password())


if __name__ == "__main__":
    main()
