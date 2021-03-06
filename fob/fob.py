import os
import sys
import getpass
import tempfile

import db
import crypto


def bytes_input(prompt):
    return input(prompt).encode("utf-8")


def get_fob_password(prompt="Fob Password: "):
    return getpass.getpass(prompt=prompt).encode("utf-8")


def config_db():
    fob_password_1 = get_fob_password("Enter a password to use with fob: ")
    fob_password_2 = get_fob_password("Verify your password: ")

    if fob_password_1 != fob_password_2:
        print("Passwords do not match! Try again.")
    else:
        hashed_fob_password = crypto.hash_fob_password(fob_password_1)

        db.insert("fob_passwords", "(fob_password)", (hashed_fob_password,))
        db.insert("salts", "(salt)", (os.urandom(16),))


def help_message():
    # TODO: Add details.
    print("usage: fob <command> <argument>")


def write_read_password_tempfile(result):
    fd, fname = tempfile.mkstemp(text=True)

    try:
        f = os.fdopen(fd, "w")
        for key in ["service_name", "service_url", "account_name", "password"]:
            f.write(" ".join([key.replace("_", " "), ":", result[key], "\n"]))
        f.close()

        editor = os.environ.get("EDITOR", "vi")

        os.system(" ".join([editor, fname]))
    finally:
        os.unlink(fname)


def list_services():
    service_names = db.select_services()
    for service_name in service_names:
        print("*", service_name)


def add_password():
    fob_password = get_fob_password()
    if crypto.hash_fob_password(fob_password) != db.select_single("fob_passwords"):
        sys.exit("Incorrect password.")

    service_name = input("Service Name: ")
    service_url = input("Service URL: ")
    account_name = input("Account Name: ")

    existing_accounts = db.select_password(service_name, account_name)

    if existing_accounts is not None:
        sys.exit("Password already exists for account: '" + account_name + "'")

    password = bytes_input("Password: ")
    hashed_password = crypto.encrypt(fob_password, password)

    db.insert(
        "passwords",
        "(service_name, service_url, account_name, password)",
        (service_name, service_url, account_name, hashed_password)
    )


def retreive_password():
    fob_password = get_fob_password()
    if crypto.hash_fob_password(fob_password) != db.select_single("fob_passwords"):
        sys.exit("Incorrect password.")

    service_name = input("Service Name: ")
    account_name = input("Account Name: ")

    result = db.select_password(service_name, account_name)
    if result is None:
        sys.exit("Account not found.")

    result = {key: result[key] for key in result.keys() if key != "password_id"}
    result["password"] = str(crypto.decrypt(fob_password, result["password"]))

    write_read_password_tempfile(result)


commands = {
    "ls": list_services,
    "add": add_password,
    "get": retreive_password,
    "help": help_message,
    "config": config_db,  # remove this later
}


def main():
    # TODO: check if configured before execution
    if len(sys.argv) <= 1 or sys.argv[1] not in commands.keys():
        help_message()
    else:
        commands[sys.argv[1]]()


if __name__ == "__main__":
    main()
