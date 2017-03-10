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
    print("usage: fob <command> <argument>")


def write_read_password_tempfile(result):
    # TODO: exception handling
    fd, fname = tempfile.mkstemp(text=True)
    f = os.fdopen(fd, "w")
    for key in result.keys():
        f.write(" ".join([key, "-", result[key], "\n"]))
    f.close()
    os.system("$EDITOR " + fname)    
    os.unlink(fname)


def add_password():
    fob_password = get_fob_password()
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
    fob_password = get_fob_password()
    service_name = input("Service name: ")
    if crypto.hash_fob_password(fob_password) != db.select_single("fob_passwords"):
        # TODO: handle error properly
        quit()

    result = db.select_row((service_name,))
    if result is None:
        # TODO: handle error properly
        quit()

    result = {key: result[key] for key in result.keys() if key != "password_id"}

    # lol @ these 2 lines
    for field in ["account_name", "password"]:
        result[field] = str(crypto.decrypt(fob_password, result[field]))

    write_read_password_tempfile(result)


commands = {
    "add": add_password,
    "get": retreive_password,
    "help": help_message,
}


def main():
    # TODO: check if configured before execution
    if len(sys.argv) <= 1 or sys.argv[1] not in commands.keys():
        help_message()
    else:
        commands[sys.argv[1]]()


if __name__ == "__main__":
    main()
