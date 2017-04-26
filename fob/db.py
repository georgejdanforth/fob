import sqlite3


DB_PATH = "fob.db"  # TODO: Change this to a better location later


def insert(table, columns, values):
    query = " ".join([
        "INSERT INTO",
        table,
        columns,
        "VALUES",
        "({})".format(", ".join(["?"] * len(values)))
    ])

    # TODO: Add exception handling
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(query, values)


def select_password(service_name, account_name):
    query = "SELECT * FROM passwords WHERE service_name = ? AND account_name = ?"

    # TODO: Add exception handling
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, (service_name, account_name))
        result = cursor.fetchone()

    return result


# This can probably be removed
def select_row(value, column="service_name", many=False):
    query = " ".join(["SELECT * FROM passwords WHERE", column, "= ?"])

    # TODO: Add exception handling
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, value)
        if many:
            result = cursor.fetchall()
        else:
            result = cursor.fetchone()

    return result


def select_single(table):
    # TODO: Add exception handling
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM " + table)
        result, = cursor.fetchone()

    return result


def select_services():
    # TODO: Add exception handling
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT service_name FROM passwords")
        result = [service_name[0] for service_name in cursor.fetchall()]

    return result
