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


def select_row(value, column="service_name"):
    query = " ".join(["SELECT * FROM passwords WHERE", column, "= ?"])

    # TODO: Add exception handling
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, value)
        result = cursor.fetchone()

    return result


def select_single(table):
    # TODO: Add exception handling
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM " + table)
        result, = cursor.fetchone()

    return result
