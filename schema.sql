-- TODO: password categories

CREATE TABLE passwords(
    password_id INTEGER PRIMARY KEY,
    service_name TEXT NOT NULL,
    service_url TEXT,
    account_name BLOB NOT NULL,
    password BLOB NOT NULL
);

CREATE TABLE salts(
    salt BLOB NOT NULL
);

CREATE TABLE fob_passwords(
    fob_password BLOB NOT NULL
);
