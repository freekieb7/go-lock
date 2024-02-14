CREATE TABLE IF NOT EXISTS tbl_client (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tbl_client_callback (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    uri TEXT NOT NULL,
    FOREIGN KEY(client_id) REFERENCES tbl_client(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tbl_user (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);