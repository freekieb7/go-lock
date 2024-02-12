CREATE TABLE IF NOT EXISTS client (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS client_redirect (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    FOREIGN KEY(client_id) REFERENCES client(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS account (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);


-- INSERT INTO example_table (name) VALUES ('Test UserName');
-- INSERT INTO example_table (name) VALUES ('Mark Silva');
-- INSERT INTO example_table (name) VALUES ('Hector Kamara');
-- INSERT INTO example_table (name) VALUES ('Greg Anthony');