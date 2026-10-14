-- auth service store. db_open() applies this on open
--
--   users     credential store, provisioned ahead of time (keygen adduser)
--   auth_log  one row per issued JWT -- the table that actually grows
--
-- users.name is capped at 63 chars

CREATE TABLE IF NOT EXISTS users (
    user_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 63),
    secret_hash TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS auth_log (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL,
    iat   INTEGER NOT NULL,
    exp   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_log_name_iat ON auth_log(name, iat);
