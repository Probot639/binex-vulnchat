-- tables for the chat service. db_open() applies this when the database
-- file doesn't exist yet.
--
-- rough plan:
--   users     id, name, created_at   (names come off the auth tickets)
--   rooms     id, name, topic
--   members   room_id, user_id       (who's currently in what)
--   messages  id, room_id, user_id, body, sent_at
--
-- messages is the only one that really needs to grow - might want an
-- index on (room_id, sent_at) once we're replaying history on join.

-- TODO write these out

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 63),
    created_at int NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS rooms (
    room_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 31),
    topic TEXT NOT NULL DEFAULT '' CHECK (length(topic) <= 255)
);

CREATE TABLE IF NOT EXISTS members (
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    room_id INTEGER NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, room_id)
);

CREATE TABLE IF NOT EXISTS messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER NOT NULL REFERENCES rooms(room_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 4095),
    sent_at int NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS messages_room_id_sent_at ON messages(room_id, sent_at);