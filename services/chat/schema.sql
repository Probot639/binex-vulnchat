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
CREATE DATABASE vulnchat_db;
USE vulnchat_db;

CREATE TABLE users (
    user_id INT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50),
    created_at DATETIME
)

CREATE TABLE rooms (
    room_id INT PRIMARY KEY,
    room_name VARCHAR(50),
    topic VARCHAR(50)
)

CREATE TABLE members (
    user_id INT PRIMARY KEY,
    room_id INT PRIMARY KEY
    CONSTRAINT PK_members PRIMARY KEY (user_id, room_id)
)

CREATE TABLE messages (
    message_id INT PRIMARY KEY,
    room_id INT,
    user_id INT,
    body VARCHAR(2000),
    sent_at DATETIME
)

SELECT * FROM users;
SELECT * FROM members;