# authd — Vulnerable IdP

Authenticates a pre-existing user and returns an **Ed25519-signed JWT** that
the chat servers verify with the IdP public key. Uses **SQLite** to store users,
schema in `schema.sql`, **one handle per process opened after `fork()`**.

    Client ── LOGIN ──► auth ──(verify vs sqlite users)──► sign ── JWT ──► Client
    Client ── JWT ─────► chat (verifies with public key; cannot forge)

# keygen - Encryption Key Generator

## Build & run

    make setup    # add the keys and users/passwords to auth.db
    make          # build the authd binary as well as the keygen binary
    make check    # checks the memory protections of the authd binary to verify build
    ./build/authd -p 4001 -k keys/idp_ed25519.sk -d build/auth.db       # example run

Add users: `./build/keygen adduser <name> <password> build/auth.db`.
Ship `keys/idp_ed25519.pk` (32 B) to each chat server; the `.sk` never leaves auth.

## Tables (schema.sql)

| table    | role                                          |
|----------|-----------------------------------------------|
| users    | credential store (name + argon2id secret_hash), provisioned ahead of time |
| auth_log | one row per issued JWT — the table that grows |

`users.name` has a maximum of 63 characters

## Vulnerabilities (PoC needed)

will be a leak vuln as well as a overflow vuln