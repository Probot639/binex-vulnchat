# auth — simplified vulnerable IdP

Replaces the earlier SAML + Kerberos design. The auth server authenticates a
pre-existing user and hands back an **Ed25519-signed JWT** that the chat
servers verify with the IdP's public key. No XML, no KDC, no keytabs, no
realm, no TLS stack — one dependency (**libsodium**), one static-friendly
binary, same framed-TCP dialect as the chat server.

    Client ── LOGIN ──► auth (signs w/ private key) ── JWT ──► Client
    Client ── JWT ─────► chat (verifies w/ public key; cannot forge)

## Build & run

    make setup     # one-shot: Ed25519 keypair (keys/) + seed alice/password123
    make           # -> ./authd ./keygen
    make check     # proves NX on / no-PIE / no canary
    ./authd -p 4001 -k keys/idp_ed25519.sk -u users.tbl

Give `keys/idp_ed25519.pk` (32 bytes) to each chat server; it's all they need
to verify tokens. `keys/idp_ed25519.sk` never leaves the auth server.
Add users with `./keygen adduser <name> <secret> >> users.tbl`.

## Protocol

Outer frame = `uint32 length (BE)` + payload. `payload[0]` = opcode.

| op   | code | payload after opcode                                   | reply            |
|------|------|--------------------------------------------------------|------------------|
| LOGIN| 0x01 | u16 user_len, user[], u16 secret_len, secret[] (BE)    | framed JWT / ERR |
| DEBUG| 0x7F | (none)                                                 | 8-byte stack addr|

## Vulnerabilities (deliverable: proof of exploitability)

1. **Pre-auth stack overflow — `handle_login` (auth_login.c).** `user_len` is
   bounds-checked against the frame but not `sizeof(user[64])`; `memcpy`
   (NUL-transparent, so a ROP chain survives) copies up to ~8 KB over a
   64-byte stack buffer. No canary, copy runs before the credential check, so
   the smashed return fires pre-auth.

2. **Stack leak — `handle_debug` (auth_login.c).** Returns a live stack
   address (the "essfunc.dll"-style artifact). `fork()` doesn't re-randomize,
   so a leak from one connection is valid for the overflow on the next
   (verified: two children report the same address).

### Intended DEP-bypass chain (NX on, no-PIE, libc ASLR'd)

1. `DEBUG` → leak stack addr `L`; `&user = L + DELTA` (DELTA is a fixed
   per-build constant — pin it once with a cyclic pattern).
2. Overflow return with a ROP chain that **derefs a resolved libc GOT entry**
   (e.g. `read@got.plt` / `memcpy@got.plt` — both are called during normal
   operation, so lazy binding has populated them) and **`add`s the
   libc-specific `mprotect - <func>` delta** to compute `&mprotect`.
3. `mprotect(page_align(&user), 0x2000, RWX)` then `ret` into shellcode placed
   in the overflow payload at `&user + <your offset>`.

`mprotect - <func>` is specific to the target's libc; compute it from the
libc you ship or the testers run. Graduate requirement: custom shellcode in
place of the final stage.
