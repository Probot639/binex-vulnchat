# Distributing Binaries to Other Teams

How to package the vulnchat services for teams that get binaries only
(no source, no exploits, no tests).

## What goes in the package

```
vulnchat-dist/
├── linux/
│   ├── authd                  # auth server (ELF 32-bit i386)
│   ├── chatd                  # chat server (ELF 64-bit x86-64)
│   └── chat_client            # chat client (ELF 64-bit x86-64, PIE)
├── windows/
│   ├── chatd.exe              # chat server (PE32+ x86-64)
│   ├── chat_client.exe        # chat client (PE32+ x86-64)
│   ├── libsodium-26.dll       # runtime dep for chatd.exe
│   └── authclient.dll         # runtime dep for chat_client.exe
├── keys/
│   └── idp_ed25519.pk         # public key (shared with chat servers)
└── README.txt                 # usage instructions (see below)
```

## What stays out

Do NOT include any of these:

- `services/*/src/` (source code)
- `services/*/include/` (headers)
- `services/*/Makefile` (reveals compiler flags and vuln-preserving options)
- `exploits/` (the whole directory)
- `tests/` (the whole directory)
- `keys/idp_ed25519.sk` (auth server secret key, only the team running authd needs it)
- `.o` files from build directories
- `.git/` history
- `DESIGN.md`, `.claude/`, any internal docs

## Stripping binaries

The binaries ship with full symbols and DWARF debug info. Decide based
on what difficulty you want:

**Keep symbols, strip debug info (recommended for this course):**

Teams can see function names in Ghidra/IDA (cmd_nick, msg_free, etc.)
but don't get source file paths, line numbers, or variable names.

```bash
# Linux binaries
strip --strip-debug services/auth/build/authd -o dist/linux/authd
strip --strip-debug services/chat-linux/build/chatd -o dist/linux/chatd
strip --strip-debug services/client-linux/build/chat_client -o dist/linux/chat_client

# Windows binaries
x86_64-w64-mingw32-strip --strip-debug services/chat-win/build/chatd.exe -o dist/windows/chatd.exe
x86_64-w64-mingw32-strip --strip-debug services/client-win/build/chat_client.exe -o dist/windows/chat_client.exe
```

**Full strip (harder, hides function names too):**

Teams have to identify functions from disassembly alone.

```bash
strip --strip-all services/chat-linux/build/chatd -o dist/linux/chatd
x86_64-w64-mingw32-strip --strip-all services/chat-win/build/chatd.exe -o dist/windows/chatd.exe
```

**No strip (easiest, current state):**

Teams get symbols AND debug info. They can map addresses to source
lines in Ghidra. Good for intro-level work.

```bash
cp services/chat-linux/build/chatd dist/linux/chatd
```

## Packaging script

Run from the repo root:

```bash
#!/bin/bash
set -e

DIST=vulnchat-dist
STRIP_LEVEL="${1:-debug}"   # "debug", "all", or "none"

rm -rf "$DIST"
mkdir -p "$DIST"/{linux,windows,keys}

case "$STRIP_LEVEL" in
    debug)
        strip --strip-debug services/auth/build/authd -o "$DIST/linux/authd"
        strip --strip-debug services/chat-linux/build/chatd -o "$DIST/linux/chatd"
        strip --strip-debug services/client-linux/build/chat_client -o "$DIST/linux/chat_client"
        x86_64-w64-mingw32-strip --strip-debug services/chat-win/build/chatd.exe -o "$DIST/windows/chatd.exe"
        x86_64-w64-mingw32-strip --strip-debug services/client-win/build/chat_client.exe -o "$DIST/windows/chat_client.exe"
        ;;
    all)
        strip --strip-all services/auth/build/authd -o "$DIST/linux/authd"
        strip --strip-all services/chat-linux/build/chatd -o "$DIST/linux/chatd"
        strip --strip-all services/client-linux/build/chat_client -o "$DIST/linux/chat_client"
        x86_64-w64-mingw32-strip --strip-all services/chat-win/build/chatd.exe -o "$DIST/windows/chatd.exe"
        x86_64-w64-mingw32-strip --strip-all services/client-win/build/chat_client.exe -o "$DIST/windows/chat_client.exe"
        ;;
    none)
        cp services/auth/build/authd "$DIST/linux/"
        cp services/chat-linux/build/chatd "$DIST/linux/"
        cp services/client-linux/build/chat_client "$DIST/linux/"
        cp services/chat-win/build/chatd.exe "$DIST/windows/"
        cp services/client-win/build/chat_client.exe "$DIST/windows/"
        ;;
esac

# runtime DLLs for Windows
cp services/chat-win/build/libsodium-26.dll "$DIST/windows/"
cp services/client-win/build/authclient.dll "$DIST/windows/"

# public key only (NOT the secret key)
cp services/auth/keys/idp_ed25519.pk "$DIST/keys/"

chmod +x "$DIST"/linux/*

echo "packaged to $DIST/ (strip level: $STRIP_LEVEL)"
echo "contents:"
find "$DIST" -type f -exec ls -lh {} \;
```

## Auth server setup

The team running the auth server needs the secret key, which is NOT in
the distribution package. Generate a fresh keypair for each deployment:

```bash
# on the auth server host (has source access)
cd services/auth && make
./build/keygen keys                          # writes keys/idp_ed25519.{sk,pk}
./build/keygen adduser <user> <pass> auth.db # create accounts
./build/authd -p 4001 -k keys/idp_ed25519.sk -d auth.db
```

Then distribute `keys/idp_ed25519.pk` (the public key) to every team
running a chat server. The secret key stays on the auth host.

## What teams get told

Include a README.txt in the package (not this file). Template:

```
vulnchat - chat service

three components:
  authd       - authentication server (Linux, 32-bit)
  chatd       - chat server (Linux 64-bit or Windows 64-bit)
  chat_client - terminal chat client

running the linux chat server:
  ./chatd -p 4002 -k idp_ed25519.pk

running the windows chat server:
  chatd.exe -p 4002 -k idp_ed25519.pk
  (place libsodium-26.dll in the same directory as chatd.exe)

running the client:
  ./chat_client -h <server-ip> -p 4002 --auth <auth-ip>:4001

the auth server will be provided by the course staff at <auth-ip>:4001.
register an account through the auth server's API before connecting.

protocol: length-prefixed binary frames (4-byte big-endian length + payload).
auth handshake: first frame is a JWT from the auth server.
commands: /nick /me /who /join /repeat /help

the services have deliberate vulnerabilities. find them.
```

Adjust the README based on what you want teams to know. Less info means
harder recon. The command list is visible via `/help` anyway, so
including it just saves time.

## Runtime dependencies

Teams running the binaries need:

| Binary | Platform | Dependencies |
|--------|----------|--------------|
| authd | Linux (any, 32-bit compat) | libsqlite3, libsodium (32-bit) |
| chatd (linux) | Linux x86-64 | libsodium |
| chatd.exe | Windows x86-64 or Wine | libsodium-26.dll (bundled) |
| chat_client | Linux x86-64 | libncursesw |
| chat_client.exe | Windows x86-64 or Wine | authclient.dll (bundled) |

On Debian/Ubuntu for the Linux binaries:
```bash
sudo apt install libsodium23 libsqlite3-0 libncursesw6
# for 32-bit authd on 64-bit host:
sudo dpkg --add-architecture i386
sudo apt install libsodium23:i386 libsqlite3-0:i386
```

On Arch:
```bash
sudo pacman -S libsodium sqlite ncurses
# 32-bit: enable multilib, pacman -S lib32-libsodium lib32-sqlite
```

## Verifying the package

Before handing it off, check that you didn't accidentally include
source or exploit files:

```bash
find vulnchat-dist/ -name "*.c" -o -name "*.h" -o -name "*.cpp" \
  -o -name "*.py" -o -name "Makefile" -o -name "*.o" -o -name "*.sk"
# should print nothing
```

Check that binaries run:

```bash
vulnchat-dist/linux/chatd --help
wine vulnchat-dist/windows/chatd.exe --help
```
