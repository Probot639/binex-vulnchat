#!/bin/bash
# demo.sh - interactive demo of all three vulnchat services.
# start all servers, drop you into a netcat-style chat session.
# ctrl-c to tear everything down.

set -e

BASE="$(cd "$(dirname "$0")" && pwd)"
AUTHD="$BASE/services/auth/build/authd"
KEYGEN="$BASE/services/auth/build/keygen"
SK="$BASE/services/auth/keys/idp_ed25519.sk"
CHATD="$BASE/services/chat-linux/build/chatd"
CHATD_WIN="$BASE/services/chat-win/build/chatd.exe"

CYAN='\033[1;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
MAGENTA='\033[1;35m'
RED='\033[0;31m'
RESET='\033[0m'

PIDS=()

cleanup() {
    echo
    echo -e "${YELLOW}shutting down...${RESET}"
    for p in "${PIDS[@]}"; do
        kill "$p" 2>/dev/null || true
        wait "$p" 2>/dev/null || true
    done
    [ -n "$TMPDIR_DEMO" ] && rm -rf "$TMPDIR_DEMO"
    echo -e "${GREEN}done.${RESET}"
}
trap cleanup EXIT

wait_port() {
    local port=$1 tries=0
    while ! ss -tlnp 2>/dev/null | grep -q ":${port} " && [ $tries -lt 50 ]; do
        sleep 0.1
        tries=$((tries + 1))
    done
    if [ $tries -ge 50 ]; then
        echo -e "${RED}timeout waiting for port $port${RESET}"
        return 1
    fi
}

# pick free ports
auth_port=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
chat_port=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
win_port=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")

echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${CYAN}  binex-vulnchat  ·  interactive demo${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo

# ── auth server ──
echo -e "${MAGENTA}── 1. auth server ──${RESET}"
TMPDIR_DEMO=$(mktemp -d)
DB="$TMPDIR_DEMO/demo.db"
"$KEYGEN" adduser alice hunter2 "$DB" >/dev/null 2>&1
"$KEYGEN" adduser bob   letmein "$DB" >/dev/null 2>&1
echo -e "  ${GREEN}✓${RESET} created users: alice, bob"

"$AUTHD" -p "$auth_port" -k "$SK" -d "$DB" >/dev/null 2>&1 &
PIDS+=($!)
wait_port "$auth_port"
echo -e "  ${GREEN}✓${RESET} authd listening on :${auth_port}"

# ── linux chat ──
echo -e "${MAGENTA}── 2. linux chat server ──${RESET}"
"$CHATD" "$chat_port" >/dev/null 2>&1 &
PIDS+=($!)
wait_port "$chat_port"
echo -e "  ${GREEN}✓${RESET} chatd (linux) listening on :${chat_port}"

# ── windows chat ──
echo -e "${MAGENTA}── 3. windows chat server (wine) ──${RESET}"
WINEDEBUG=-all wine "$CHATD_WIN" "$win_port" >/dev/null 2>&1 &
PIDS+=($!)
wait_port "$win_port" || {
    # wine needs more time
    sleep 3
    wait_port "$win_port"
}
echo -e "  ${GREEN}✓${RESET} chatd.exe (wine) listening on :${win_port}"

# ── auth demo ──
echo
echo -e "${MAGENTA}── 4. auth: login + vuln demo ──${RESET}"

python3 -I - "$auth_port" <<'PYEOF'
import socket, struct, sys, json, base64

port = int(sys.argv[1])

def frame(p):
    return struct.pack("!I", len(p)) + p

def recv_frame(s):
    hdr = b""
    while len(hdr) < 4:
        hdr += s.recv(4 - len(hdr))
    n = struct.unpack("!I", hdr)[0]
    d = b""
    while len(d) < n:
        d += s.recv(n - len(d))
    return d

def login(user, pw):
    ub, pb = user.encode(), pw.encode()
    return bytes([0x01]) + struct.pack("!H", len(ub)) + ub + struct.pack("!H", len(pb)) + pb

# login alice
s = socket.create_connection(("127.0.0.1", port), timeout=3)
s.sendall(frame(login("alice", "hunter2")))
tok = recv_frame(s).decode()
s.close()
parts = tok.split(".")
claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
print(f"  \033[0;32m✓\033[0m alice login: JWT for '{claims['sub']}' ({len(tok)} bytes)")

# wrong password
s = socket.create_connection(("127.0.0.1", port), timeout=3)
s.sendall(frame(login("bob", "wrong")))
resp = recv_frame(s)
s.close()
print(f"  \033[0;32m✓\033[0m bob wrong pw: {resp.decode()}")

# debug leak
s = socket.create_connection(("127.0.0.1", port), timeout=3)
s.sendall(frame(bytes([0x7F])))
leak = recv_frame(s)
s.close()
addr = struct.unpack("<Q", leak.ljust(8, b'\x00')[:8])[0]
print(f"  \033[0;32m✓\033[0m debug leak:   0x{addr:016x} (stack address)")

# second leak, same address (fork reuse)
s = socket.create_connection(("127.0.0.1", port), timeout=3)
s.sendall(frame(bytes([0x7F])))
leak2 = recv_frame(s)
s.close()
addr2 = struct.unpack("<Q", leak2.ljust(8, b'\x00')[:8])[0]
match = "same" if addr == addr2 else "different"
print(f"  \033[0;32m✓\033[0m fork reuse:   0x{addr2:016x} ({match}, no ASLR re-randomization)")
PYEOF

# ── mitigation profile ──
echo
echo -e "${MAGENTA}── 5. mitigation profile ──${RESET}"
echo -e "  ${YELLOW}Linux (chatd):${RESET}"
if readelf -l "$CHATD" 2>/dev/null | grep -q "GNU_STACK.*RWE"; then
    echo -e "    NX: ${RED}OFF${RESET}"
else
    echo -e "    NX: ${GREEN}ON${RESET}"
fi
if readelf -h "$CHATD" 2>/dev/null | grep -q "DYN"; then
    echo -e "    PIE: ${RED}YES${RESET}"
else
    echo -e "    PIE: ${GREEN}NO (fixed addresses)${RESET}"
fi
if readelf -d "$CHATD" 2>/dev/null | grep -q "BIND_NOW"; then
    echo -e "    RELRO: ${RED}FULL${RESET}"
else
    echo -e "    RELRO: ${GREEN}PARTIAL (.got.plt writable)${RESET}"
fi

echo -e "  ${YELLOW}Windows (chatd.exe):${RESET}"
dllc=$(x86_64-w64-mingw32-objdump -p "$CHATD_WIN" 2>/dev/null | awk '/DllCharacteristics/{print $2}')
val=$((0x$dllc))
if [ $((val & 0x0040)) -ne 0 ]; then echo -e "    ASLR: ${RED}ON${RESET}"; else echo -e "    ASLR: ${GREEN}OFF${RESET}"; fi
if [ $((val & 0x0100)) -eq 0 ]; then echo -e "    DEP:  ${RED}OFF${RESET}"; else echo -e "    DEP:  ${GREEN}ON${RESET}"; fi
if [ $((val & 0x4000)) -ne 0 ]; then echo -e "    CFG:  ${RED}ON${RESET}"; else echo -e "    CFG:  ${GREEN}OFF${RESET}"; fi

# ── interactive chat ──
echo
echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${CYAN}  servers are running. connect and chat:${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo
echo -e "  ${YELLOW}Linux chat:${RESET}   ncat 127.0.0.1 ${chat_port}"
echo -e "  ${YELLOW}Windows chat:${RESET} ncat 127.0.0.1 ${win_port}"
echo
echo -e "  first 4 bytes = big-endian length, then payload."
echo -e "  or use the python helper:"
echo
echo -e "  ${MAGENTA}python3 $BASE/demo_client.py 127.0.0.1 ${chat_port} <nick>${RESET}"
echo -e "  ${MAGENTA}python3 $BASE/demo_client.py 127.0.0.1 ${win_port} <nick>${RESET}"
echo
echo -e "  ctrl-c to shut everything down."
echo

# keep running until ctrl-c
wait
