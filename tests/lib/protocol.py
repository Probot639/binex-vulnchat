"""
protocol.py - wire protocol for both auth and chat services.

both use the same framing: 4-byte big-endian length prefix, then payload.
auth adds an opcode byte at payload[0]. chat uses raw text or '/' commands.
"""

import socket
import struct
import base64
import json

# auth opcodes
OP_LOGIN = 0x01
OP_DEBUG = 0x7F

# defaults
AUTH_PORT = 4001
CHAT_PORT = 4002


def frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


def recv_frame(sock, timeout=3.0):
    sock.settimeout(timeout)
    hdr = _recvn(sock, 4)
    if hdr is None:
        return None
    n = struct.unpack("!I", hdr)[0]
    if n == 0:
        return b""
    return _recvn(sock, n)


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def connect(host, port, timeout=3.0):
    return socket.create_connection((host, port), timeout=timeout)


def send_recv(host, port, payload, timeout=3.0):
    s = connect(host, port, timeout)
    try:
        s.sendall(frame(payload))
        return recv_frame(s, timeout)
    finally:
        s.close()


# ---- auth-specific helpers ----

def login_payload(user: bytes, secret: bytes) -> bytes:
    return (bytes([OP_LOGIN])
            + struct.pack("!H", len(user)) + user
            + struct.pack("!H", len(secret)) + secret)


def debug_payload() -> bytes:
    return bytes([OP_DEBUG])


def parse_jwt(tok: bytes):
    parts = tok.decode().split(".")
    if len(parts) != 3:
        return None, None, None
    hdr = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    sig = b64url_decode(parts[2])
    return hdr, claims, sig


def jwt_signing_input(tok: bytes) -> bytes:
    parts = tok.decode().split(".")
    return (parts[0] + "." + parts[1]).encode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def get_jwt(auth_host, auth_port, user="testuser", password="testpass"):
    """authenticate and return the raw JWT bytes."""
    payload = login_payload(user.encode(), password.encode())
    resp = send_recv(auth_host, auth_port, payload)
    if resp is None or resp.startswith(b"ERR"):
        raise RuntimeError(f"auth failed: {resp}")
    return resp


# ---- chat-specific helpers ----

def chat_nick_frame(nick: str) -> bytes:
    raw = nick.encode()
    return frame(struct.pack("!I", len(raw)) + raw)


def chat_send_nick(sock, nick: str):
    raw = nick.encode()
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def chat_send_jwt(sock, jwt: bytes):
    """send a JWT as the handshake token to the chat server."""
    sock.sendall(struct.pack("!I", len(jwt)) + jwt)


def chat_send_msg(sock, text: str):
    raw = text.encode()
    sock.sendall(frame(raw))


def chat_send_cmd(sock, cmd: str):
    chat_send_msg(sock, cmd)
