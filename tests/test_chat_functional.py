import time
import socket
import struct
import pytest

from lib.protocol import (
    frame, recv_frame, chat_send_nick, chat_send_jwt,
    chat_send_msg, chat_send_cmd, get_jwt,
)

MSG_BODY_MAX = 4095


def _conn_alive(sock, timeout=1.0):
    """True if the socket has not been closed by the remote end."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(1)
        return len(data) > 0
    except socket.timeout:
        return True
    except OSError:
        return False


def _expect_close(sock, timeout=2.0):
    """True if the server closes its end within timeout."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(1)
        return data == b""
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


def _jwt(auth_server):
    return get_jwt(auth_server.host, auth_server.port)


def _auth_and_drain(sock, auth_server):
    """send JWT handshake and drain the join announcement."""
    chat_send_jwt(sock, _jwt(auth_server))
    resp = recv_frame(sock, timeout=2.0)
    assert resp is not None and b"joined" in resp


# -- connection and auth handshake --

def test_connect_send_jwt(chat_server, auth_server):
    s = chat_server.conn()
    try:
        chat_send_jwt(s, _jwt(auth_server))
        resp = recv_frame(s, timeout=2.0)
        assert resp is not None and b"joined" in resp
    finally:
        s.close()


def test_empty_token_rejected(chat_server):
    s = chat_server.conn()
    try:
        s.sendall(struct.pack("!I", 0))
        assert _expect_close(s)
    finally:
        s.close()


def test_bad_token_rejected(chat_server):
    s = chat_server.conn()
    try:
        chat_send_jwt(s, b"not.a.jwt")
        resp = recv_frame(s, timeout=2.0)
        assert resp == b"ERR auth"
    finally:
        s.close()


# -- message frame validation --

def _expect_disconnect(sock, timeout=3.0):
    """drain any trailing frames, then confirm the server closes."""
    sock.settimeout(timeout)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                return True
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


def test_msg_too_long_rejected(chat_server, auth_server):
    s = chat_server.conn()
    try:
        _auth_and_drain(s, auth_server)
        payload = b"X" * (MSG_BODY_MAX + 1)
        s.sendall(struct.pack("!I", len(payload)) + payload)
        assert _expect_disconnect(s)
    finally:
        s.close()


def test_zero_length_msg_rejected(chat_server, auth_server):
    s = chat_server.conn()
    try:
        _auth_and_drain(s, auth_server)
        s.sendall(struct.pack("!I", 0))
        assert _expect_disconnect(s)
    finally:
        s.close()


# -- command and message paths --

def test_cmd_routing(chat_server, auth_server):
    s = chat_server.conn()
    try:
        _auth_and_drain(s, auth_server)
        chat_send_cmd(s, "/help")
        resp = recv_frame(s, timeout=2.0)
        assert resp is not None
    finally:
        s.close()


def test_msg_delivery_two_clients(chat_server, auth_server):
    s1 = chat_server.conn()
    s2 = chat_server.conn()
    try:
        _auth_and_drain(s1, auth_server)
        _auth_and_drain(s2, auth_server)
        # s2 also sees s1's join announcement, drain it
        # (may or may not arrive depending on timing)
        time.sleep(0.2)
        chat_send_msg(s1, "hello from testuser")
        # s2 might get leftover join announcements before the message
        deadline = time.monotonic() + 3.0
        found = False
        while time.monotonic() < deadline:
            resp = recv_frame(s2, timeout=1.0)
            if resp is None:
                break
            if b"hello from testuser" in resp:
                found = True
                break
        assert found
    finally:
        s1.close()
        s2.close()


# -- server resilience --

def test_fork_isolation(chat_server):
    bad = chat_server.conn()
    bad.sendall(struct.pack("!I", 9999))
    bad.close()
    time.sleep(0.3)
    s = chat_server.conn()
    try:
        s.sendall(struct.pack("!I", 3) + b"abc")
        time.sleep(0.3)
        s2 = chat_server.conn()
        s2.close()
    finally:
        s.close()


def test_sequential_connections(chat_server, auth_server):
    for i in range(5):
        s = chat_server.conn()
        try:
            chat_send_jwt(s, _jwt(auth_server))
            assert _conn_alive(s, timeout=0.5)
        finally:
            s.close()
