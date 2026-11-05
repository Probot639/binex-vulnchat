"""
test_chat_win.py - functional tests for Darwin's Windows chat server.

same wire protocol as chat-linux, so most tests are shared logic.
this file covers windows-specific concerns: the binary's mitigation
profile (PE headers instead of ELF), and any behavioral differences
from the windows implementation.

run with wine (auto if chatd.exe exists):
    pytest test_chat_win.py -v

run against a remote windows server:
    pytest test_chat_win.py --chat-host=<win-vm-ip> --chat-port=4002
"""

import os
import struct
import subprocess
import socket
import time

import pytest

from lib.protocol import (
    frame, recv_frame, chat_send_nick, chat_send_msg, chat_send_cmd,
)

CHAT_USER_MAX = 64


def _conn_alive(sock, timeout=1.0):
    sock.settimeout(timeout)
    try:
        data = sock.recv(1)
        return len(data) > 0
    except socket.timeout:
        return True
    except OSError:
        return False


def _expect_close(sock, timeout=2.0):
    sock.settimeout(timeout)
    try:
        data = sock.recv(1)
        return data == b""
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


# -- functional parity with chat-linux --

def test_win_connect_send_nick(wine_chat_server):
    s = wine_chat_server.conn()
    try:
        chat_send_nick(s, "alice")
        assert _conn_alive(s)
    finally:
        s.close()


def test_win_empty_nick_rejected(wine_chat_server):
    s = wine_chat_server.conn()
    try:
        s.sendall(struct.pack("!I", 0))
        assert _expect_close(s)
    finally:
        s.close()


def test_win_nick_too_long_rejected(wine_chat_server):
    s = wine_chat_server.conn()
    try:
        chat_send_nick(s, "A" * CHAT_USER_MAX)
        assert _expect_close(s)
    finally:
        s.close()


def test_win_msg_too_long_rejected(wine_chat_server):
    s = wine_chat_server.conn()
    try:
        chat_send_nick(s, "bob")
        payload = b"X" * 4096
        s.sendall(struct.pack("!I", len(payload)) + payload)
        assert _expect_close(s)
    finally:
        s.close()


def test_win_cmd_routing(wine_chat_server):
    s = wine_chat_server.conn()
    try:
        chat_send_nick(s, "carol")
        chat_send_cmd(s, "/help")
        resp = recv_frame(s, timeout=2.0)
        assert resp is not None
    finally:
        s.close()


def test_win_sequential_connections(wine_chat_server):
    for i in range(5):
        s = wine_chat_server.conn()
        try:
            chat_send_nick(s, f"user{i}")
            assert _conn_alive(s, timeout=0.5)
        finally:
            s.close()


# -- windows-specific: PE mitigation checks --
# uses mingw objdump so these work on linux too (no pefile needed)

CHATD_WIN = os.path.join(os.path.dirname(__file__), "..", "services", "chat-win", "build", "chatd.exe")


def _pe_dll_characteristics():
    """parse DllCharacteristics from PE headers via mingw objdump."""
    r = subprocess.run(
        ["x86_64-w64-mingw32-objdump", "-p", CHATD_WIN],
        capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("x86_64-w64-mingw32-objdump failed")
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("DllCharacteristics"):
            # line looks like: DllCharacteristics	00000100
            return int(line.split()[-1], 16)
    pytest.fail("DllCharacteristics not found in PE headers")


@pytest.mark.skipif(not os.path.exists(CHATD_WIN), reason="windows binary not found")
class TestWinMitigations:

    def test_win_no_aslr(self):
        # DYNAMIC_BASE cleared = no ASLR, fixed addresses for the exploit
        chars = _pe_dll_characteristics()
        assert not (chars & 0x0040), "ASLR is on (DYNAMIC_BASE set)"

    def test_win_dep_enabled(self):
        # NX_COMPAT should be set (DEP on, we ROP around it)
        chars = _pe_dll_characteristics()
        assert chars & 0x0100, "DEP/NX not enabled (NX_COMPAT cleared)"

    def test_win_no_cfg(self):
        # GUARD_CF off so control flow isn't checked
        chars = _pe_dll_characteristics()
        assert not (chars & 0x4000), "CFG is on (GUARD_CF set)"
