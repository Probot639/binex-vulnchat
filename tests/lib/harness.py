"""
harness.py - launch and teardown services for testing.

spins up isolated instances with throwaway databases on free ports.
each service gets its own temp directory so tests don't collide.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import time

from . import protocol


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_for_port(host, port, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


class RemoteServer:
    """thin wrapper for testing against a server someone else is running.
    no start/stop, just connect. use --chat-host/--chat-port or
    --auth-host/--auth-port from the command line."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.pk = None

    def start(self, **kwargs):
        if not wait_for_port(self.host, self.port, timeout=5.0):
            raise RuntimeError(f"remote server not reachable at {self.host}:{self.port}")
        return self

    def stop(self):
        pass

    def conn(self, timeout=3.0):
        return protocol.connect(self.host, self.port, timeout)

    def send_recv(self, payload, timeout=3.0):
        return protocol.send_recv(self.host, self.port, payload, timeout)


class AuthServer:
    """managed auth server instance for testing."""

    def __init__(self, base_dir=None):
        self.base = base_dir or self._find_auth_dir()
        self.tmpdir = None
        self.proc = None
        self.port = 0
        self.host = "127.0.0.1"
        self.pk = None

    @staticmethod
    def _find_auth_dir():
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.normpath(os.path.join(here, "..", "..", "services", "auth"))

    def start(self, user="testuser", password="testpass"):
        authd = os.path.join(self.base, "build", "authd")
        keygen = os.path.join(self.base, "build", "keygen")
        sk = os.path.join(self.base, "keys", "idp_ed25519.sk")
        pk_path = os.path.join(self.base, "keys", "idp_ed25519.pk")

        for p in (authd, keygen, sk, pk_path):
            if not os.path.exists(p):
                raise FileNotFoundError(f"missing {p}, run `make setup` in services/auth")

        self.pk = open(pk_path, "rb").read()
        self.tmpdir = tempfile.mkdtemp(prefix="authtest_")
        dbpath = os.path.join(self.tmpdir, "auth_test.db")

        rc = subprocess.run([keygen, "adduser", user, password, dbpath],
                            capture_output=True, text=True)
        if rc.returncode != 0:
            raise RuntimeError(f"keygen adduser failed: {rc.stderr}")

        self.port = free_port()
        self.proc = subprocess.Popen(
            [authd, "-p", str(self.port), "-k", sk, "-d", dbpath],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

        if not wait_for_port(self.host, self.port):
            err = self.proc.stderr.read() if self.proc.stderr else ""
            self.stop()
            raise RuntimeError(f"auth server did not start on :{self.port}\n{err}")

        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
            self.tmpdir = None

    def conn(self, timeout=3.0):
        return protocol.connect(self.host, self.port, timeout)

    def send_recv(self, payload, timeout=3.0):
        return protocol.send_recv(self.host, self.port, payload, timeout)


class ChatServer:
    """managed chat server instance for testing."""

    def __init__(self, base_dir=None):
        self.base = base_dir or self._find_chat_dir()
        self.proc = None
        self.port = 0
        self.host = "127.0.0.1"
        self.pk_path = None

    @staticmethod
    def _find_chat_dir():
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.normpath(os.path.join(here, "..", "..", "services", "chat-linux"))

    def start(self, pk_path=None):
        chatd = os.path.join(self.base, "build", "chatd")
        if not os.path.exists(chatd):
            raise FileNotFoundError(f"missing {chatd}, run `make` in services/chat-linux")

        if pk_path is None:
            here = os.path.dirname(os.path.abspath(__file__))
            pk_path = os.path.normpath(os.path.join(
                here, "..", "..", "services", "auth", "keys", "idp_ed25519.pk"))
        if not os.path.exists(pk_path):
            raise FileNotFoundError(f"missing {pk_path}, run `make setup` in services/auth")
        self.pk_path = pk_path

        self.port = free_port()
        self.proc = subprocess.Popen(
            [chatd, "-p", str(self.port), "-k", pk_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

        if not wait_for_port(self.host, self.port):
            err = self.proc.stderr.read() if self.proc.stderr else ""
            self.stop()
            raise RuntimeError(f"chat server did not start on :{self.port}\n{err}")

        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(2)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def conn(self, timeout=3.0):
        return protocol.connect(self.host, self.port, timeout)

    def send_recv(self, payload, timeout=3.0):
        return protocol.send_recv(self.host, self.port, payload, timeout)


class WineChatServer:
    """chat server running under Wine for cross-platform testing."""

    def __init__(self, base_dir=None):
        self.base = base_dir or self._find_chat_win_dir()
        self.proc = None
        self.port = 0
        self.host = "127.0.0.1"

    @staticmethod
    def _find_chat_win_dir():
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.normpath(os.path.join(here, "..", "..", "services", "chat-win"))

    def start(self):
        chatd = os.path.join(self.base, "build", "chatd.exe")
        if not os.path.exists(chatd):
            raise FileNotFoundError(f"missing {chatd}, build the windows chat server first")

        wine = shutil.which("wine")
        if not wine:
            raise RuntimeError("wine not installed")

        self.port = free_port()
        env = os.environ.copy()
        env["WINEDEBUG"] = "-all"
        self.proc = subprocess.Popen(
            [wine, chatd, str(self.port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env)

        if not wait_for_port(self.host, self.port, timeout=10.0):
            self.stop()
            raise RuntimeError(f"wine chat server did not start on :{self.port}")

        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def conn(self, timeout=3.0):
        return protocol.connect(self.host, self.port, timeout)

    def send_recv(self, payload, timeout=3.0):
        return protocol.send_recv(self.host, self.port, payload, timeout)
