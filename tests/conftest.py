"""
conftest.py - pytest fixtures for auth and chat server instances.

each fixture spins up an isolated server on a free port and tears it
down after the test session. tests that need a running server just
take the fixture as an argument.

for testing a remote server (e.g. Windows VM), pass --auth-host/--auth-port
or --chat-host/--chat-port. the fixture skips local launch and connects
to the remote instead.
"""

import pytest
from lib.harness import AuthServer, ChatServer, RemoteServer, WineChatServer
from lib import protocol


def pytest_addoption(parser):
    parser.addoption("--auth-host", default=None, help="remote auth server host")
    parser.addoption("--auth-port", default=None, type=int, help="remote auth server port")
    parser.addoption("--chat-host", default=None, help="remote chat server host")
    parser.addoption("--chat-port", default=None, type=int, help="remote chat server port")


@pytest.fixture(scope="session")
def auth_server(request):
    host = request.config.getoption("--auth-host")
    port = request.config.getoption("--auth-port")
    if host and port:
        srv = RemoteServer(host, port)
        yield srv
        return
    srv = AuthServer()
    try:
        srv.start(user="testuser", password="testpass")
    except (FileNotFoundError, RuntimeError) as e:
        pytest.skip(f"auth server not available: {e}")
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def chat_server(request, auth_server):
    host = request.config.getoption("--chat-host")
    port = request.config.getoption("--chat-port")
    if host and port:
        srv = RemoteServer(host, port)
        yield srv
        return
    srv = ChatServer()
    try:
        srv.start()
    except (FileNotFoundError, RuntimeError) as e:
        pytest.skip(f"chat server not available: {e}")
    yield srv
    srv.stop()


@pytest.fixture
def chat_jwt(auth_server):
    """get a fresh JWT for chat tests."""
    return protocol.get_jwt(auth_server.host, auth_server.port)


@pytest.fixture(scope="session")
def wine_chat_server(request, auth_server):
    host = request.config.getoption("--chat-host")
    port = request.config.getoption("--chat-port")
    if host and port:
        srv = RemoteServer(host, port)
        yield srv
        return
    srv = WineChatServer()
    pk_path = getattr(auth_server, "pk_path", None)
    try:
        srv.start(pk_path=pk_path)
    except (FileNotFoundError, RuntimeError) as e:
        pytest.skip(f"wine chat server not available: {e}")
    yield srv
    srv.stop()
