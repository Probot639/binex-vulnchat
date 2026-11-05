import struct
import time

import pytest

from lib.protocol import (
    OP_LOGIN, OP_DEBUG,
    frame, recv_frame, login_payload, debug_payload,
    parse_jwt, jwt_signing_input,
)


def _login(auth_server, user=b"testuser", password=b"testpass"):
    return auth_server.send_recv(login_payload(user, password))


def _verify_ed25519(pk_bytes, signature, message):
    """try cryptography first, fall back to nacl."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
        pk.verify(signature, message)
        return True
    except ImportError:
        pass
    from nacl.signing import VerifyKey
    vk = VerifyKey(pk_bytes)
    vk.verify(message, signature)
    return True


def test_debug_leak_8_bytes(auth_server):
    resp = auth_server.send_recv(debug_payload())
    assert resp is not None
    assert len(resp) == 8
    addr = struct.unpack("<Q", resp)[0]
    assert addr != 0


def test_fork_aslr_reuse(auth_server):
    # fork() inherits the parent's address space, so two connections
    # to a forking server get the same leaked stack address
    a = auth_server.send_recv(debug_payload())
    b = auth_server.send_recv(debug_payload())
    assert a == b


def test_login_returns_jwt(auth_server):
    resp = _login(auth_server)
    assert resp is not None
    tok = resp.decode()
    assert not tok.startswith("ERR")
    assert tok.count(".") == 2


def test_jwt_header_correct(auth_server):
    resp = _login(auth_server)
    hdr, _, _ = parse_jwt(resp)
    assert hdr is not None
    assert hdr["alg"] == "EdDSA"
    assert hdr["typ"] == "JWT"


def test_jwt_claims_correct(auth_server):
    resp = _login(auth_server)
    _, claims, _ = parse_jwt(resp)
    assert claims["sub"] == "testuser"
    assert claims["iss"] == "binex-idp"
    assert claims["exp"] == claims["iat"] + 300
    assert claims["exp"] > time.time()


def test_jwt_signature_verifies(auth_server):
    resp = _login(auth_server)
    _, _, sig = parse_jwt(resp)
    signing_input = jwt_signing_input(resp)
    assert _verify_ed25519(auth_server.pk, sig, signing_input)


def test_tampered_jwt_fails_verification(auth_server):
    resp = _login(auth_server)
    _, _, sig = parse_jwt(resp)
    signing_input = jwt_signing_input(resp)
    tampered = b"x" + signing_input[1:]
    with pytest.raises(Exception):
        _verify_ed25519(auth_server.pk, sig, tampered)


def test_wrong_password_returns_err(auth_server):
    resp = _login(auth_server, password=b"wrongpass")
    assert resp is not None
    assert resp.decode().startswith("ERR auth")


def test_unknown_user_returns_err(auth_server):
    resp = _login(auth_server, user=b"nobody", password=b"whatever")
    assert resp is not None
    assert resp.decode().startswith("ERR auth")


def test_unknown_opcode_returns_err(auth_server):
    resp = auth_server.send_recv(bytes([0x55]))
    assert resp is not None
    assert resp.decode().startswith("ERR op")


def test_multiple_logins_same_connection(auth_server):
    sock = auth_server.conn()
    try:
        payload = login_payload(b"testuser", b"testpass")

        sock.sendall(frame(payload))
        first = recv_frame(sock)
        assert first is not None
        tok1 = first.decode()
        assert not tok1.startswith("ERR")
        assert tok1.count(".") == 2

        sock.sendall(frame(payload))
        second = recv_frame(sock)
        assert second is not None
        tok2 = second.decode()
        assert not tok2.startswith("ERR")
        assert tok2.count(".") == 2
    finally:
        sock.close()
