#!/usr/bin/env python3

# this is just a generated script to verify that my stuff works, not meant to be useful for anything else
# seems like it works somewhat well, and tests pass

"""
test_auth.py - integration test harness for the binex-vulnchat auth server.

Spins up an ISOLATED instance of ./build/authd (own port, throwaway DB seeded
with a test user) so it never touches your running server or your real auth.db,
exercises every protocol path, and verifies issued JWTs under the Ed25519
public key. Prints PASS/FAIL per check and exits non-zero if any failed.

Usage:
    python3 test_auth.py                 # from the services/auth directory
    python3 test_auth.py --authd build/authd --keydir keys --no-overflow
"""
import argparse, os, socket, struct, subprocess, sys, tempfile, time, shutil, base64, json, sqlite3

# ---------------------------------------------------------------- protocol
OP_LOGIN, OP_DEBUG = 0x01, 0x7F

def frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload

def login_payload(user: bytes, secret: bytes) -> bytes:
    return (bytes([OP_LOGIN]) + struct.pack("!H", len(user)) + user
            + struct.pack("!H", len(secret)) + secret)

def recv_frame(s: socket.socket, timeout=2.0):
    s.settimeout(timeout)
    hdr = b""
    while len(hdr) < 4:
        b = s.recv(4 - len(hdr))
        if not b: return None
        hdr += b
    n = struct.unpack("!I", hdr)[0]
    body = b""
    while len(body) < n:
        b = s.recv(n - len(body))
        if not b: return None
        body += b
    return body

def conn(host, port, timeout=2.0):
    s = socket.create_connection((host, port), timeout=timeout)
    return s

def send_recv(host, port, payload, timeout=2.0):
    s = conn(host, port, timeout)
    try:
        s.sendall(frame(payload))
        return recv_frame(s, timeout)
    finally:
        s.close()

# ---------------------------------------------------------------- ed25519 verify (3 fallbacks)
def _verify_cryptography(pk, msg, sig):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg); return True
    except InvalidSignature:
        return False

def _verify_nacl(pk, msg, sig):
    import nacl.signing, nacl.exceptions
    try:
        nacl.signing.VerifyKey(pk).verify(msg, sig); return True
    except nacl.exceptions.BadSignatureError:
        return False

def _verify_pure(pk, msg, sig):
    # RFC 8032 reference Ed25519 verify (slow but dependency-free).
    import hashlib
    sys.setrecursionlimit(5000)
    b, q = 256, 2**255 - 19
    def H(m): return hashlib.sha512(m).digest()
    def expmod(bb, e, m):
        r = 1; bb %= m
        while e:
            if e & 1: r = (r*bb) % m
            bb = (bb*bb) % m; e >>= 1
        return r
    def inv(x): return expmod(x, q-2, q)
    d = (-121665 * inv(121666)) % q
    I = expmod(2, (q-1)//4, q)
    def xrecover(y):
        xx = (y*y-1) * inv(d*y*y+1)
        x = expmod(xx, (q+3)//8, q)
        if (x*x - xx) % q != 0: x = (x*I) % q
        if x % 2 != 0: x = q-x
        return x
    By = (4 * inv(5)) % q; Bx = xrecover(By); B = [Bx % q, By % q]
    def edwards(P, Q):
        x1,y1 = P; x2,y2 = Q
        x3 = (x1*y2 + x2*y1) * inv(1 + d*x1*x2*y1*y2)
        y3 = (y1*y2 + x1*x2) * inv(1 - d*x1*x2*y1*y2)
        return [x3 % q, y3 % q]
    def scalarmult(P, e):
        Q = [0, 1]
        while e:
            if e & 1: Q = edwards(Q, P)
            P = edwards(P, P); e >>= 1
        return Q
    def bit(h, i): return (h[i//8] >> (i % 8)) & 1
    def decodeint(s): return sum(2**i * bit(s, i) for i in range(0, b))
    def decodepoint(s):
        y = sum(2**i * bit(s, i) for i in range(0, b-1))
        x = xrecover(y)
        if x & 1 != bit(s, b-1): x = q-x
        return [x, y]
    def encodepoint(P):
        x, y = P
        bits = [(y >> i) & 1 for i in range(b-1)] + [x & 1]
        return bytes(sum(bits[i*8+j] << j for j in range(8)) for i in range(b//8))
    if len(sig) != 64 or len(pk) != 32: return False
    try:
        R = decodepoint(sig[:32]); A = decodepoint(pk); S = decodeint(sig[32:])
        h = int.from_bytes(H(encodepoint(R) + pk + msg), "little")  # full 512-bit hash (not 256)
        return scalarmult(B, S) == edwards(R, scalarmult(A, h))
    except Exception:
        return False

def ed25519_verify(pk, msg, sig):
    for fn, name in ((_verify_cryptography, "cryptography"),
                     (_verify_nacl, "pynacl"),
                     (_verify_pure, "pure-python")):
        try:
            return fn(pk, msg, sig), name
        except ImportError:
            continue
    return None, None

def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# ---------------------------------------------------------------- harness
class Runner:
    def __init__(self): self.passed = 0; self.failed = 0
    def check(self, name, ok, detail=""):
        tag = "PASS" if ok else "FAIL"
        if ok: self.passed += 1
        else:  self.failed += 1
        print(f"  [{tag}] {name}" + (f"  -- {detail}" if detail else ""))
        return ok
    def info(self, msg): print(f"  [ .. ] {msg}")

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--authd", default="build/authd")
    ap.add_argument("--keygen", default="build/keygen")
    ap.add_argument("--keydir", default="keys")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="0 = auto-pick a free port")
    ap.add_argument("--no-overflow", action="store_true", help="skip the crash/isolation test")
    args = ap.parse_args()

    for p in (args.authd, args.keygen, os.path.join(args.keydir, "idp_ed25519.sk"),
              os.path.join(args.keydir, "idp_ed25519.pk")):
        if not os.path.exists(p):
            print(f"missing: {p}\nRun `make setup` first, and run this from the services/auth dir.")
            return 2

    pk = open(os.path.join(args.keydir, "idp_ed25519.pk"), "rb").read()
    host = args.host
    port = args.port or free_port()
    user, secret = b"testuser", b"s3cr3t-pw"

    tmp = tempfile.mkdtemp(prefix="authtest_")
    dbp = os.path.join(tmp, "auth_test.db")
    srv = None
    r = Runner()
    try:
        # seed an isolated test DB with a known user
        rc = subprocess.run([args.keygen, "adduser", user.decode(), secret.decode(), dbp],
                            capture_output=True, text=True)
        if rc.returncode != 0:
            print("keygen adduser failed:", rc.stderr); return 2

        # launch an isolated server instance
        srv = subprocess.Popen(
            [args.authd, "-p", str(port), "-k", os.path.join(args.keydir, "idp_ed25519.sk"), "-d", dbp],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        # wait for it to listen
        up = False
        for _ in range(50):
            try:
                conn(host, port, 0.3).close(); up = True; break
            except OSError:
                if srv.poll() is not None: break
                time.sleep(0.1)
        if not up:
            err = srv.stderr.read() if srv.stderr else ""
            print(f"server did not come up on {host}:{port}\n{err}"); return 2

        print(f"\n== auth server integration test (isolated :{port}, db={os.path.basename(dbp)}) ==\n")

        # 1. DEBUG leak
        leak1 = send_recv(host, port, bytes([OP_DEBUG]))
        ok = leak1 is not None and len(leak1) == 8 and int.from_bytes(leak1, "little") != 0
        addr1 = int.from_bytes(leak1, "little") if leak1 and len(leak1) == 8 else 0
        r.check("DEBUG leak returns an 8-byte stack address", ok,
                f"0x{addr1:012x}" if ok else f"got {leak1!r}")

        # 2. fork-ASLR reuse (the premise of the leak-then-exploit strategy)
        leak2 = send_recv(host, port, bytes([OP_DEBUG]))
        addr2 = int.from_bytes(leak2, "little") if leak2 and len(leak2) == 8 else 0
        r.check("two connections leak the SAME address (fork doesn't re-randomize)",
                addr1 and addr1 == addr2, f"0x{addr1:012x} == 0x{addr2:012x}")

        # 3. successful login -> 3-part JWT
        tok = send_recv(host, port, login_payload(user, secret))
        is_jwt = tok is not None and tok.count(b".") == 2 and not tok.startswith(b"ERR")
        r.check("LOGIN with correct credentials returns a JWT", is_jwt,
                (tok[:28].decode(errors="replace") + "...") if is_jwt else f"got {tok!r}")

        hdr = pl = sig = None
        if is_jwt:
            h_b64, p_b64, s_b64 = tok.decode().split(".")
            hdr = json.loads(b64url_decode(h_b64))
            pl  = json.loads(b64url_decode(p_b64))
            sig = b64url_decode(s_b64)
            # 4. header
            r.check("JWT header is {alg:EdDSA, typ:JWT}",
                    hdr.get("alg") == "EdDSA" and hdr.get("typ") == "JWT", str(hdr))
            # 5. claims
            good_claims = (pl.get("sub") == user.decode()
                           and pl.get("iss") == "binex-idp"
                           and isinstance(pl.get("exp"), int)
                           and pl.get("exp") - pl.get("iat") == 300
                           and pl.get("exp") > time.time())
            r.check("JWT claims: sub matches, iss set, exp=iat+300, not expired",
                    good_claims, f"sub={pl.get('sub')} ttl={pl.get('exp',0)-pl.get('iat',0)}s")
            # 6. signature verifies under the PUBLIC key (asymmetric proof)
            signing_input = (h_b64 + "." + p_b64).encode()
            valid, backend = ed25519_verify(pk, signing_input, sig)
            r.check(f"JWT signature verifies under the public key [{backend}]", valid is True)
            # 7. tamper detection
            tampered = signing_input + b"x"
            bad, _ = ed25519_verify(pk, tampered, sig)
            r.check("tampered payload fails signature verification", bad is False)

        # 8. wrong password
        bad_pw = send_recv(host, port, login_payload(user, b"wrong"))
        r.check("LOGIN with wrong password -> ERR auth", bad_pw == b"ERR auth", repr(bad_pw))

        # 9. unknown user
        nouser = send_recv(host, port, login_payload(b"ghost", b"whatever"))
        r.check("LOGIN with unknown user -> ERR auth", nouser == b"ERR auth", repr(nouser))

        # 10. unknown opcode
        badop = send_recv(host, port, bytes([0x55]))
        r.check("unknown opcode -> ERR op", badop == b"ERR op", repr(badop))

        # 11. DB side effects: user present, auth_log grew by #successful logins (1)
        time.sleep(0.2)
        db = sqlite3.connect(dbp)
        nusers = db.execute("SELECT COUNT(*) FROM users WHERE name=?", (user.decode(),)).fetchone()[0]
        nlog   = db.execute("SELECT COUNT(*) FROM auth_log WHERE name=?", (user.decode(),)).fetchone()[0]
        db.close()
        r.check("sqlite: test user present in users table", nusers == 1, f"rows={nusers}")
        r.check("sqlite: exactly one auth_log row for the one successful login", nlog == 1, f"rows={nlog}")

        # 12. overflow -> child crashes, parent survives (fork isolation)
        if not args.no_overflow:
            overflowed_jwt = False
            try:
                s = conn(host, port); s.sendall(frame(login_payload(b"A"*600, b"x")))
                resp = recv_frame(s, 1.0); s.close()
                overflowed_jwt = (resp is not None and resp.count(b".") == 2)
            except OSError:
                pass
            r.info("sent 600-byte user id (overflows user[64])")
            # the real assertions: it did NOT yield a valid token, and parent still serves
            still_up = send_recv(host, port, bytes([OP_DEBUG]))
            r.check("overflow did NOT produce a valid JWT", not overflowed_jwt)
            r.check("parent still serves after a child crash (fork isolation)",
                    still_up is not None and len(still_up) == 8)
        else:
            r.info("overflow/isolation test skipped (--no-overflow)")

        print(f"\n== {r.passed} passed, {r.failed} failed ==")
        return 0 if r.failed == 0 else 1
    finally:
        if srv and srv.poll() is None:
            srv.terminate()
            try: srv.wait(2)
            except subprocess.TimeoutExpired: srv.kill()
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())