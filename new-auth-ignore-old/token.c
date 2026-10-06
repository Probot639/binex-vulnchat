/* token.c -- EdDSA (Ed25519) JWT mint. ALL crypto and encoding lives here,
 * in its own translation unit, in its own stack frame. The jwt[] buffer and
 * libsodium's scratch are pushed BELOW handle_login's frame and popped on
 * return, so they are never between the overflow buffer and its saved RIP.
 *
 * Why Ed25519 via libsodium: asymmetric (only the auth server holds the
 * secret key; the chat servers verify with the 32-byte public key and
 * cannot forge), one portable dependency on both Linux and Windows,
 * crypto_sign_detached returns exactly the 64-byte JWS signature -- no
 * DER<->R||S transcoding, no padding footguns.
 */
#include "token.h"
#include "net.h"
#include "b64url.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static unsigned char g_sk[crypto_sign_SECRETKEYBYTES];   /* 64 */
static int g_ready = 0;

int token_init(const char *sk_path)
{
    FILE *f = fopen(sk_path, "rb");
    if (!f) { perror("token_init: open sk"); return -1; }
    size_t rd = fread(g_sk, 1, sizeof g_sk, f);
    fclose(f);
    if (rd != sizeof g_sk) {
        fprintf(stderr, "token_init: bad secret key size (%zu)\n", rd);
        return -1;
    }
    g_ready = 1;
    return 0;
}

static int mint_jwt(const char *user, char *out, size_t cap)
{
    const char *hdr = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}";
    char          hdr_b64[64];
    char          pl_json[192];
    char          pl_b64[256];
    char          signing_input[320];
    unsigned char sig[crypto_sign_BYTES];     /* 64 */
    char          sig_b64[128];

    b64url_encode((const unsigned char *)hdr, strlen(hdr), hdr_b64);

    int n = snprintf(pl_json, sizeof pl_json,
        "{\"sub\":\"%s\",\"iss\":\"binex-idp\",\"iat\":%ld,\"exp\":%ld}",
        user, (long)time(NULL), (long)time(NULL) + 300);
    if (n < 0 || (size_t)n >= sizeof pl_json) return -1;
    b64url_encode((const unsigned char *)pl_json, (size_t)n, pl_b64);

    int m = snprintf(signing_input, sizeof signing_input, "%s.%s", hdr_b64, pl_b64);
    if (m < 0 || (size_t)m >= sizeof signing_input) return -1;

    /* Ed25519: one-shot, no pre-hash. sig is already in JWS form (64 raw B). */
    crypto_sign_detached(sig, NULL,
                         (const unsigned char *)signing_input, (size_t)m, g_sk);
    b64url_encode(sig, sizeof sig, sig_b64);

    int w = snprintf(out, cap, "%s.%s", signing_input, sig_b64);
    return (w > 0 && (size_t)w < cap) ? 0 : -1;
}

int issue_token(int fd, const char *user)
{
    char jwt[512];                 /* this frame -- not handle_login's */
    if (!g_ready) { send_frame(fd, "ERR nokey", 9); return 0; }
    if (mint_jwt(user, jwt, sizeof jwt) != 0) {
        send_frame(fd, "ERR mint", 8);
        return 0;
    }
    return send_frame(fd, jwt, (uint32_t)strlen(jwt));
}
