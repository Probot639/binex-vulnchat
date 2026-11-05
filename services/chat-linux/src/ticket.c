/* ticket.c - verify Ed25519-signed JWTs from the auth server.
 *
 * Not in the vuln path. The overflow is in command.c; the UAF is in
 * session.cpp via message.c. This is just the gate that checks the
 * client actually talked to the IdP before chatting.
 */
#include "ticket.h"

#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static unsigned char g_pk[crypto_sign_PUBLICKEYBYTES];   /* 32 */
static int g_ready;

int ticket_init(const char *pk_path)
{
    FILE *f = fopen(pk_path, "rb");
    if (!f) { perror("ticket_init"); return -1; }

    size_t rd = fread(g_pk, 1, sizeof g_pk, f);
    fclose(f);

    if (rd != sizeof g_pk) {
        fprintf(stderr, "ticket_init: bad pk size\n");
        return -1;
    }
    g_ready = 1;
    return 0;
}


static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static int b64url_decode(const char *in, size_t inlen,
                         unsigned char *out, size_t cap, size_t *outlen)
{
    size_t o = 0, i = 0;
    while (i + 4 <= inlen) {
        int a = b64val(in[i]), b = b64val(in[i+1]),
            c = b64val(in[i+2]), d = b64val(in[i+3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        if (o + 3 > cap) return -1;
        out[o++] = (a << 2) | (b >> 4);
        out[o++] = ((b & 0xf) << 4) | (c >> 2);
        out[o++] = ((c & 3) << 6) | d;
        i += 4;
    }
    size_t rem = inlen - i;
    if (rem == 2) {
        int a = b64val(in[i]), b = b64val(in[i+1]);
        if (a < 0 || b < 0 || o + 1 > cap) return -1;
        out[o++] = (a << 2) | (b >> 4);
    } else if (rem == 3) {
        int a = b64val(in[i]), b = b64val(in[i+1]), c = b64val(in[i+2]);
        if (a < 0 || b < 0 || c < 0 || o + 2 > cap) return -1;
        out[o++] = (a << 2) | (b >> 4);
        out[o++] = ((b & 0xf) << 4) | (c >> 2);
    }
    *outlen = o;
    return 0;
}


static int extract_sub(const char *json, size_t len,
                       char *out, uint32_t cap)
{
    (void)len;
    const char *key = "\"sub\":\"";
    const char *p = strstr(json, key);
    if (!p) return -1;
    p += strlen(key);
    const char *end = strchr(p, '"');
    if (!end) return -1;
    size_t slen = (size_t)(end - p);
    if (slen == 0 || slen >= cap) return -1;
    memcpy(out, p, slen);
    out[slen] = '\0';
    return 0;
}


static long extract_exp(const char *json, size_t len)
{
    (void)len;
    const char *key = "\"exp\":";
    const char *p = strstr(json, key);
    if (!p) return -1;
    p += strlen(key);
    return strtol(p, NULL, 10);
}

int ticket_verify(const char *jwt, uint32_t jwt_len,
                  char *sub_out, uint32_t sub_cap)
{
    if (!g_ready) return -1;

    /* find the two dots: header.payload.signature */
    const char *dot1 = memchr(jwt, '.', jwt_len);
    if (!dot1) return -1;
    const char *dot2 = memchr(dot1 + 1, '.', jwt_len - (size_t)(dot1 + 1 - jwt));
    if (!dot2) return -1;

    /* signing input is everything before the second dot */
    size_t si_len = (size_t)(dot2 - jwt);

    /* decode the signature */
    const char *sig_b64 = dot2 + 1;
    size_t sig_b64_len = jwt_len - (size_t)(sig_b64 - jwt);
    unsigned char sig[crypto_sign_BYTES];
    size_t sig_len;
    if (b64url_decode(sig_b64, sig_b64_len, sig, sizeof sig, &sig_len) < 0)
        return -1;
    if (sig_len != crypto_sign_BYTES) return -1;

    /* verify Ed25519 signature */
    if (crypto_sign_verify_detached(sig, (const unsigned char *)jwt,
                                    si_len, g_pk) != 0)
        return -1;

    /* decode the payload (between the two dots) */
    const char *pl_b64 = dot1 + 1;
    size_t pl_b64_len = (size_t)(dot2 - pl_b64);
    unsigned char pl[512];
    size_t pl_len;
    if (b64url_decode(pl_b64, pl_b64_len, pl, sizeof(pl) - 1, &pl_len) < 0)
        return -1;
    pl[pl_len] = '\0';

    /* check expiry */
    long exp = extract_exp((const char *)pl, pl_len);
    if (exp > 0 && (long)time(NULL) > exp)
        return -1;

    /* extract subject */
    return extract_sub((const char *)pl, pl_len, sub_out, sub_cap);
}
