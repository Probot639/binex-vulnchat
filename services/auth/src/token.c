/* token.c -- EdDSA (Ed25519) JWT mint. All crypto/encoding here, in its own
 * stack frame below handle_login's -- never in the overflow path.
 */
#include "token.h"
#include "net.h"
#include "db.h"
#include "b64url.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static unsigned char g_sk[crypto_sign_SECRETKEYBYTES];   /* 64 */
static int g_ready = 0;

// pull the private key from the file and mark g_ready as true as
// the server will be ready for signing tokens once the private key
// is ready
int token_init(const char *sk_path)
{
    // open the private key
    FILE *f = fopen(sk_path, "rb");
    if (!f) {
        perror("token_init: open sk");
        return -1;
    }

    // reads the private key and stores it in the global static g_sk, then closes the f handle
    size_t rd = fread(g_sk, 1, sizeof g_sk, f);
    fclose(f);

    // if the size of rd (return value of fread) is not the length of g_sk, it didn't work
    // successfully
    if (rd != sizeof g_sk) {
        fprintf(stderr, "token_init: bad sk size\n");
        return -1;
    }

    // private key is ready for signing tokens
    g_ready = 1;
    return 0;
}


// mint a jwt
static int mint_jwt(const char *user, char *out, size_t cap, long *iat_o, long *exp_o)
{

    // JSON string for the JWT
    const char *hdr = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}";

    // initialize buffers 
    char hdr_b64[64], pl_json[192], pl_b64[256], signing_input[320];
    unsigned char sig[crypto_sign_BYTES];
    char sig_b64[128];

    // get the time the token with issued at and get the expiration
    long iat = (long)time(NULL), exp = iat + 300;

    // encode the header into hdr_b64
    b64url_encode((const unsigned char *)hdr, strlen(hdr), hdr_b64);

    // write the payload JSON
    int n = snprintf(pl_json, sizeof pl_json,
        "{\"sub\":\"%s\",\"iss\":\"binex-idp\",\"iat\":%ld,\"exp\":%ld}", user, iat, exp);
    if (n < 0 || (size_t)n >= sizeof pl_json) return -1;

    // encode payload into pl_b64
    b64url_encode((const unsigned char *)pl_json, (size_t)n, pl_b64);

    // join it all into a single header+payload signing_input before signing it
    int m = snprintf(signing_input, sizeof signing_input, "%s.%s", hdr_b64, pl_b64);
    if (m < 0 || (size_t)m >= sizeof signing_input) return -1;

    // sign the token with the private key (64-byte ed25519 signature in sig) and encode it
    crypto_sign_detached(sig, NULL, (const unsigned char *)signing_input, (size_t)m, g_sk);
    b64url_encode(sig, sizeof sig, sig_b64);

    // concat it all into header+payload+signature in the out buffer
    int w = snprintf(out, cap, "%s.%s", signing_input, sig_b64);
    if (!(w > 0 && (size_t)w < cap)) return -1;

    // save the issued and expiration times
    *iat_o = iat; *exp_o = exp;
    return 0;
}

// issue a token to the client
int issue_token(int fd, const char *user)
{
    char jwt[512];
    long iat, exp;

    // make sure the private key is loaded
    if (!g_ready) { send_frame(fd, "ERR nokey", 9); return 0; }
    
    // mint the token
    if (mint_jwt(user, jwt, sizeof jwt, &iat, &exp) != 0) {
        send_frame(fd, "ERR mint", 8); return 0;
    }
    
    // log whenever a token is issued, then send the frame with the jwt
    db_log_issue(user, iat, exp);
    return send_frame(fd, jwt, (uint32_t)strlen(jwt));
}
