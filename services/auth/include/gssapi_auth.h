#ifndef GSSAPI_AUTH_H
#define GSSAPI_AUTH_H

#include <stddef.h>

/*
 * Result of validating one SPNEGO token. On success, principal holds the
 * client's Kerberos principal name (e.g. "alice@EXAMPLE.COM"). If the
 * mechanism requires a follow-up leg (rare for a single-roundtrip web
 * negotiate, but GSSAPI allows it), out_token/out_token_len hold a token
 * that must be base64-encoded and sent back in another 401 challenge.
 */
typedef struct {
    int authenticated;          /* 1 if a full security context was established */
    char principal[512];        /* valid when authenticated == 1 */
    unsigned char *out_token;   /* optional continuation token, caller must free */
    size_t out_token_len;
} gssapi_auth_result_t;

/*
 * Call once at startup. keytab_path is the IdP's service keytab
 * (HTTP/idp.yourdomain.com@REALM), generated separately via kadmin/ktadd.
 * Sets KRB5_KTNAME so the GSSAPI layer picks it up. Returns 0 on success.
 */
int gssapi_auth_init(const char *keytab_path);

/*
 * Validates one raw SPNEGO token (already base64-decoded from the
 * "Authorization: Negotiate <token>" header). Fills in result. Returns 0
 * on success (even if authenticated == 0, meaning "needs another leg" --
 * check result.authenticated), -1 on a hard failure.
 */
int gssapi_auth_validate(const unsigned char *token, size_t token_len,
                          gssapi_auth_result_t *result);

/* Frees result->out_token if set. */
void gssapi_auth_result_free(gssapi_auth_result_t *result);

#endif /* GSSAPI_AUTH_H */