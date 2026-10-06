/* token.h - Ed25519-signed JWT issuance (EdDSA / libsodium). */
#ifndef TOKEN_H
#define TOKEN_H

/* Load the IdP signing key from `sk_path` (32+32 byte libsodium secret key).
 * Returns 0 on success. Call once at startup. */
int token_init(const char *sk_path);

/* Mint a JWT for `user` and send it back framed. Lives in its own stack
 * frame, below handle_login's -- never in the overflow path. */
int issue_token(int fd, const char *user);

#endif
