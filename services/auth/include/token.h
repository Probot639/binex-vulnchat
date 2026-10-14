/* token.h - Ed25519-signed JWT issuance (EdDSA / libsodium). */
#ifndef TOKEN_H
#define TOKEN_H
int token_init(const char *sk_path);     /* load IdP signing key; call once */
int issue_token(int fd, const char *user);/* mint + send; own stack frame   */
#endif
