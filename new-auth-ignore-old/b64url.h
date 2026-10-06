/* b64url.h - base64url, no padding (RFC 7515 style, for the JWT). */
#ifndef B64URL_H
#define B64URL_H

#include <stddef.h>

/* Writes a NUL-terminated base64url string of `in` into `out`.
 * `out` must hold at least 4*((n+2)/3)+1 bytes. Returns string length. */
size_t b64url_encode(const unsigned char *in, size_t n, char *out);

#endif
