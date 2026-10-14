#ifndef B64URL_H
#define B64URL_H
#include <stddef.h>
size_t b64url_encode(const unsigned char *in, size_t n, char *out);
#endif
