#include "b64url.h"

size_t b64url_encode(const unsigned char *in, size_t n, char *out)
{
    static const char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0, i = 0;
    while (i + 3 <= n) {
        unsigned v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = t[(v >> 6)  & 63];
        out[o++] = t[v & 63];
        i += 3;
    }
    size_t rem = n - i;
    if (rem == 1) {
        unsigned v = in[i] << 16;
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
    } else if (rem == 2) {
        unsigned v = (in[i] << 16) | (in[i+1] << 8);
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = t[(v >> 6)  & 63];
    }
    out[o] = '\0';          /* base64url: no '=' padding */
    return o;
}
