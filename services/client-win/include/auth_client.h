/* auth_client.h - client library for authentication
 *
 * Client responsibilities: connect, LOGIN, receive a JWT
 */
#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

#include <stdint.h>
#include <stddef.h>

// alters behavior based on whether this is a linux or a windows build
#if defined(_WIN32)
#  if defined(AUTH_CLIENT_BUILD)
#    define AUTH_API __declspec(dllexport)
#  else
#    define AUTH_API __declspec(dllimport)
#  endif
#else
#  define AUTH_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// return codes
typedef enum {
    AUTH_OK            =  0,
    AUTH_ERR_CONNECT   = -1,   // socket/connect failed
    AUTH_ERR_IO        = -2,   // send/recv failed or short read
    AUTH_ERR_PROTO     = -3,   // malformed / oversized frame
    AUTH_ERR_DENIED    = -4,   // server replied ERR (bad creds)
    AUTH_ERR_ARG       = -5    // bad argument / buffer too small
} auth_result_t;

/* Authenticate `user`/`secret` to authd at host:port.
 * AUTH_OK response writes the NUL-terminated JWT into `jwt_out` (<= jwt_cap)
 * and sets *jwt_len (excluding the NUL). jwt_cap >= 512 recommended. */
AUTH_API auth_result_t auth_login(const char *host, uint16_t port,
                                  const char *user, const char *secret,
                                  char *jwt_out, size_t jwt_cap, size_t *jwt_len);

/* Send the DEBUG opcode; writes the 8 raw leaked bytes into addr_out[8].
 * This is meant for testing on our end, so remove it before giving it to
 * the other group. */
AUTH_API auth_result_t auth_debug(const char *host, uint16_t port,
                                  unsigned char addr_out[8]);

/* Helper function for making error human readable */
AUTH_API const char *auth_strerror(auth_result_t r);

#ifdef __cplusplus
}
#endif
#endif