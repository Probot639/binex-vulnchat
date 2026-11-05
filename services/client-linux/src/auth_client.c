/* auth_client.c - implementation for windows + linux
 * Builds as a Linux .so and a Windows .dll from the same source. */
#define AUTH_CLIENT_BUILD
#include "auth_client.h"

#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  if defined(_MSC_VER)
#    pragma comment(lib, "ws2_32.lib")   /* MSVC auto-link; MinGW uses -lws2_32 */
#  endif
   typedef SOCKET sock_t;
#  define SOCK_BAD   INVALID_SOCKET
#  define closesock  closesocket
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
   typedef int sock_t;
#  define SOCK_BAD   (-1)
#  define closesock  close
#endif

#define OP_LOGIN 0x01
#define OP_DEBUG 0x7F
#define FRAME_MAX 8192

/* ---- platform init/teardown (no-op on POSIX) ---- */
static int net_startup(void) {
#if defined(_WIN32)
    WSADATA w; return WSAStartup(MAKEWORD(2,2), &w) == 0 ? 0 : -1;
#else
    return 0;
#endif
}
static void net_cleanup(void) {
#if defined(_WIN32)
    WSACleanup();
#endif
}

static int send_all(sock_t s, const unsigned char *p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = (int)send(s, (const char *)p + off, (int)(n - off), 0);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}
static int recv_all(sock_t s, unsigned char *p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = (int)recv(s, (char *)p + off, (int)(n - off), 0);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

/* connect; returns SOCK_BAD on failure */
static sock_t dial(const char *host, uint16_t port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) {
        struct hostent *he = gethostbyname(host);        /* simple name fallback */
        if (!he) return SOCK_BAD;
        memcpy(&a.sin_addr, he->h_addr_list[0], sizeof a.sin_addr);
    }
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == SOCK_BAD) return SOCK_BAD;
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) { closesock(s); return SOCK_BAD; }
    return s;
}

/* send one framed payload, read one framed reply into buf (<=cap) */
static auth_result_t txn(const char *host, uint16_t port,
                         const unsigned char *payload, uint32_t plen,
                         unsigned char *reply, uint32_t cap, uint32_t *rlen) {
    if (net_startup() != 0) return AUTH_ERR_CONNECT;
    sock_t s = dial(host, port);
    if (s == SOCK_BAD) { net_cleanup(); return AUTH_ERR_CONNECT; }

    auth_result_t rc = AUTH_OK;
    uint32_t nlen = htonl(plen);
    if (send_all(s, (unsigned char *)&nlen, 4) != 0 ||
        send_all(s, payload, plen) != 0) { rc = AUTH_ERR_IO; goto done; }

    unsigned char hdr[4];
    if (recv_all(s, hdr, 4) != 0) { rc = AUTH_ERR_IO; goto done; }
    uint32_t n;
    memcpy(&n, hdr, 4);
    n = ntohl(n);
    if (n == 0 || n > cap) { rc = AUTH_ERR_PROTO; goto done; }
    if (recv_all(s, reply, n) != 0) { rc = AUTH_ERR_IO; goto done; }
    *rlen = n;
done:
    closesock(s); net_cleanup();
    return rc;
}

AUTH_API auth_result_t auth_login(const char *host, uint16_t port,
                                  const char *user, const char *secret,
                                  char *jwt_out, size_t jwt_cap, size_t *jwt_len) {
    if (!host || !user || !secret || !jwt_out || jwt_cap == 0) return AUTH_ERR_ARG;
    size_t ul = strlen(user), sl = strlen(secret);
    if (ul > 0xFFFF || sl > 0xFFFF) return AUTH_ERR_ARG;
    if (1 + 2 + ul + 2 + sl > FRAME_MAX) return AUTH_ERR_ARG;

    unsigned char p[FRAME_MAX]; uint32_t o = 0;
    p[o++] = OP_LOGIN;
    p[o++] = (unsigned char)(ul >> 8); p[o++] = (unsigned char)ul;
    memcpy(p + o, user, ul); o += (uint32_t)ul;
    p[o++] = (unsigned char)(sl >> 8); p[o++] = (unsigned char)sl;
    memcpy(p + o, secret, sl); o += (uint32_t)sl;

    unsigned char reply[FRAME_MAX]; uint32_t rn = 0;
    auth_result_t rc = txn(host, port, p, o, reply, sizeof reply, &rn);
    if (rc != AUTH_OK) return rc;

    if (rn >= 3 && memcmp(reply, "ERR", 3) == 0) return AUTH_ERR_DENIED;
    if ((size_t)rn + 1 > jwt_cap) return AUTH_ERR_ARG;     /* caller buffer too small */
    memcpy(jwt_out, reply, rn); jwt_out[rn] = '\0';
    if (jwt_len) *jwt_len = rn;
    return AUTH_OK;
}

AUTH_API auth_result_t auth_debug(const char *host, uint16_t port,
                                  unsigned char addr_out[8]) {
    if (!host || !addr_out) return AUTH_ERR_ARG;
    unsigned char op = OP_DEBUG, reply[FRAME_MAX]; uint32_t rn = 0;
    auth_result_t rc = txn(host, port, &op, 1, reply, sizeof reply, &rn);
    if (rc != AUTH_OK) return rc;
    if (rn != 8) return AUTH_ERR_PROTO;
    memcpy(addr_out, reply, 8);
    return AUTH_OK;
}

AUTH_API const char *auth_strerror(auth_result_t r) {
    switch (r) {
    case AUTH_OK:          return "ok";
    case AUTH_ERR_CONNECT: return "connect failed";
    case AUTH_ERR_IO:      return "i/o error";
    case AUTH_ERR_PROTO:   return "protocol error";
    case AUTH_ERR_DENIED:  return "authentication denied";
    case AUTH_ERR_ARG:     return "bad argument";
    default:               return "unknown";
    }
}