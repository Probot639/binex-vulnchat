/* net.c -- sockets + the per-connection frame loop (the "wiring").
 *
 * Mirrors the chat server: fixed 4-byte network-order length prefix, then
 * that many payload bytes; parent accepts and forks, each child runs the
 * loop and dispatches on the payload's opcode byte. This is what carries
 * attacker bytes from the socket into handle_login().
 */
#include "net.h"
#include "auth.h"
#include "proto.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

long readn(int fd, void *buf, size_t n)
{
    char *p = (char *)buf;
    size_t left = n;
    while (left > 0) {
        long r = read(fd, p, left);
        if (r <= 0) return -1;
        p += r;
        left -= (size_t)r;
    }
    return (long)n;
}

int send_frame(int fd, const void *body, uint32_t len)
{
    uint32_t nlen = htonl(len);
    if (write(fd, &nlen, sizeof nlen) != (long)sizeof nlen) return -1;
    if (len && write(fd, body, len) != (long)len) return -1;
    return 0;
}

int net_listen(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -1; }
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    return fd;
}

/* One client, inside the forked child. Read frames, dispatch on opcode. */
static void session_serve(int fd)
{
    for (;;) {
        uint32_t len;
        if (readn(fd, &len, sizeof len) < 0) break;
        len = ntohl(len);
        if (len == 0 || len > AUTH_FRAME_MAX) break;

        /* whole payload read into one buffer; a pointer into it is handed
         * to the handler, whose own user[64] is the thing that overflows. */
        uint8_t payload[AUTH_FRAME_MAX];
        if (readn(fd, payload, len) < 0) break;

        switch (payload[0]) {
        case OP_LOGIN: handle_login(fd, payload, len); break;
        case OP_DEBUG: handle_debug(fd);               break;
        default:       send_frame(fd, "ERR op", 6);    break;
        }
    }
}

void net_serve_forever(int srv)
{
    signal(SIGCHLD, SIG_IGN);     /* reap children automatically */
    for (;;) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;

        pid_t pid = fork();
        if (pid == 0) {           /* child: shares parent's ASLR base */
            close(srv);
            session_serve(c);
            close(c);
            _exit(0);
        }
        close(c);                 /* parent keeps accepting */
    }
}
