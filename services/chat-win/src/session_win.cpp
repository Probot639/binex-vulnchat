/* session_win.cpp - per-client, runs in its own thread
 *
 * join handshake first (ticket from auth), then loop on frames and
 * hand off to command.c or message.c. this owns the chat_msg.
 *
 * only difference from linux: recv() instead of read()
 */
#include "chatd.h"

#include <winsock2.h>
#include <cstdio>
#include <cstring>

static int recvn(SOCKET fd, void *buf, int n)
{
    char *p = (char *)buf;
    int left = n;

    while (left > 0) {
        int r = recv(fd, p, left, 0);
        if (r <= 0)
            return -1;
        p += r;
        left -= r;
    }
    return n;
}

extern "C" void session_serve(int fd)
{
    SOCKET s = (SOCKET)fd;

    /* first frame is the nick for now, no auth yet */
    uint32_t nlen;
    if (recvn(s, &nlen, sizeof(nlen)) < 0){
        return;
    }
    nlen = ntohl(nlen);

    if (nlen == 0 || nlen >= CHAT_USER_MAX){
        return;
    }

    char nick[CHAT_USER_MAX];
    memset(nick, 0, sizeof(nick));
    if (recvn(s, nick, nlen) < 0){
        return;
    }

    fprintf(stderr, "join: %s\n", nick);

    struct chat_room *room = room_join("lobby", fd);

    for (;;) {
        uint32_t len;
        if (recvn(s, &len, sizeof(len)) < 0) {
            break;
        }
        len = ntohl(len);

        if (len == 0 || len > 4095){
            break;
        }

        char buf[4096];

        if (recvn(s, buf, len) < 0){
            break;
        }
        buf[len] = '\0';

        if (buf[0] == '/') {
            struct chat_msg *m = msg_new(nick);
            if (m) {
                cmd_dispatch(m, buf, len);
                if (m->len > 0) {
                    uint32_t nl = htonl(m->len);
                    send(s, (const char *)&nl, 4, 0);
                    send(s, m->body, m->len, 0);
                }
                msg_free(m);
            }
            continue;
        }


        char line[4096];
        int n = snprintf(line, sizeof(line), "%s: %s", nick, buf);

        struct chat_msg *m = msg_new(nick);
        msg_set_body(m, line, n);
        room_broadcast(room, m);
        msg_free(m);
    }
}
