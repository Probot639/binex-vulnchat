/* session_win.cpp - per-client, runs in its own thread
 *
 * join handshake first (ticket from auth), then loop on frames and
 * hand off to command.c or message.c. this owns the chat_msg.
 *
 * only difference from linux: recv() instead of read(), threads
 * instead of fork, no relay pipe (room_broadcast does direct sends).
 */
#include "chatd.h"
#include "ticket.h"

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

    /* first frame is the JWT from the auth server */
    uint32_t nlen;
    if (recvn(s, &nlen, sizeof(nlen)) < 0)
        return;
    nlen = ntohl(nlen);

    if (nlen == 0 || nlen > 1024)
        return;

    char tok[1025];
    if (recvn(s, tok, nlen) < 0)
        return;
    tok[nlen] = '\0';

    char nick[CHAT_USER_MAX];
    memset(nick, 0, sizeof(nick));

    if (ticket_verify(tok, nlen, nick, CHAT_USER_MAX) != 0) {
        const char *err = "ERR auth";
        uint32_t el = htonl(8);
        send(s, (const char *)&el, 4, 0);
        send(s, err, 8, 0);
        return;
    }

    fprintf(stderr, "join: %s\n", nick);

    struct chat_room *room = room_join("lobby", fd);
    struct chat_msg *last_msg = nullptr;

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

            if (len >= 7 && strncmp(buf, "/repeat", 7) == 0
                && (len == 7 || buf[7] == ' ')) {
                if (last_msg) {
                    last_msg->render(last_msg);
                    uint32_t nl = htonl(last_msg->len);
                    send(s, (const char *)&nl, 4, 0);
                    send(s, last_msg->body, last_msg->len, 0);
                }
                continue;
            }

            struct chat_msg *m = msg_new(nick);
            if (m) {
                cmd_dispatch(m, buf, len);
                if (m->len > 0) {
                    uint32_t nl = htonl(m->len);
                    send(s, (const char *)&nl, 4, 0);
                    send(s, m->body, m->len, 0);
                    last_msg = m;
                }
                msg_free(m);
            }
            continue;
        }


        char line[4096];
        int n = snprintf(line, sizeof(line), "%s: %s", nick, buf);
        if (n >= (int)sizeof(line))
            n = (int)sizeof(line) - 1;

        struct chat_msg *m = msg_new(nick);
        msg_set_body(m, line, n);
        room_broadcast(room, m);
        msg_free(m);
    }

    room_leave(room, fd);
}
