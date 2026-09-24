/* session.c - per-client, runs in the forked child
 *
 * join handshake first (ticket from auth), then loop on frames and
 * hand off to command.c or message.c. this owns the chat_msg.
 */
#include "chatd.h"

#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

static ssize_t readn(int fd, void *buf, size_t n){
    char *p = (char *)buf;
    size_t left = n;

    while (left > 0) {
        ssize_t r = read(fd, p, left);
        if (r <= 0){
            return -1;
        }
        p += r;
        left -= r;
    }
    return (ssize_t)n;
}

void session_serve(int fd)
{
    /* first frame is the nick for now, no auth yet */
    uint32_t nlen;
    if (readn(fd, &nlen, sizeof(nlen)) < 0){
        return;
    }
    nlen = ntohl(nlen);

    if (nlen == 0 || nlen >= CHAT_USER_MAX){
        return;
    }

    char nick[CHAT_USER_MAX];
    memset(nick, 0, sizeof(nick));
    if (readn(fd, &len, sizeof(len)) < 0){
        return;
    }

    fprintf(stderr, "join: %s\n", nick);

    for (;;) {
        uint32_t len;
        if (readn(fd, &len, sizeof(len)) < 0) {
            break;
        }
        len = ntohl(len);

        if (len == 0 || len > 4095){
            break;
        }

        char buf[4096];

        if (readn(fd, buf, len) < 0){
            break;
        }
        buf[len] = '\0';

        if (buf[0] == '/') {
            struct chat_msg *m = msg_new(nick);
            if (m) {
                cmd_dispatch(m, buf, len);
            }
            continue;
        }


        /* TODO: wrap in chat_msg and send to room */
    }


    }
}
