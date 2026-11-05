/* session.c - per-client, runs in the forked child
 *
 * join handshake first (ticket from auth), then loop on frames and
 * hand off to command.c or message.c. this owns the chat_msg.
 *
 * messages go through g_relay_fd (pipe to the parent) so the parent
 * can broadcast to all connected clients across fork boundaries.
 *
 * the /repeat path keeps a last_msg pointer across iterations.
 * command messages that produce output get saved there, then freed
 * in the same block. /repeat dereferences the stale pointer.
 */
#include "chatd.h"
#include "ticket.h"

#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

extern int g_relay_fd;
extern struct who_slot *g_who_table;

static ssize_t readn(int fd, void *buf, size_t n)
{
    char *p = (char *)buf;
    size_t left = n;

    while (left > 0) {
        ssize_t r = read(fd, p, left);
        if (r <= 0)
            return -1;
        p += r;
        left -= r;
    }
    return (ssize_t)n;
}

static void relay_broadcast(const char *text, int len)
{
    char frame[4100];
    uint32_t nl = htonl(len);
    memcpy(frame, &nl, 4);
    memcpy(frame + 4, text, len);
    write(g_relay_fd, frame, 4 + len);
}

static void send_response(int fd, const char *text, int len)
{
    uint32_t nl = htonl(len);
    write(fd, &nl, 4);
    write(fd, text, len);
}

void session_serve(int fd)
{
    uint32_t nlen;
    if (readn(fd, &nlen, sizeof(nlen)) < 0)
        return;
    nlen = ntohl(nlen);

    if (nlen == 0 || nlen > 1024)
        return;

    char tok[1025];
    if (readn(fd, tok, nlen) < 0)
        return;
    tok[nlen] = '\0';

    char nick[CHAT_USER_MAX];
    memset(nick, 0, sizeof(nick));

    if (ticket_verify(tok, nlen, nick, CHAT_USER_MAX) != 0) {
        send_response(fd, "ERR auth", 8);
        return;
    }

    fprintf(stderr, "join: %s\n", nick);

    int who_idx = -1;
    if (g_who_table) {
        for (int i = 0; i < WHO_TABLE_MAX; i++) {
            if (g_who_table[i].pid == 0) {
                g_who_table[i].pid = getpid();
                strncpy(g_who_table[i].nick, nick, CHAT_USER_MAX - 1);
                who_idx = i;
                break;
            }
        }
    }

    char announce[256];
    int alen = snprintf(announce, sizeof(announce), "-- %s joined --", nick);
    relay_broadcast(announce, alen);

    struct chat_msg *last_msg = nullptr;
    struct chat_room *cur_room = nullptr;

    for (;;) {
        uint32_t len;
        if (readn(fd, &len, sizeof(len)) < 0)
            break;
        len = ntohl(len);

        if (len == 0 || len > 4095)
            break;

        char buf[4096];

        if (readn(fd, buf, len) < 0)
            break;
        buf[len] = '\0';

        if (buf[0] == '/') {

            /* /who -- read from the shared who table (mmap'd across forks) */
            if (len >= 4 && strncmp(buf, "/who", 4) == 0
                && (len == 4 || buf[4] == ' ')) {
                char resp[4096];
                int rlen = snprintf(resp, sizeof(resp), "online:");
                if (g_who_table) {
                    for (int i = 0; i < WHO_TABLE_MAX; i++) {
                        if (g_who_table[i].pid != 0)
                            rlen += snprintf(resp + rlen,
                                sizeof(resp) - rlen, " %s",
                                g_who_table[i].nick);
                    }
                }
                send_response(fd, resp, rlen);
                continue;
            }

            /* /repeat -- replays last_msg through the render pointer.
             * if the msg was freed (command path), this dereferences
             * a dangling pointer: the render function pointer and body
             * come from whatever now occupies the freed region. */
            if (len >= 7 && strncmp(buf, "/repeat", 7) == 0
                && (len == 7 || buf[7] == ' ')) {
                if (last_msg) {
                    last_msg->render(last_msg);
                    send_response(fd, last_msg->body, last_msg->len);
                }
                continue;
            }

            /* /join -- wire up the room table from room.cpp */
            if (len > 6 && strncmp(buf, "/join ", 6) == 0) {
                const char *rname = buf + 6;
                cur_room = room_join(rname, fd);
                if (cur_room) {
                    char resp[128];
                    int rlen = snprintf(resp, sizeof(resp),
                        "joined #%s", rname);
                    send_response(fd, resp, rlen);
                }
                continue;
            }

            struct chat_msg *m = msg_new(nick);
            if (!m) continue;

            cmd_dispatch(m, buf, len);

            if (strcmp(m->author, nick) != 0) {
                char nchange[256];
                int nclen = snprintf(nchange, sizeof(nchange),
                    "-- %s is now %s --", nick, m->author);
                relay_broadcast(nchange, nclen);
                strncpy(nick, m->author, CHAT_USER_MAX - 1);
                if (who_idx >= 0 && g_who_table)
                    strncpy(g_who_table[who_idx].nick, nick,
                        CHAT_USER_MAX - 1);
            }

            if (m->len > 0) {
                if (len >= 4 && strncmp(buf, "/me ", 4) == 0) {
                    char action[4096];
                    int alen = snprintf(action, sizeof(action),
                        "* %s %s", nick, m->body);
                    relay_broadcast(action, alen);
                } else {
                    send_response(fd, m->body, m->len);
                }
                last_msg = m;
            }
            msg_free(m);
            continue;
        }

        char line[4096];
        int n = snprintf(line, sizeof(line), "%s: %s", nick, buf);
        if (n >= (int)sizeof(line))
            n = (int)sizeof(line) - 1;

        struct chat_msg *m = msg_new(nick);
        msg_set_body(m, line, n);

        relay_broadcast(m->body, m->len);

        last_msg = m;
    }

    if (who_idx >= 0 && g_who_table) {
        g_who_table[who_idx].pid = 0;
        memset(g_who_table[who_idx].nick, 0, CHAT_USER_MAX);
    }
}
