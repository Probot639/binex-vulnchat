/* chatd.h */
#ifndef CHATD_H
#define CHATD_H

#include <stdint.h>

#define CHATD_DEFAULT_PORT 4002
#define CHAT_USER_MAX 64        /* has to match the auth ticket layout */
#define CHAT_MSG_INLINE 128
#define CHAT_ROOM_MAX 16

struct chat_msg {
    uint32_t len;
    char *body;     /* points into inline_body until we promote it */
    char inline_body[CHAT_MSG_INLINE];
    void (*render)(struct chat_msg *);
    char author[CHAT_USER_MAX];
};

struct chat_room;   /* defined in room.c */

int net_listen(uint16_t port);
int net_accept(int srv);
void session_serve(int fd);
int room_broadcast(struct chat_room *r, const struct chat_msg *m);
int cmd_dispatch(struct chat_msg *m, const char *line, uint32_t len);
struct chat_msg *msg_new(const char *author);

#endif
