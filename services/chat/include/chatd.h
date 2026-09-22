/* chatd.h - types and prototypes shared across the chat server.
 *
 * if only one .c file needs it, keep it static in that file instead of
 * putting it in here.
 */
#ifndef CHATD_H
#define CHATD_H

#include <stdint.h>

#define CHATD_DEFAULT_PORT 4002

/* has to agree with the ticket layout the auth server hands us.
 * check with darwin before touching it */
#define CHAT_USER_MAX 64

/* messages this size or smaller live in the struct. anything bigger gets
 * moved out to the heap, see message.c */
#define CHAT_MSG_INLINE 128

#define CHAT_ROOM_MAX 16

struct chat_msg {
    uint32_t len;
    char *body;     /* points into inline_body until we promote it */
    char inline_body[CHAT_MSG_INLINE];
    void (*render)(struct chat_msg *);
    char author[CHAT_USER_MAX];
};

struct chat_room;   /* room.c owns the real definition */

/* net.c */
int net_listen(uint16_t port);
int net_accept(int srv);

/* session.c */
void session_serve(int fd);

/* room.c */
int room_broadcast(struct chat_room *r, const struct chat_msg *m);

/* command.c */
int cmd_dispatch(struct chat_msg *m, const char *line, uint32_t len);

/* message.c */
struct chat_msg *msg_new(const char *author);

#endif
