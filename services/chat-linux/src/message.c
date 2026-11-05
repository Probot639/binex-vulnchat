/* message.c - chat_msg alloc/grow/free
 *
 * body starts in inline_body, gets promoted to heap past CHAT_MSG_INLINE.
 * the free path doesn't null out body. if the caller still holds a ref
 * to the msg, render() goes through a dangling pointer.
 */
#include "chatd.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void default_render(struct chat_msg *m)
{
    fprintf(stderr, "%s: %s\n", m->author, m->body);
}

struct chat_msg *msg_new(const char *author)
{
    struct chat_msg *m;

    m = malloc(sizeof(*m));
    if (!m)
        return NULL;
    memset(m, 0, sizeof(*m));

    strncpy(m->author, author, CHAT_USER_MAX - 1);
    m->body = m->inline_body;
    m->render = default_render;

    return m;
}

void msg_free(struct chat_msg *m)
{
    if (m->body != m->inline_body)
        free(m->body);
    free(m);
}

void msg_set_body(struct chat_msg *m, const char *text, uint32_t len)
{
    if (len < CHAT_MSG_INLINE) {
        memcpy(m->inline_body, text, len);
        m->inline_body[len] = '\0';
        m->body = m->inline_body;
    } else {
        m->body = malloc(len + 1);
        memcpy(m->body, text, len);
        m->body[len] = '\0';
    }
    m->len = len;
}
