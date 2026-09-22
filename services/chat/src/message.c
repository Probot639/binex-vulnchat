/*
 * message.c - allocating, growing and freeing chat_msg.
 *
 * a message starts with its text sitting in inline_body. once it goes
 * over CHAT_MSG_INLINE we move it out to the heap.
 *
 * NOTE whoever calls the grow path has to use the pointer it returns.
 * the one they passed in isn't valid after that.
 */
#include "chatd.h"
#include <stddef.h>

struct chat_msg *msg_new(const char *author)
{
    (void)author;

    /* calloc, body points at inline_body, render gets the default,
     * copy the author in */
    return NULL;
}
