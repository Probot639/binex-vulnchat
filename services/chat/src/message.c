/* message.c - chat_msg alloc/grow/free
 *
 * body starts in inline_body, gets promoted to heap past CHAT_MSG_INLINE.
 * if you call the grow path use the pointer it returns, not the old one.
 */
#include "chatd.h"
#include <stddef.h>

struct chat_msg *msg_new(const char *author)
{
    (void)author;
    return NULL;
}
