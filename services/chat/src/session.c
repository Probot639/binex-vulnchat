/* session.c
 *
 * one of these runs in each forked child, for one connected client.
 *
 * does the join handshake first (the ticket comes from the auth server),
 * then loops pulling frames off the socket and handing them to command.c
 * or message.c depending on what type they are.
 *
 * this owns the client's chat_msg. nothing else should be freeing it.
 */
#include "chatd.h"

void session_serve(int fd)
{
    (void)fd;

    /* TODO read the JOIN frame and pull the ticket out */
    /* TODO verify it - gavin says the mac is a placeholder right now so
     *      this is just a length/expiry check until that lands */
    /* TODO room_join, then loop until the client goes away */
}
