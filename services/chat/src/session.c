/* session.c - per-client, runs in the forked child
 *
 * join handshake first (ticket from auth), then loop on frames and
 * hand off to command.c or message.c. this owns the chat_msg.
 */
#include "chatd.h"

void session_serve(int fd)
{
    (void)fd;

    /* read JOIN frame, pull ticket out, verify
     * gavin's mac is a placeholder so just check length/expiry for now */
    /* then room_join + loop until disconnect */
}
