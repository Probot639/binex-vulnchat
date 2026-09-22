/* net.c
 *
 * sockets and framing. a frame is the fixed size header followed by
 * exactly `length` bytes of payload.
 *
 * length gets checked against the read buffer here and nowhere else, so
 * everything downstream can assume it's been handed a sane frame.
 */
#include "chatd.h"

int net_listen(uint16_t port)
{
    (void)port;

    /* socket, SO_REUSEADDR, bind, listen */
    return -1;
}

/* new fd on success, -1 otherwise. caller decides about forking */
int net_accept(int srv)
{
    (void)srv;
    return -1;
}
