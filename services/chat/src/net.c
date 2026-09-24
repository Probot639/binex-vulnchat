/* net.c - sockets and framing
 *
 * frame = fixed header + length bytes payload.
 * length validated here, nowhere else.
 */
#include "chatd.h"

int net_listen(uint16_t port)
{
    (void)port;
    return -1;
}

int net_accept(int srv)
{
    (void)srv;
    return -1;
}
