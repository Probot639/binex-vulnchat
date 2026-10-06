/* net.h - socket plumbing + the per-connection frame loop (the "wiring"). */
#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>

int  net_listen(uint16_t port);          /* socket/bind/listen; -1 on error */
void net_serve_forever(int srv);          /* accept + fork-per-connection    */

/* read exactly n bytes; -1 on EOF/error. Shared by net.c and handlers. */
long readn(int fd, void *buf, size_t n);

/* frame a reply: 4-byte network-order length prefix, then body. */
int  send_frame(int fd, const void *body, uint32_t len);

#endif
