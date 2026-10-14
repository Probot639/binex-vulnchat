/* net.h - socket plumbing + the per-connection frame loop (the "wiring"). */
#ifndef NET_H
#define NET_H
#include <stdint.h>
#include <stddef.h>
int  net_listen(uint16_t port);
void net_serve_forever(int srv, const char *db_path);
long readn(int fd, void *buf, size_t n);
int  send_frame(int fd, const void *body, uint32_t len);
#endif
