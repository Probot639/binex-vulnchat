/* net_win.cpp - winsock listen/accept
 *
 * same framing as linux: 4-byte big-endian length + payload.
 * winsock is mostly the same API but SOCKET is its own type and
 * you need WSAStartup before anything works.
 */
#include "chatd.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>

extern "C" int net_listen(uint16_t port)
{
    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(fd);
        return -1;
    }

    if (listen(fd, 16) == SOCKET_ERROR) {
        closesocket(fd);
        return -1;
    }

    return (int)fd;
}

extern "C" int net_accept(int srv)
{
    SOCKET c = accept((SOCKET)srv, nullptr, nullptr);
    if (c == INVALID_SOCKET)
        return -1;
    return (int)c;
}
