/*
 * main_win.cpp - accept loop, thread per connection
 *
 * windows doesn't have fork so each client gets a thread.
 * the address space is shared but that's fine for the demo,
 * the vuln is still exploitable per-thread.
 */
#include "chatd.h"
#include "db.h"

#include <winsock2.h>
#include <cstdio>
#include <cstdlib>

/* from room_win.cpp */
extern "C" void room_init(void);

static DWORD WINAPI client_thread(LPVOID arg)
{
    int fd = (int)(intptr_t)arg;
    session_serve(fd);
    closesocket((SOCKET)fd);
    return 0;
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    uint16_t port = CHATD_DEFAULT_PORT;
    if (argc > 1){
        port = (uint16_t)atoi(argv[1]);
    }

    room_init();

    int srv = net_listen(port);
    if (srv < 0){
        fprintf(stderr, "net_listen: failed\n");
        WSACleanup();
        return 1;
    }
    fprintf(stderr, "chatd listening on %d\n", port);

    for (;;) {
        int fd = net_accept(srv);
        if (fd < 0){
            continue;
        }

        HANDLE h = CreateThread(NULL, 0, client_thread,
                                (LPVOID)(intptr_t)fd, 0, NULL);
        if (h == NULL) {
            closesocket((SOCKET)fd);
            continue;
        }
        CloseHandle(h);
    }

    WSACleanup();
}
