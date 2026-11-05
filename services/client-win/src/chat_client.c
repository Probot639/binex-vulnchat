/* chat_client.c - console chat client for vulnchat (windows)
 *
 * authenticates via auth_client lib, connects to chatd with the JWT,
 * receiver thread prints incoming messages while main thread reads
 * stdin. no curses, just plain console i/o.
 */
#define AUTH_CLIENT_BUILD
#include "auth_client.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAME_MAX 4096

static SOCKET chat_sock = INVALID_SOCKET;
static volatile int running = 1;
static char my_nick[64];
static CRITICAL_SECTION nick_cs;



static int recvn(SOCKET s, void *buf, int n)
{
    char *p = buf;
    int left = n;
    while (left > 0) {
        int r = recv(s, p, left, 0);
        if (r <= 0)
            return -1;
        p += r;
        left -= r;
    }
    return 0;
}

static int send_frame(SOCKET s, const void *data, uint32_t len)
{
    uint32_t nl = htonl(len);
    const char *p = data;
    int off;

    if (send(s, (const char *)&nl, 4, 0) != 4)
        return -1;
    off = 0;
    while ((uint32_t)off < len) {
        int r = send(s, p + off, len - off, 0);
        if (r <= 0)
            return -1;
        off += r;
    }
    return 0;
}

static int recv_frame(SOCKET s, char *buf, int cap)
{
    uint32_t nl, len;

    if (recvn(s, &nl, 4) < 0)
        return -1;
    len = ntohl(nl);
    if (len == 0 || len >= (uint32_t)cap)
        return -1;
    if (recvn(s, buf, (int)len) < 0)
        return -1;
    buf[len] = '\0';
    return (int)len;
}



static DWORD WINAPI recv_thread(LPVOID arg)
{
    char buf[FRAME_MAX];
    int n;

    (void)arg;

    while (running) {
        n = recv_frame(chat_sock, buf, sizeof(buf));
        if (n < 0) {
            if (running) {
                printf("\n*** connection lost ***\n");
                running = 0;
            }
            break;
        }
        EnterCriticalSection(&nick_cs);
        printf("\r%s\n%s> ", buf, my_nick);
        fflush(stdout);
        LeaveCriticalSection(&nick_cs);
    }
    return 0;
}


int main(int argc, char **argv)
{
    const char *auth_host, *chat_host, *user, *pw;
    uint16_t auth_port, chat_port;
    char jwt[2048];
    size_t jwt_len;
    auth_result_t rc;
    WSADATA wsa;
    struct sockaddr_in addr;
    char joinbuf[FRAME_MAX];
    HANDLE rtid;
    char line[FRAME_MAX];

    if (argc < 7) {
        fprintf(stderr,
            "usage: %s <auth_host> <auth_port> <chat_host> <chat_port> <user> <pass>\n",
            argv[0]);
        return 1;
    }

    auth_host = argv[1];
    auth_port = (uint16_t)atoi(argv[2]);
    chat_host = argv[3];
    chat_port = (uint16_t)atoi(argv[4]);
    user      = argv[5];
    pw        = argv[6];

    strncpy(my_nick, user, sizeof(my_nick) - 1);

    /* winsock init */
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    /* authenticate */
    fprintf(stderr, "authenticating %s with %s:%d...\n", user, auth_host, auth_port);
    rc = auth_login(auth_host, auth_port, user, pw,
                    jwt, sizeof(jwt), &jwt_len);
    if (rc != AUTH_OK) {
        fprintf(stderr, "auth failed: %s\n", auth_strerror(rc));
        WSACleanup();
        return 1;
    }
    fprintf(stderr, "token ok (%u bytes), connecting to %s:%d...\n",
            (unsigned)jwt_len, chat_host, chat_port);

    /* connect to chatd */
    chat_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (chat_sock == INVALID_SOCKET) {
        fprintf(stderr, "socket failed\n");
        WSACleanup();
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(chat_port);
    if (inet_pton(AF_INET, chat_host, &addr.sin_addr) != 1) {
        struct hostent *he = gethostbyname(chat_host);
        if (!he) {
            fprintf(stderr, "can't resolve %s\n", chat_host);
            closesocket(chat_sock);
            WSACleanup();
            return 1;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));
    }

    if (connect(chat_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "connect to chatd failed\n");
        closesocket(chat_sock);
        WSACleanup();
        return 1;
    }

    /* send JWT */
    if (send_frame(chat_sock, jwt, (uint32_t)jwt_len) < 0) {
        fprintf(stderr, "handshake failed\n");
        closesocket(chat_sock);
        WSACleanup();
        return 1;
    }

    if (recv_frame(chat_sock, joinbuf, sizeof(joinbuf)) < 0 ||
        strncmp(joinbuf, "ERR", 3) == 0) {
        fprintf(stderr, "server rejected: %s\n", joinbuf);
        closesocket(chat_sock);
        WSACleanup();
        return 1;
    }

    printf("connected as %s. type /help for commands, ctrl-c to quit.\n", my_nick);
    printf("%s> ", my_nick);
    fflush(stdout);

    InitializeCriticalSection(&nick_cs);
    rtid = CreateThread(NULL, 0, recv_thread, NULL, 0, NULL);
    if (!rtid) {
        fprintf(stderr, "CreateThread failed\n");
        closesocket(chat_sock);
        WSACleanup();
        return 1;
    }

    /* input loop */
    while (running && fgets(line, sizeof(line), stdin)) {
        int len = (int)strlen(line);
        /* strip trailing newline */
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0)
            continue;

        /* track /nick locally */
        if (strncmp(line, "/nick ", 6) == 0) {
            const char *nn = line + 6;
            while (*nn == ' ') nn++;
            if (*nn) {
                EnterCriticalSection(&nick_cs);
                strncpy(my_nick, nn, sizeof(my_nick) - 1);
                my_nick[sizeof(my_nick) - 1] = '\0';
                LeaveCriticalSection(&nick_cs);
            }
        }

        send_frame(chat_sock, line, (uint32_t)len);
        printf("%s> ", my_nick);
        fflush(stdout);
    }

    running = 0;
    closesocket(chat_sock);
    WaitForSingleObject(rtid, 2000);
    CloseHandle(rtid);
    DeleteCriticalSection(&nick_cs);
    WSACleanup();
    printf("disconnected\n");
    return 0;
}
