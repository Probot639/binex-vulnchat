/*
 * main.c - accept loop, forks per connection
 *
 * the parent keeps every client fd open and acts as a message relay.
 * children write framed messages to a shared pipe, the parent reads
 * them and broadcasts to all connected sockets.
 */
#include "chatd.h"
#include "db.h"
#include "ticket.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/mman.h>

int g_relay_fd = -1;
struct who_slot *g_who_table = nullptr;

struct slot {
    int fd;
    pid_t pid;
};

static struct slot slots[256];
static int nslots;

static void slot_add(int fd, pid_t pid)
{
    if (nslots < 256) {
        slots[nslots].fd = fd;
        slots[nslots].pid = pid;
        nslots++;
    }
}

static void broadcast_all(const char *text, int len)
{
    uint32_t nl = htonl(len);
    for (int i = 0; i < nslots; i++) {
        write(slots[i].fd, &nl, 4);
        write(slots[i].fd, text, len);
    }
}

static void slot_reap(void)
{
    pid_t p;
    while ((p = waitpid(-1, nullptr, WNOHANG)) > 0) {
        if (g_who_table) {
            for (int i = 0; i < WHO_TABLE_MAX; i++) {
                if (g_who_table[i].pid == p) {
                    char msg[256];
                    int mlen = snprintf(msg, sizeof(msg),
                        "-- %s left --", g_who_table[i].nick);
                    g_who_table[i].pid = 0;
                    memset(g_who_table[i].nick, 0, CHAT_USER_MAX);
                    broadcast_all(msg, mlen);
                    break;
                }
            }
        }
        for (int i = 0; i < nslots; i++) {
            if (slots[i].pid == p) {
                close(slots[i].fd);
                slots[i] = slots[--nslots];
                break;
            }
        }
    }
}

static volatile sig_atomic_t got_child;

static void on_sigchld(int sig)
{
    (void)sig;
    got_child = 1;
}

static ssize_t readn(int fd, void *buf, size_t n)
{
    char *p = (char *)buf;
    size_t left = n;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r <= 0)
            return -1;
        p += r;
        left -= (size_t)r;
    }
    return (ssize_t)n;
}

static void relay_one(int pipe_rd)
{
    uint32_t net_len;
    if (readn(pipe_rd, &net_len, 4) < 0)
        return;
    uint32_t len = ntohl(net_len);
    if (len == 0 || len > 8192)
        return;

    char buf[8192];
    if (readn(pipe_rd, buf, len) < 0)
        return;

    for (int i = 0; i < nslots; i++) {
        write(slots[i].fd, &net_len, 4);
        write(slots[i].fd, buf, len);
    }
}

int main(int argc, char **argv)
{
    uint16_t port = CHATD_DEFAULT_PORT;
    const char *pk_path = nullptr;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-k") && i + 1 < argc)
            pk_path = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc)
            port = (uint16_t)atoi(argv[++i]);
        else
            port = (uint16_t)atoi(argv[i]);
    }

    if (!pk_path) {
        fprintf(stderr, "usage: chatd [-p port] -k <pubkey>\n");
        return 1;
    }

    if (ticket_init(pk_path) != 0) {
        fprintf(stderr, "failed to load public key: %s\n", pk_path);
        return 1;
    }

    signal(SIGCHLD, on_sigchld);
    signal(SIGPIPE, SIG_IGN);

    int srv = net_listen(port);
    if (srv < 0) {
        perror("net_listen");
        return 1;
    }
    fprintf(stderr, "chatd listening on %d (jwt verify on)\n", port);

    g_who_table = (struct who_slot *)mmap(nullptr,
        sizeof(struct who_slot) * WHO_TABLE_MAX,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_who_table != MAP_FAILED)
        memset(g_who_table, 0, sizeof(struct who_slot) * WHO_TABLE_MAX);
    else
        g_who_table = nullptr;

    int relay[2];
    if (pipe(relay) < 0) {
        perror("pipe");
        return 1;
    }
    g_relay_fd = relay[1];

    struct pollfd pfd[2];
    pfd[0].fd = srv;
    pfd[0].events = POLLIN;
    pfd[1].fd = relay[0];
    pfd[1].events = POLLIN;

    for (;;) {
        int n = poll(pfd, 2, -1);

        if (got_child) {
            got_child = 0;
            slot_reap();
        }

        if (n < 0)
            continue;

        if (pfd[1].revents & POLLIN)
            relay_one(relay[0]);

        if (pfd[0].revents & POLLIN) {
            int fd = net_accept(srv);
            if (fd < 0)
                continue;

            pid_t pid = fork();
            if (pid < 0) {
                close(fd);
                continue;
            }

            if (pid == 0) {
                close(srv);
                close(relay[0]);
                session_serve(fd);
                close(fd);
                _exit(0);
            }

            slot_add(fd, pid);
        }
    }
}
