/*
 * main.c - accept loop, forks per connection
 */
#include "chatd.h"
#include "db.h"

#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

static void reap(int sig)
{
    (void)sig;
    while (waitpid(-1, nullptr, WNOHANG) > 0);
}

int main(int argc, char **argv)
{
    uint16_t port = CHATD_DEFAULT_PORT;
    if (argc > 1){
        port = (uint16_t)atoi(argv[1]);
    }

    signal(SIGCHLD, reap);

    int srv = net_listen(port);
    if (srv < 0){
        perror("net_listen");
        return 1;
    }
    fprintf(stderr, "chatd listening on %d\n", port);

    for (;;) {
        int fd = net_accept(srv);
        if (fd < 0){
            continue;
        }

        pid_t pid = fork();
        if (pid < 0){
            close(fd);
            continue;
        }

        if (pid == 0) {
            close(srv);
            session_serve(fd);
            close(fd);
            _exit(0);
        }

        close(fd);
    }
}
