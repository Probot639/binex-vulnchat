/* net.c -- sockets + the per-connection frame loop (the "wiring").
 * Mirrors chat-linux: 4-byte network-order length prefix + payload; parent
 * accepts and forks; each child opens ITS OWN sqlite handle, runs the loop,
 * and dispatches on the opcode byte.
 */
#include "net.h"
#include "auth.h"
#include "db.h"
#include "proto.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>


/*
* something
*/
long readn(int fd, void *buf, size_t n)
{
    char *p = (char *)buf; size_t left = n;
    while (left > 0) {
        long r = read(fd, p, left);
        if (r <= 0) return -1;
        p += r; left -= (size_t)r;
    }
    return (long)n;
}

// sends a message to the client, maintains protocol format
int send_frame(int fd, const void *body, uint32_t len)
{
    // convert to big-endian (network) order
    uint32_t nlen = htonl(len);

    // send the 4 byte length (which is why "ERR auth" messages pass the length)
    if (write(fd, &nlen, sizeof nlen) != (long)sizeof nlen) return -1;

    // send the message bytes
    if (len && write(fd, body, len) != (long)len) return -1;
    return 0;
}

int net_listen(uint16_t port)
{
    // create a socket to listen on
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    // set the options for the socket
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    // store socket data
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    // bind the socket to the address:port and begin listening
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd); return -1;
    }
    return fd;
}

/* handler for incoming requests
* 
*/
static void session_serve(int fd, const char *db_path)
{
    // open the database
    db_open(db_path);

    // begin infinite loop
    for (;;) {

        // read the request
        uint32_t len;
        if (readn(fd, &len, sizeof len) < 0) break;

        // fix endianness
        len = ntohl(len);
        if (len == 0 || len > AUTH_FRAME_MAX) break;

        // read the message body
        uint8_t payload[AUTH_FRAME_MAX];
        if (readn(fd, payload, len) < 0) break;

        // determine how to handle the payload based on formatting
        switch (payload[0]) {
            case OP_LOGIN : {
                handle_login(fd, payload, len);
                break;
            }
            case OP_DEBUG: {
                handle_debug(fd);
                break;
            }
            default: {
                send_frame(fd, "ERR op", 6);
                break;
            }
        }
    }
    db_close();
}


/*
* @brief Accepts incoming authentication requests
*
* Accepts incoming authentication requests. Once the requests are accepted,
* it forks with the active connection, having the child serve the request,
* while the parent process 
*
* @param srv The socket already binded and listening
* @param db_path The path to the database file
*/
void net_serve_forever(int srv, const char *db_path)
{
    signal(SIGCHLD, SIG_IGN);

    // begin infinite loop
    for (;;) {

        // accept new connection
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;

        // fork to handle new connections in child, while parent accepts more
        // !!! IMPORTANT: Allows the process to remain alive after addresses leaked
        pid_t pid = fork();
        if (pid == 0) {
            close(srv);
            session_serve(c, db_path);
            close(c);
            _exit(0);
        }
        close(c);
    }
}
