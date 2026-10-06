/* main.c -- auth server entry point. */
#include "net.h"
#include "token.h"
#include "user_table.h"
#include "proto.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    uint16_t port    = AUTH_DEFAULT_PORT;
    const char *sk   = "keys/idp_ed25519.sk";
    const char *tbl  = "users.tbl";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc) port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "-k") && i + 1 < argc) sk  = argv[++i];
        else if (!strcmp(argv[i], "-u") && i + 1 < argc) tbl = argv[++i];
        else { fprintf(stderr, "usage: %s [-p port] [-k sk] [-u users.tbl]\n", argv[0]); return 1; }
    }

    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); return 1; }
    if (token_init(sk)      != 0) return 1;
    if (user_table_load(tbl) != 0) return 1;

    int srv = net_listen(port);
    if (srv < 0) { perror("net_listen"); return 1; }

    fprintf(stderr, "[auth] IdP listening on %u (Ed25519 JWT, framed TCP)\n", port);
    net_serve_forever(srv);
    return 0;
}
