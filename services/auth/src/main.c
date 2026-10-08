/* main.c -- auth server entry point. */
#include "net.h"
#include "token.h"
#include "db.h"
#include "proto.h"

#include <sodium.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Make sure that the db file exists
static void resolve_db_path(const char *arg, char *out, size_t cap)
{
    struct stat st;
    size_t n = strlen(arg);
    int is_dir = (n > 0 && arg[n-1] == '/')
              || (stat(arg, &st) == 0 && S_ISDIR(st.st_mode));
    if (is_dir) {
        int has_slash = (n > 0 && arg[n-1] == '/');
        snprintf(out, cap, "%s%sauth.db", arg, has_slash ? "" : "/");
    } else {
        snprintf(out, cap, "%s", arg);
    }
}

int main(int argc, char **argv)
{
    uint16_t port   = AUTH_DEFAULT_PORT;
    const char *sk  = "keys/idp_ed25519.sk";
    const char *darg = "auth.db";

    for (int i = 1; i < argc; i++) {
        // check to see if user has entered a port
        if (!strcmp(argv[i], "-p") && i+1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else {
            port = 4001;
        }

        // check to see if user has entered a specific key file
        if (!strcmp(argv[i], "-k") && i+1 < argc) {
            sk = argv[++i];
        } else {
            sk = "keys/idp_ed25519.sk";
        }

        // check to see if user has entered a specific db file
        if (!strcmp(argv[i], "-d") && i+1 < argc) {
            darg = argv[++i];
        } else { 
            darg = "/build/auth.db";
        }
    }

    // check db, make sure it exists
    char db[1024];
    resolve_db_path(darg, db, sizeof db);

    // initializes the sodium library, which is necessary in order to use sodium
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    // initialize the secret key by placing it into memory
    if (token_init(sk) != 0) return 1;

    // make sure the database opens properly and works
    if (db_open(db) != 0) return 1;
    db_close();

    // create a socket that starts listening for authentication requests
    int srv = net_listen(port);
    if (srv < 0) {
        perror("net_listen");
        return 1;
    }

    // accept and handle authentication requests
    fprintf(stderr, "[auth] IdP on %u (Ed25519 JWT, sqlite store %s)\n", port, db);
    net_serve_forever(srv, db);
    return 0;
}