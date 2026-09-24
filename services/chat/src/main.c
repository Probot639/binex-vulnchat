/*
 * main.c - accept loop, forks per connection
 */
#include "chatd.h"
#include "db.h"

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    // TODO: port from argv[1], default CHATD_DEFAULT_PORT
    /* db_open before bind - no point listening if storage is dead */
    /* then accept/fork loop, child calls session_serve() */

    return 0;
}
