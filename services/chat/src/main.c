/*
 * main.c
 *
 * startup and the accept loop. fork a child per connection and let
 * session.c do the actual work.
 *
 * keeping this boring on purpose, no protocol handling here.
 */
#include "chatd.h"
#include "db.h"

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* TODO port out of argv[1], fall back to CHATD_DEFAULT_PORT */
    /* TODO db_open before we bind, no point listening if storage is dead */
    /* TODO net_listen, then accept / fork / session_serve in the child */

    return 0;
}
