/* keygen.c -- setup/admin tool.
 *   keygen keys                       -> keys/idp_ed25519.{sk,pk}
 *   keygen adduser <name> <secret> [db] -> INSERT into the sqlite users table
 */
#include "db.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int cmd_keys(void)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    mkdir("keys", 0700);
    FILE *f;
    if (!(f = fopen("keys/idp_ed25519.sk","wb"))) { perror("sk"); return 1; }
    fwrite(sk,1,sizeof sk,f); fclose(f); chmod("keys/idp_ed25519.sk",0600);
    if (!(f = fopen("keys/idp_ed25519.pk","wb"))) { perror("pk"); return 1; }
    fwrite(pk,1,sizeof pk,f); fclose(f);
    fprintf(stderr,"wrote keys/idp_ed25519.sk (secret) + .pk (ship to chat servers)\n");
    return 0;
}

static int cmd_adduser(const char *name, const char *secret, const char *db)
{
    if (db_open(db) != 0) return 1;
    int rc = db_adduser(name, secret);
    db_close();
    if (rc == 0) fprintf(stderr, "added user '%s' to %s\n", name, db);
    else         fprintf(stderr, "adduser failed\n");
    return rc == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (sodium_init() < 0) return 1;
    if (argc >= 2 && !strcmp(argv[1],"keys")) return cmd_keys();
    if ((argc == 4 || argc == 5) && !strcmp(argv[1],"adduser"))
        return cmd_adduser(argv[2], argv[3], argc == 5 ? argv[4] : "auth.db");
    fprintf(stderr,"usage:\n  %s keys\n  %s adduser <name> <secret> [auth.db]\n", argv[0], argv[0]);
    return 1;
}
