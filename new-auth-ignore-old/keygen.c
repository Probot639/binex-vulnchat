/* keygen.c -- setup tool. Replaces the old quickstart.sh crypto wholesale.
 *
 *   keygen keys                      -> keys/idp_ed25519.sk  (64B, server)
 *                                       keys/idp_ed25519.pk  (32B, give to
 *                                                             each chat server)
 *   keygen adduser <name> <secret>   -> prints "name:argon2id_hash"
 *                                       (append it to users.tbl)
 */
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int cmd_keys(void)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    mkdir("keys", 0700);
    FILE *f;
    if (!(f = fopen("keys/idp_ed25519.sk", "wb"))) { perror("sk"); return 1; }
    fwrite(sk, 1, sizeof sk, f); fclose(f); chmod("keys/idp_ed25519.sk", 0600);
    if (!(f = fopen("keys/idp_ed25519.pk", "wb"))) { perror("pk"); return 1; }
    fwrite(pk, 1, sizeof pk, f); fclose(f);

    fprintf(stderr, "wrote keys/idp_ed25519.sk (keep secret) and keys/idp_ed25519.pk (ship to SPs)\n");
    return 0;
}

static int cmd_adduser(const char *name, const char *secret)
{
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, secret, strlen(secret),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        fprintf(stderr, "out of memory hashing\n");
        return 1;
    }
    printf("%s:%s\n", name, hash);
    return 0;
}

int main(int argc, char **argv)
{
    if (sodium_init() < 0) return 1;
    if (argc >= 2 && !strcmp(argv[1], "keys"))
        return cmd_keys();
    if (argc == 4 && !strcmp(argv[1], "adduser"))
        return cmd_adduser(argv[2], argv[3]);
    fprintf(stderr, "usage:\n  %s keys\n  %s adduser <name> <secret>\n", argv[0], argv[0]);
    return 1;
}
