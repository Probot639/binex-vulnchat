/* The "pre-existing users" store. This is the login step, NOT the vuln --
 * kept deliberately boring and correct so the only interesting bug in the
 * auth server is the user-ID overflow next door in auth_login.c.
 *
 * Format (one per line):   username:argon2id_hash
 * Hashes are produced by keygen ("keygen adduser <name> <secret>").
 */
#include "user_table.h"
#include "proto.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

struct rec {
    char name[AUTH_USER_MAX];
    char hash[crypto_pwhash_STRBYTES];   /* argon2id encoded string */
};

#define MAX_USERS 256
static struct rec g_users[MAX_USERS];
static int g_count = 0;

int user_table_load(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror("user_table_load"); return -1; }

    char line[512];
    g_count = 0;
    while (g_count < MAX_USERS && fgets(line, sizeof line, f)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';

        snprintf(g_users[g_count].name, sizeof g_users[g_count].name, "%s", line);
        snprintf(g_users[g_count].hash, sizeof g_users[g_count].hash, "%s", colon + 1);
        g_count++;
    }
    fclose(f);
    fprintf(stderr, "[auth] loaded %d user(s) from %s\n", g_count, path);
    return 0;
}

int user_lookup(const char *user, const uint8_t *secret, size_t slen)
{
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_users[i].name, user) != 0)
            continue;
        /* constant-time argon2id verify */
        return crypto_pwhash_str_verify(
                   g_users[i].hash,
                   (const char *)secret, slen) == 0;
    }
    return 0;
}
