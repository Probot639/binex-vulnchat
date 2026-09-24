#include "sp_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

/*
 * NOTE: this uses a tiny hand-rolled "key: value" line format rather than
 * real JSON, purely to avoid pulling in a JSON dependency I can't confirm
 * you're already linking. Your keys/krbtgt_*.json files imply kdc.c
 * already parses JSON somewhere -- if there's a lib already in use
 * (jansson, cJSON, etc.) this should be swapped to match for consistency.
 * The on-disk format is the only thing that would change; the API above
 * stays the same.
 */

int sp_registry_save(const char *sp_dir, const sp_record_t *rec)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/%s.conf", sp_dir, rec->name);

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "sp_registry_save: cannot open %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    fprintf(f, "name: %s\n", rec->name);
    fprintf(f, "acs_host: %s\n", rec->acs_host);
    fprintf(f, "acs_port: %d\n", rec->acs_port);
    fprintf(f, "cert_path: %s\n", rec->cert_path);

    fclose(f);
    return 0;
}

static void parse_line(sp_record_t *rec, const char *key, const char *val)
{
    if (strcmp(key, "name") == 0)
        snprintf(rec->name, sizeof(rec->name), "%s", val);
    else if (strcmp(key, "acs_host") == 0)
        snprintf(rec->acs_host, sizeof(rec->acs_host), "%s", val);
    else if (strcmp(key, "acs_port") == 0)
        rec->acs_port = atoi(val);
    else if (strcmp(key, "cert_path") == 0)
        snprintf(rec->cert_path, sizeof(rec->cert_path), "%s", val);
}

static int load_one(const char *path, sp_record_t *rec)
{
    memset(rec, 0, sizeof(*rec));

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *sep = strchr(line, ':');
        if (!sep)
            continue;
        *sep = '\0';
        char *key = line;
        char *val = sep + 1;
        while (*val == ' ')
            val++;
        char *nl = strpbrk(val, "\r\n");
        if (nl)
            *nl = '\0';
        parse_line(rec, key, val);
    }

    fclose(f);
    return 0;
}

int sp_registry_load(const char *sp_dir, sp_record_t *out, size_t max_records)
{
    DIR *d = opendir(sp_dir);
    if (!d) {
        fprintf(stderr, "sp_registry_load: cannot open %s: %s\n",
                sp_dir, strerror(errno));
        return -1;
    }

    size_t count = 0;
    struct dirent *ent;
    while (count < max_records && (ent = readdir(d)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len < 6 || strcmp(ent->d_name + len - 5, ".conf") != 0)
            continue;

        char path[600];
        snprintf(path, sizeof(path), "%s/%s", sp_dir, ent->d_name);
        if (load_one(path, &out[count]) == 0)
            count++;
    }

    closedir(d);
    return (int)count;
}

const sp_record_t *sp_registry_find(const sp_record_t *records, int count,
                                     const char *name)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(records[i].name, name) == 0)
            return &records[i];
    }
    return NULL;
}

int sp_registry_acs_url(const sp_record_t *rec, char *buf, size_t buflen)
{
    if (rec->acs_port > 0)
        snprintf(buf, buflen, "https://%s:%d/acs", rec->acs_host, rec->acs_port);
    else
        snprintf(buf, buflen, "https://%s/acs", rec->acs_host);
    return 0;
}