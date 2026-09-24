#ifndef SP_REGISTRY_H
#define SP_REGISTRY_H

#include <stddef.h>

/*
 * One registered Service Provider (e.g. the chat server).
 *
 * These are what `quickstart.sh service NAME IP_ADDR[:PORT] [SP_CERT_FILE]`
 * writes out. Each SP gets one file under sp/<name>.json.
 */
typedef struct {
    char name[128];        /* NAME arg, also used as the SAML entity ID */
    char acs_host[256];    /* IP_ADDR portion */
    int  acs_port;         /* PORT portion, 0 if none given */
    char cert_path[512];   /* optional SP_CERT_FILE, empty string if none */
} sp_record_t;

/* Writes/overwrites the registration file for one SP under sp_dir. */
int sp_registry_save(const char *sp_dir, const sp_record_t *rec);

/*
 * Loads every SP registration in sp_dir into out[], up to max_records.
 * Returns the number loaded, or -1 on error (e.g. sp_dir unreadable).
 */
int sp_registry_load(const char *sp_dir, sp_record_t *out, size_t max_records);

/* Finds a loaded record by name (== SAML entity ID). NULL if not found. */
const sp_record_t *sp_registry_find(const sp_record_t *records, int count,
                                     const char *name);

/* Builds "https://host:port/acs" style URL into buf. Returns 0 on success. */
int sp_registry_acs_url(const sp_record_t *rec, char *buf, size_t buflen);

#endif /* SP_REGISTRY_H */