/* db.h - sqlite store for the auth service.
 *
 * Narrow interface, same shape as chat-linux/db.h so the convention matches
 * across services. One handle per PROCESS: open AFTER fork(), never share a
 * handle a child inherited (sqlite connections are not fork-safe).
 */
#ifndef DB_H
#define DB_H
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Open this process's handle and apply schema (idempotent). 0 on success. */
int  db_open(const char *path);
void db_close(void);

/* Provision a user (argon2id-hashed secret). Used by the keygen admin tool. */
int  db_adduser(const char *name, const char *secret);

/* Append an issued-token row to the audit log. Non-fatal; the growing table. */
void db_log_issue(const char *name, long iat, long exp);

int user_lookup(const char *user, const uint8_t *secret, size_t slen);

#ifdef __cplusplus
}
#endif
#endif
