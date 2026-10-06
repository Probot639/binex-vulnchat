/* user_table.h - the pre-existing-users store (login step, not the vuln). */
#ifndef USER_TABLE_H
#define USER_TABLE_H

#include <stdint.h>
#include <stddef.h>

/* Load users.tbl ("username:argon2id_hash" per line). 0 on success. */
int user_table_load(const char *path);

/* 1 if `user` exists and `secret` (len `slen`) verifies, else 0. */
int user_lookup(const char *user, const uint8_t *secret, size_t slen);

#endif
