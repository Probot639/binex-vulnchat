/* db.cpp - sqlite backend for the auth service. Scaffolding, so .cpp.
 *
 * One handle per process (opened in the forked child from net.c). All
 * queries are PREPARED/bound -- there is deliberately no SQL-injection
 * surface here, because the only intended bug in this service is the
 * memory-corruption overflow next door in auth_login.c, and that fires
 * pre-auth, before any query below is ever reached.
 *
 * The schema lives in schema.sql (readable source of truth) and is embedded
 * here so the release binary needs no sidecar file on the testers' machines.
 * Keep the two in sync (or generate this string with `xxd -i schema.sql`).
 */
#include "db.h"

#include <sqlite3.h>
#include <sodium.h>
#include <cstdio>
#include <cstring>

static const char *SCHEMA =
    "CREATE TABLE IF NOT EXISTS users ("
    "  user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 63),"
    "  secret_hash TEXT NOT NULL,"
    "  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')));"
    "CREATE TABLE IF NOT EXISTS auth_log ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  name TEXT NOT NULL, iat INTEGER NOT NULL, exp INTEGER NOT NULL);"
    "CREATE INDEX IF NOT EXISTS auth_log_name_iat ON auth_log(name, iat);";

static sqlite3 *g_db = nullptr;      // database handle

// open the database
int db_open(const char *path)
{
    // check if it's already open
    if (g_db) return 0;

    // opens the database file
    if (sqlite3_open(path, &g_db) != SQLITE_OK) {
        fprintf(stderr, "db_open: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    // create the tables using the SCHEMA variable
    char *err = nullptr;
    if (sqlite3_exec(g_db, SCHEMA, nullptr, nullptr, &err) != SQLITE_OK) {
        fprintf(stderr, "db_open schema: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

// close the database and set the db pointer to a null pointer
void db_close(void)
{
    if (g_db) { sqlite3_close(g_db); g_db = nullptr; }
}

// looks up the user
int user_lookup(const char *user, const uint8_t *secret, size_t slen)
{
    // if the database handle is not active just return 0
    if (!g_db) return 0;

    // setup the prepared sql statement (prevents sql injection as it's not the point)
    sqlite3_stmt *st = nullptr;
    if (sqlite3_prepare_v2(g_db,
            "SELECT secret_hash FROM users WHERE name = ?1",
            -1, &st, nullptr) != SQLITE_OK)
        return 0;

    // bind the text together (prevents sql injection again)
    sqlite3_bind_text(st, 1, user, -1, SQLITE_TRANSIENT); 

    // query for data
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {

        // grab the password hash
        const char *hash = (const char *)sqlite3_column_text(st, 0);
        if (hash)

            // use libsodium functions to verify the secret matches the hash
            ok = (crypto_pwhash_str_verify(hash,
                      (const char *)secret, slen) == 0);
    }

    // destroy the statement
    sqlite3_finalize(st);
    return ok;
}


// add a user to the database
int db_adduser(const char *name, const char *secret)
{

    // if the database handle is not active, return error
    if (!g_db) return -1;

    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, secret, strlen(secret),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
        return -1;

    sqlite3_stmt *st = nullptr;
    if (sqlite3_prepare_v2(g_db,
            "INSERT OR REPLACE INTO users(name, secret_hash) VALUES(?1, ?2)",
            -1, &st, nullptr) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, hash, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

// log whenever a token is issued
void db_log_issue(const char *name, long iat, long exp)
{

    // make sure the database handler is active, otherwise exit function
    if (!g_db) return;

    // prepare the log statement
    sqlite3_stmt *st = nullptr;
    if (sqlite3_prepare_v2(g_db,
            "INSERT INTO auth_log(name, iat, exp) VALUES(?1, ?2, ?3)",
            -1, &st, nullptr) != SQLITE_OK)
        return;

    // insert the log into the database
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, iat);
    sqlite3_bind_int64(st, 3, exp);
    sqlite3_step(st);
    sqlite3_finalize(st);
}
