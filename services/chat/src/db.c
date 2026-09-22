/* db.c
 *
 * persistence - users, rooms, history. tables are over in schema.sql.
 *
 * sqlite for now. if it turns out to be a pain, this file and db.h
 * should be the only things that need rewriting.
 *
 * don't share a handle across fork(), open one per process.
 */
#include "db.h"

int db_open(const char *path) {
  (void)path;

  /* TODO sqlite3_open, then apply schema.sql if we just created it */
  return -1;
}
