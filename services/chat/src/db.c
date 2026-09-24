/* db.c - sqlite, one handle per process (don't share across fork) */
#include "db.h"

int db_open(const char *path) {
  (void)path;
  /* TODO: sqlite3_open, apply schema.sql on first create */
  return -1;
}
