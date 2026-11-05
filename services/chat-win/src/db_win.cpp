/* db_win.cpp - sqlite, not wired up yet */
#include "db.h"

int db_open(const char *path) {
  (void)path;
  /* TODO: sqlite3_open, apply schema.sql on first create */
  return -1;
}
