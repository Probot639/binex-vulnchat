/* db.h - storage layer. keep this interface narrow, the whole point is
 * that we can rip sqlite out later without touching the server code. */
#ifndef DB_H
#define DB_H

int db_open(const char *path);

#endif /* DB_H */
