/* db.h
 * keep this narrow so we can swap sqlite out later */
#ifndef DB_H
#define DB_H

#ifdef __cplusplus
extern "C" {
#endif

int db_open(const char *path);

#ifdef __cplusplus
}
#endif

#endif
