#ifndef DB_H
#define DB_H

#include <sqlite3.h>

int      db_open(const char *path);
void     db_close(void);
sqlite3 *db_handle(void);

#endif
