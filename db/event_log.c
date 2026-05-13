#include <stdio.h>
#include <sqlite3.h>
#include "db.h"
#include "event_log.h"

static sqlite3_stmt *s_insert;

int event_log_init(void)
{
    int rc = sqlite3_prepare_v2(db_handle(),
        "INSERT INTO events(ts,type,pid,start_ts,ppid,uid,comm,p_comm,fn,cmd)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        -1, &s_insert, NULL);
    return rc == SQLITE_OK ? 0 : -1;
}

int64_t event_log_insert(const struct event *e, int64_t start_ts)
{
    sqlite3 *db = db_handle();

    sqlite3_reset(s_insert);
    sqlite3_bind_int64(s_insert,  1, e->ts_ns);
    sqlite3_bind_int  (s_insert,  2, e->type);
    sqlite3_bind_int64(s_insert,  3, e->pid);
    sqlite3_bind_int64(s_insert,  4, start_ts);
    sqlite3_bind_int64(s_insert,  5, e->ppid);
    sqlite3_bind_int64(s_insert,  6, e->uid);
    sqlite3_bind_text (s_insert,  7, e->comm,   -1, SQLITE_STATIC);
    sqlite3_bind_text (s_insert,  8, e->p_comm, -1, SQLITE_STATIC);
    sqlite3_bind_text (s_insert,  9, e->fn,     -1, SQLITE_STATIC);
    sqlite3_bind_text (s_insert, 10, e->cmd,    -1, SQLITE_STATIC);

    if (sqlite3_step(s_insert) != SQLITE_DONE) {
        fprintf(stderr, "event_log_insert: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    return sqlite3_last_insert_rowid(db);
}
