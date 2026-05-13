#include <stdio.h>
#include <sqlite3.h>
#include "db.h"
#include "process_db.h"

static sqlite3_stmt *s_fork_insert;
static sqlite3_stmt *s_exec_update;
static sqlite3_stmt *s_exec_bootstrap;
static sqlite3_stmt *s_exit_update;
static sqlite3_stmt *s_active_lookup;

int process_db_init(void)
{
    sqlite3 *db = db_handle();

    /* evt_fork: 새 프로세스 레코드 생성 */
    sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO processes(pid,start_ts,ppid,uid,comm)"
        " VALUES(?,?,?,?,?)",
        -1, &s_fork_insert, NULL);

    /* evt_exec: 살아있는 레코드의 comm/exe 갱신 */
    sqlite3_prepare_v2(db,
        "UPDATE processes SET comm=?,exe=? WHERE pid=? AND end_ts IS NULL",
        -1, &s_exec_update, NULL);

    /* EDR 기동 전 이미 실행 중이던 프로세스 (fork 이벤트 누락) 부트스트랩 */
    sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO processes(pid,start_ts,uid,comm,exe)"
        " VALUES(?,?,?,?,?)",
        -1, &s_exec_bootstrap, NULL);

    /* evt_exit: end_ts 기록 */
    sqlite3_prepare_v2(db,
        "UPDATE processes SET end_ts=? WHERE pid=? AND end_ts IS NULL",
        -1, &s_exit_update, NULL);

    /* 살아있는 프로세스의 start_ts 조회 */
    sqlite3_prepare_v2(db,
        "SELECT start_ts FROM processes"
        " WHERE pid=? AND end_ts IS NULL"
        " ORDER BY start_ts DESC LIMIT 1",
        -1, &s_active_lookup, NULL);

    return 0;
}

int64_t process_db_active_start(uint32_t pid)
{
    sqlite3_reset(s_active_lookup);
    sqlite3_bind_int64(s_active_lookup, 1, pid);
    if (sqlite3_step(s_active_lookup) == SQLITE_ROW)
        return sqlite3_column_int64(s_active_lookup, 0);
    return -1;
}

int64_t process_db_upsert(const struct event *e)
{
    switch (e->type) {

    case evt_fork:
        sqlite3_reset(s_fork_insert);
        sqlite3_bind_int64(s_fork_insert, 1, e->pid);
        sqlite3_bind_int64(s_fork_insert, 2, e->ts_ns);   /* start_ts = fork 시각 */
        sqlite3_bind_int64(s_fork_insert, 3, e->ppid);
        sqlite3_bind_int64(s_fork_insert, 4, e->uid);
        sqlite3_bind_text (s_fork_insert, 5, e->comm, -1, SQLITE_STATIC);
        sqlite3_step(s_fork_insert);
        return (int64_t)e->ts_ns;

    case evt_exec: {
        sqlite3_reset(s_exec_update);
        sqlite3_bind_text (s_exec_update, 1, e->comm, -1, SQLITE_STATIC);
        sqlite3_bind_text (s_exec_update, 2, e->fn,   -1, SQLITE_STATIC);
        sqlite3_bind_int64(s_exec_update, 3, e->pid);
        sqlite3_step(s_exec_update);

        if (sqlite3_changes(db_handle()) == 0) {
            /* 해당 pid의 fork를 못 봤음 → 부트스트랩 레코드 삽입 */
            sqlite3_reset(s_exec_bootstrap);
            sqlite3_bind_int64(s_exec_bootstrap, 1, e->pid);
            sqlite3_bind_int64(s_exec_bootstrap, 2, e->ts_ns);
            sqlite3_bind_int64(s_exec_bootstrap, 3, e->uid);
            sqlite3_bind_text (s_exec_bootstrap, 4, e->comm, -1, SQLITE_STATIC);
            sqlite3_bind_text (s_exec_bootstrap, 5, e->fn,   -1, SQLITE_STATIC);
            sqlite3_step(s_exec_bootstrap);
        }
        return process_db_active_start(e->pid);
    }

    case evt_exit: {
        /* end_ts 업데이트 전에 start_ts를 먼저 가져온다 */
        int64_t st = process_db_active_start(e->pid);
        sqlite3_reset(s_exit_update);
        sqlite3_bind_int64(s_exit_update, 1, e->ts_ns);
        sqlite3_bind_int64(s_exit_update, 2, e->pid);
        sqlite3_step(s_exit_update);
        return st;
    }

    default:
        return process_db_active_start(e->pid);
    }
}
