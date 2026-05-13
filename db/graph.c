#include <stdio.h>
#include <sqlite3.h>
#include "db.h"
#include "graph.h"
#include "process_db.h"

static sqlite3_stmt *s_insert;

int graph_init(void)
{
    int rc = sqlite3_prepare_v2(db_handle(),
        "INSERT INTO graph_edges"
        "(ts,edge_type,src_pid,src_start,dst_pid,dst_start,artifact,event_id)"
        " VALUES(?,?,?,?,?,?,?,?)",
        -1, &s_insert, NULL);
    return rc == SQLITE_OK ? 0 : -1;
}

static int insert_edge(int64_t ts, const char *type,
                       int64_t src_pid, int64_t src_start,
                       int64_t dst_pid, int64_t dst_start,
                       const char *artifact, int64_t event_id)
{
    sqlite3_reset(s_insert);
    sqlite3_bind_int64(s_insert, 1, ts);
    sqlite3_bind_text (s_insert, 2, type, -1, SQLITE_STATIC);
    sqlite3_bind_int64(s_insert, 3, src_pid);
    sqlite3_bind_int64(s_insert, 4, src_start);

    if (dst_pid >= 0) {
        sqlite3_bind_int64(s_insert, 5, dst_pid);
        sqlite3_bind_int64(s_insert, 6, dst_start);
    } else {
        sqlite3_bind_null(s_insert, 5);
        sqlite3_bind_null(s_insert, 6);
    }

    if (artifact && artifact[0])
        sqlite3_bind_text(s_insert, 7, artifact, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(s_insert, 7);

    sqlite3_bind_int64(s_insert, 8, event_id);
    return sqlite3_step(s_insert) == SQLITE_DONE ? 0 : -1;
}

int graph_insert_edge(const struct event *e, int64_t src_start, int64_t event_id)
{
    switch (e->type) {

    case evt_fork: {
        /* fork 엣지: ppid → child pid
         * src_start = 부모의 현재 start_ts,  dst_start = 자식의 start_ts(=src_start 인자) */
        int64_t ppid_start = process_db_active_start(e->ppid);
        if (ppid_start < 0) ppid_start = 0;  /* 부모 레코드 없음 (PID 1 등) */
        insert_edge(e->ts_ns, "fork",
                    e->ppid, ppid_start,
                    e->pid,  src_start,
                    NULL, event_id);
        break;
    }

    case evt_exec:
        /* exec 엣지: pid → artifact(실행 파일 경로) */
        insert_edge(e->ts_ns, "exec",
                    e->pid, src_start,
                    -1, -1,
                    e->fn, event_id);
        break;

    case evt_file:
        insert_edge(e->ts_ns, "open",
                    e->pid, src_start,
                    -1, -1,
                    e->fn, event_id);
        break;

    case evt_net:
        /* fn 필드에 "ip:port" 형식으로 저장 (probe 구현 시 약속) */
        insert_edge(e->ts_ns, "connect",
                    e->pid, src_start,
                    -1, -1,
                    e->fn, event_id);
        break;

    default:
        break;
    }
    return 0;
}

/* ── IR 쿼리 ───────────────────────────────────────────────────── */

void graph_print_ancestry(uint32_t pid, int64_t start_ts)
{
    static const char SQL[] =
        "WITH RECURSIVE anc(pid,start_ts,ppid,comm,exe,depth) AS ("
        "  SELECT pid,start_ts,ppid,comm,exe,0 FROM processes"
        "  WHERE pid=?1 AND start_ts=?2"
        "  UNION ALL"
        "  SELECT p.pid,p.start_ts,p.ppid,p.comm,p.exe,a.depth+1"
        "  FROM processes p JOIN anc a ON p.pid=a.ppid"
        "  WHERE a.depth<50"
        ")"
        "SELECT pid,comm,exe,depth FROM anc ORDER BY depth DESC;";

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db_handle(), SQL, -1, &st, NULL);
    sqlite3_bind_int64(st, 1, pid);
    sqlite3_bind_int64(st, 2, start_ts);

    while (sqlite3_step(st) == SQLITE_ROW) {
        int         d    = sqlite3_column_int (st, 3);
        int         p    = sqlite3_column_int (st, 0);
        const char *comm = (const char *)sqlite3_column_text(st, 1);
        const char *exe  = (const char *)sqlite3_column_text(st, 2);
        printf("%*s[%d] %s (%s)\n", d * 2, "", p,
               comm ? comm : "?", exe ? exe : "?");
    }
    sqlite3_finalize(st);
}

void graph_print_blast_radius(uint32_t root_pid, int64_t start_ts)
{
    static const char SQL[] =
        "WITH RECURSIVE tree(pid,start_ts,depth) AS ("
        "  SELECT ?1,?2,0"
        "  UNION ALL"
        "  SELECT ge.dst_pid,ge.dst_start,t.depth+1"
        "  FROM graph_edges ge JOIN tree t"
        "    ON ge.src_pid=t.pid AND ge.src_start=t.start_ts"
        "  WHERE ge.edge_type='fork' AND t.depth<50"
        ")"
        "SELECT DISTINCT p.pid,p.comm,p.exe,tree.depth"
        "  FROM tree JOIN processes p USING(pid,start_ts)"
        "  ORDER BY tree.depth,p.pid;";

    sqlite3_stmt *st;
    sqlite3_prepare_v2(db_handle(), SQL, -1, &st, NULL);
    sqlite3_bind_int64(st, 1, root_pid);
    sqlite3_bind_int64(st, 2, start_ts);

    while (sqlite3_step(st) == SQLITE_ROW) {
        int         d    = sqlite3_column_int (st, 3);
        int         p    = sqlite3_column_int (st, 0);
        const char *comm = (const char *)sqlite3_column_text(st, 1);
        const char *exe  = (const char *)sqlite3_column_text(st, 2);
        printf("%*s[%d] %s (%s)\n", d * 2, "", p,
               comm ? comm : "?", exe ? exe : "?");
    }
    sqlite3_finalize(st);
}
