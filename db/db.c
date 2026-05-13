#include <stdio.h>
#include <sqlite3.h>
#include "db.h"

static sqlite3 *g_db = NULL;

/* schema.sql과 동일 내용 — 빌드 시 외부 파일 의존 없이 self-contained */
static const char SCHEMA[] =
    "PRAGMA journal_mode=WAL;"
    "PRAGMA synchronous=NORMAL;"
    "CREATE TABLE IF NOT EXISTS processes("
    "  pid INTEGER NOT NULL,"
    "  start_ts INTEGER NOT NULL,"
    "  ppid INTEGER,"
    "  uid INTEGER,"
    "  comm TEXT,"
    "  exe TEXT,"
    "  end_ts INTEGER,"
    "  exit_code INTEGER,"
    "  PRIMARY KEY(pid,start_ts)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_proc_ppid   ON processes(ppid);"
    "CREATE INDEX IF NOT EXISTS idx_proc_active ON processes(pid) WHERE end_ts IS NULL;"
    "CREATE TABLE IF NOT EXISTS events("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts INTEGER NOT NULL,"
    "  type INTEGER NOT NULL,"
    "  pid INTEGER NOT NULL,"
    "  start_ts INTEGER NOT NULL,"
    "  ppid INTEGER,"
    "  uid INTEGER,"
    "  comm TEXT,"
    "  p_comm TEXT,"
    "  fn TEXT,"
    "  cmd TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_ev_pid  ON events(pid,start_ts);"
    "CREATE INDEX IF NOT EXISTS idx_ev_ts   ON events(ts);"
    "CREATE INDEX IF NOT EXISTS idx_ev_type ON events(type);"
    "CREATE TABLE IF NOT EXISTS graph_edges("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts INTEGER NOT NULL,"
    "  edge_type TEXT NOT NULL,"
    "  src_pid INTEGER NOT NULL,"
    "  src_start INTEGER NOT NULL,"
    "  dst_pid INTEGER,"
    "  dst_start INTEGER,"
    "  artifact TEXT,"
    "  event_id INTEGER REFERENCES events(id)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_edge_src  ON graph_edges(src_pid,src_start);"
    "CREATE INDEX IF NOT EXISTS idx_edge_dst  ON graph_edges(dst_pid,dst_start);"
    "CREATE INDEX IF NOT EXISTS idx_edge_type ON graph_edges(edge_type);"
    "CREATE TABLE IF NOT EXISTS alerts("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts INTEGER NOT NULL,"
    "  rule_id TEXT NOT NULL,"
    "  severity INTEGER NOT NULL,"
    "  pid INTEGER,"
    "  start_ts INTEGER,"
    "  event_id INTEGER REFERENCES events(id),"
    "  context TEXT"
    ");";

int db_open(const char *path)
{
    int rc = sqlite3_open(path, &g_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_open: %s\n", sqlite3_errmsg(g_db));
        return -1;
    }

    char *err = NULL;
    rc = sqlite3_exec(g_db, SCHEMA, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db schema init: %s\n", err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

void db_close(void)
{
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
}

sqlite3 *db_handle(void) { return g_db; }
