PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;

CREATE TABLE IF NOT EXISTS processes (
    pid       INTEGER NOT NULL,
    start_ts  INTEGER NOT NULL,  -- evt_fork ts_ns (PID 재사용 구분자)
    ppid      INTEGER,
    uid       INTEGER,
    comm      TEXT,
    exe       TEXT,              -- exec 이후 갱신
    end_ts    INTEGER,           -- NULL = 아직 살아있음
    exit_code INTEGER,
    PRIMARY KEY (pid, start_ts)
);
CREATE INDEX IF NOT EXISTS idx_proc_ppid   ON processes(ppid);
CREATE INDEX IF NOT EXISTS idx_proc_active ON processes(pid) WHERE end_ts IS NULL;

CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    type     INTEGER NOT NULL,   -- enum event_type
    pid      INTEGER NOT NULL,
    start_ts INTEGER NOT NULL,   -- → processes(pid, start_ts)
    ppid     INTEGER,
    uid      INTEGER,
    comm     TEXT,
    p_comm   TEXT,
    fn       TEXT,
    cmd      TEXT
);
CREATE INDEX IF NOT EXISTS idx_ev_pid  ON events(pid, start_ts);
CREATE INDEX IF NOT EXISTS idx_ev_ts   ON events(ts);
CREATE INDEX IF NOT EXISTS idx_ev_type ON events(type);

CREATE TABLE IF NOT EXISTS graph_edges (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    edge_type TEXT NOT NULL,     -- 'fork' | 'exec' | 'open' | 'connect'
    src_pid   INTEGER NOT NULL,
    src_start INTEGER NOT NULL,
    dst_pid   INTEGER,           -- fork 엣지 전용
    dst_start INTEGER,
    artifact  TEXT,              -- exec/open/connect: 경로 또는 ip:port
    event_id  INTEGER REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS idx_edge_src  ON graph_edges(src_pid, src_start);
CREATE INDEX IF NOT EXISTS idx_edge_dst  ON graph_edges(dst_pid, dst_start);
CREATE INDEX IF NOT EXISTS idx_edge_type ON graph_edges(edge_type);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    rule_id  TEXT NOT NULL,
    severity INTEGER NOT NULL,   -- 1=INFO 2=WARN 3=HIGH 4=CRIT
    pid      INTEGER,
    start_ts INTEGER,
    event_id INTEGER REFERENCES events(id),
    context  TEXT                -- JSON 탐지 근거 스냅샷
);
