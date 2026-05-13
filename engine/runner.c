#include <stdio.h>
#include <sqlite3.h>
#include "rule.h"
#include "runner.h"
#include "../db/db.h"
#include "rules/r001_shell_from_service.h"

/* ── 룰 테이블: 새 룰 추가 시 여기에만 등록 ──────────────────── */
static const rule_t *RULES[] = {
    &r001_shell_from_service,
    NULL,
};

static sqlite3_stmt *s_alert;

void rule_runner_init(void)
{
    sqlite3_prepare_v2(db_handle(),
        "INSERT INTO alerts(ts,rule_id,severity,pid,start_ts,event_id)"
        " VALUES(?,?,?,?,?,?)",
        -1, &s_alert, NULL);
}

static void alert_insert(const rule_t *r, const struct event *e,
                         int64_t start_ts, int64_t event_id)
{
    fprintf(stderr, "[ALERT] %s sev=%d pid=%u comm=%s fn=%s\n",
            r->id, r->severity, e->pid, e->comm, e->fn);

    sqlite3_reset(s_alert);
    sqlite3_bind_int64(s_alert, 1, (int64_t)e->ts_ns);
    sqlite3_bind_text (s_alert, 2, r->id,     -1, SQLITE_STATIC);
    sqlite3_bind_int  (s_alert, 3, r->severity);
    sqlite3_bind_int64(s_alert, 4, e->pid);
    sqlite3_bind_int64(s_alert, 5, start_ts);
    sqlite3_bind_int64(s_alert, 6, event_id);
    sqlite3_step(s_alert);
}

void rule_runner_evaluate(const struct event *e, int64_t start_ts, int64_t event_id)
{
    for (int i = 0; RULES[i]; i++) {
        const rule_t *r = RULES[i];
        if (r->evaluate(e, start_ts, event_id))
            alert_insert(r, e, start_ts, event_id);
    }
}
