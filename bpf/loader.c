#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "include/event_schema.h"
#include "sensor.skel.h"
#include "../db/db.h"
#include "../db/process_db.h"
#include "../db/event_log.h"
#include "../db/graph.h"
#include "../engine/runner.h"

#define DB_PATH "edr.db"

static volatile int exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

static int handle_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    const struct event *e = data;
    if (len < sizeof(*e)) {
        fprintf(stderr, "short event: %zu\n", len);
        return 0;
    }

    int64_t start_ts = process_db_upsert(e);
    int64_t ev_id    = event_log_insert(e, start_ts);
    graph_insert_edge(e, start_ts, ev_id);
    rule_runner_evaluate(e, start_ts, ev_id);
    return 0;
}

int main(void)
{
    struct sensor_bpf *skel = NULL;
    struct ring_buffer *rb  = NULL;
    int err = 0;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    if (db_open(DB_PATH) < 0) return 1;
    process_db_init();
    event_log_init();
    graph_init();
    rule_runner_init();

    skel = sensor_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "open/load failed\n"); goto cleanup; }

    err = sensor_bpf__attach(skel);
    if (err) { fprintf(stderr, "attach failed: %d\n", err); goto cleanup; }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ringbuf create failed\n"); goto cleanup; }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) break;
    }
    err = 0;

cleanup:
    ring_buffer__free(rb);
    sensor_bpf__destroy(skel);
    db_close();
    return err < 0 ? -err : err;
}
