#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "include/event_schema.h"
#include "sensor.skel.h"

static volatile int exiting = 0;
static void sig_handler(int sig) {exiting = 1;}

static int handle_event(void *ctx, void *data, size_t len){
    const struct event *e = data;

    if (len < sizeof(*e)) {
        fprintf(stderr, "short event: %zu\n", len);
        return 0;
    }
    printf("type: %u pid: %u ppid: %u uid: %u comm: %s p_comm: %s fn: %s\n cmd: %s\n",
                e->type, e->pid, e->ppid, e->uid, e->comm, e->p_comm, e->fn, e->cmd);
    
    return 0;
}

int main(void)
{
    struct sensor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = sensor_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

    err = sensor_bpf__attach(skel);
    if (err) { fprintf(stderr, "attach failed: %d\n", err); goto cleanup; }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if(!rb) { fprintf(stderr, "ringbuf create failed\n"); goto cleanup; }

    while(!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) break;
    }

cleanup:
    ring_buffer__free(rb);
    sensor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}