#ifndef EVENT_SCHEMA_H
#define EVENT_SCHEMA_H

#define COMM_LEN 16
#define MAX_FN 256
#define MAX_CMD 256

enum event_type {
    evt_fork = 1,
    evt_exec = 2,
    evt_exit = 3,
    evt_file = 4,
    evt_net  = 5,
};

struct event {
    unsigned int type;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned long long ts_ns;
    char comm[COMM_LEN];
    char p_comm[COMM_LEN];
    char fn[MAX_FN];
    char cmd[MAX_CMD];
};

#endif