#ifndef RULE_H
#define RULE_H

#include <stdint.h>
#include "../bpf/include/event_schema.h"

typedef struct {
    const char *id;
    int         severity;  /* 1=INFO 2=WARN 3=HIGH 4=CRIT */
    int        (*evaluate)(const struct event *e, int64_t start_ts, int64_t event_id);
} rule_t;

#endif
