#ifndef RUNNER_H
#define RUNNER_H

#include <stdint.h>
#include "../bpf/include/event_schema.h"

void rule_runner_init(void);
void rule_runner_evaluate(const struct event *e, int64_t start_ts, int64_t event_id);

#endif
