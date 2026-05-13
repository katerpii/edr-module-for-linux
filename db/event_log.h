#ifndef EVENT_LOG_H
#define EVENT_LOG_H

#include <stdint.h>
#include "../bpf/include/event_schema.h"

int     event_log_init(void);

/* events 테이블에 원본 이벤트를 삽입. 생성된 row id 반환, 실패 시 -1. */
int64_t event_log_insert(const struct event *e, int64_t start_ts);

#endif
