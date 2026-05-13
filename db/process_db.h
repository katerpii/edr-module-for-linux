#ifndef PROCESS_DB_H
#define PROCESS_DB_H

#include <stdint.h>
#include "../bpf/include/event_schema.h"

int     process_db_init(void);

/* processes 테이블을 이벤트에 따라 갱신하고,
 * 해당 pid의 start_ts를 반환한다. 실패 시 -1. */
int64_t process_db_upsert(const struct event *e);

/* 현재 살아있는 프로세스의 start_ts 반환. 없으면 -1. */
int64_t process_db_active_start(uint32_t pid);

#endif
