#ifndef GRAPH_H
#define GRAPH_H

#include <stdint.h>
#include "../bpf/include/event_schema.h"

int graph_init(void);

/* 이벤트 타입에 맞는 엣지를 graph_edges에 삽입한다. */
int graph_insert_edge(const struct event *e, int64_t src_start, int64_t event_id);

/* IR 쿼리: 조상 체인 (루트까지) */
void graph_print_ancestry(uint32_t pid, int64_t start_ts);

/* IR 쿼리: fork 기반 자손 폭발 반경 */
void graph_print_blast_radius(uint32_t root_pid, int64_t start_ts);

#endif
