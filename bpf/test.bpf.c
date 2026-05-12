#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LISENCE SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} events SEC(".maps");

struct event {
    __u32 pid;
    char comm[16];
};

SEC("tp/syscall/sys_enter_execve")
int handle_execve(void *ctx){
    
}