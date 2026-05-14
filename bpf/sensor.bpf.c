#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "include/event_schema.h"
#include "include/sock_state.h"

#ifndef TCP_SYN_SENT
#define TCP_SYN_SENT 2
#endif

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork,
             struct task_struct *p,
             struct task_struct *c)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->type = evt_fork;
    e->pid = BPF_CORE_READ(c, tgid);
    e->ppid = BPF_CORE_READ(p, tgid);
    e->uid = BPF_CORE_READ(c, cred, uid.val) & 0xffffffff;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), BPF_CORE_READ(c, comm));
    bpf_probe_read_kernel_str(&e->p_comm, sizeof(e->p_comm), BPF_CORE_READ(p, comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec,
             struct task_struct *t,
             pid_t old_pid,
             struct linux_binprm *bprm){

    struct event *e;
    struct mm_struct *mm;
    unsigned long arg_start, arg_end, len;

    const char *fn = BPF_CORE_READ(bprm, filename);
    u64 pid = BPF_CORE_READ(t, tgid);
    u32 uid = BPF_CORE_READ(t, cred, uid.val);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    
    e->type = evt_exec;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(t, real_parent, tgid);
    e->uid = uid;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), BPF_CORE_READ(t, comm));
    bpf_probe_read_kernel_str(e->p_comm, sizeof(e->p_comm), BPF_CORE_READ(t, real_parent, comm));
    bpf_probe_read_kernel_str(e->fn, sizeof(e->fn), fn);

    
    mm = BPF_CORE_READ(t, mm);
    if (!mm) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    arg_start = BPF_CORE_READ(mm, arg_start);
    arg_end   = BPF_CORE_READ(mm, arg_end);
    if (arg_end <= arg_start) { bpf_ringbuf_discard(e, 0); return 0; }

    len = arg_end - arg_start;
    if (len > sizeof(e->cmd) - 1) len = sizeof(e->cmd) - 1;
    bpf_probe_read_user(e->cmd, len, (void*)arg_start);
    e->cmd[len] = '\0';
    {
        unsigned int i;
        #pragma unroll
        for (i = 0; i < sizeof(e->cmd) - 1; i++) {
            if (i >= len) break;
            if (e->cmd[i] == '\0') e->cmd[i] = ' ';
        }
    }
    bpf_printk("exec pid=%u fn=%s cmd=%s\n", e->pid, e->fn, e->cmd);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *t)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->type = evt_exit;
    e->pid = BPF_CORE_READ(t, tgid);
    e->ppid = BPF_CORE_READ(t, real_parent, tgid);
    e->uid = BPF_CORE_READ(t, cred, uid.val) & 0xffffffff;
    e->ts_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);
    return 0;   
}


SEC("tracepoint/sock/inet_sock_set_state")
int BPF_PROG(tp_inet_sock_set_state, struct inet_sock_state_args *args)
{
    if (args->newstate != TCP_SYN_SENT) return 0;
    if (args->protocol != IPPROTO_TCP) return 0;
    
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->type = evt_net;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // set network field
    __builtin_memcpy(&e->saddr, args->saddr, 4);
    __builtin_memcpy(&e->daddr, args->daddr, 4); 
    e->sport = args->sport;
    e->dport = args->dport;
    e->proto = IPPROTO_TCP;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk, 
                          struct msghdr *msg,
                          size_t len)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->type = evt_net;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->proto = IPPROTO_UDP;

    __u32 daddr = 0;
    __u16 dport = 0;
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

    e->daddr = daddr;
    e->dport = bpf_ntohs(dport);

    bpf_ringbuf_submit(e, 0);
    return 0;
}