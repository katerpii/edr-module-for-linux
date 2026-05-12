#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "include/event_schema.h"

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
    bpf_printk("exec pid=%u fn_ret=%s cmd_ret=%s len=%u arg_start=%lx arg_end=%lx\n",
           e->pid, e->fn, e->cmd, len, arg_start, arg_end);
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