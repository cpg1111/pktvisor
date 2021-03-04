#ifdef __BCC__
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#else
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_BPF_HASH_SIZE 10240 // default BCC hash map size, defined for libbpf compatibility
#endif
#include <net/sock.h>


struct ipv4_connect_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
};

struct ipv6_connect_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 dport;
    char task[TASK_COMM_LEN];
};

struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 dport;
};

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 dport;
};

#ifdef __BCC__
BPF_HASH(currsock, u32, struct sock *);

BPF_PERF_OUTPUT(ipv4_connect_events);

BPF_PERF_OUTPUT(ipv6_connect_events);

BPF_HASH(ipv4_connect_count, struct ipv4_flow_key_t);

BPF_HASH(ipv6_connect_count, struct ipv6_flow_key_t);
#else
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BPF_HASH_SIZE);
    __type(key, u32);
    __type(value, struct sock *);
} currsock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ipv4_connect_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ipv6_connect_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BPF_HASH_SIZE);
    __type(key, u32);
    __type(value, struct ipv4_flow_key_t);
} ipv4_connect_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BPF_HASH_SIZE);
    __type(key, u32);
    __type(value, struct ipv6_flow_key_t);
} ipv6_connect_count SEC(".maps");
#endif

#ifdef __BCC__
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
#else
static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
#endif
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;

#ifdef __BCC__
    // TODO bcc pid filter
#else
    if (pid_filter && pid != pid_filter)
        return 0;
#endif
    
    __u32 uid = bpf_get_current_uid_gid();
#ifdef __BCC__
    // TODO bc uid filter
#else
    if (uid_filter != (uid_t) -1 && uid != uid_filter)
        return 0;
#endif
    
#ifdef __BCC__
    currsock.update(&tid, &sk);
#else
    bpf_map_update_elem(&currsock, &tid, &sk, 0);
#endif
    return 0;
}

static  __always_inline void count_v4(struct sock *sk, __u16 dport)
{
    struct ipv4_flow_key key = {};
    static __u64 zero;
    __u64 *val;

    BPF_CORE_READ_INTO(&key.saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&key.daddr, sk, __sk_common.skc_daddr);
    key.dport = dport;
    val = bpf_map_lookup_or_try_init(&ipv4_count, &key, &zero);
    if (val)
        __atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void count_v6(struct sock *sk, __u16 dport)
{
    struct ipv6_flow_key key = {};
    static const __u64 zero;
    __u64 *val;

    BPF_CORE_READ_INTO(&key.saddr, sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&key.daddr, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    key.dport = dport;

    val = bpf_map_lookup_or_try_init(&ipv6_count, &key, &zero);
    if (val)
        __atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline void
trace_v4(struct pt_regs *ctx, pid_t pid, struct sock *sk, __u16 dport)
{
    struct event event = {};

    event.af = AF_INET;
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid();
    event.ts_us = bpf_ktime_get_ns() / 1000;
    BPF_CORE_READ_INTO(&event.saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event.daddr_v4, sk, __sk_common.skc_daddr);
    event.dport = dport;
    bpf_get_current_comm(event.task, sizeof(event.task));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &event, sizeof(event));
}

static __always_inline void
trace_v6(struct pt_regs *ctx, pid_t pid, struct sock *sk, __u16 dport)
{
    struct event event = {};

    event.af = AF_INET6;
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid();
    event.ts_us = bpf_ktime_get_ns() / 1000;
    BPF_CORE_READ_INTO(&event.saddr_v6, sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&event.daddr_v6, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    event.dport = dport;
    bpf_get_current_comm(event.task, sizeof(event.task));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &event, sizeof(event));
}

#ifdef __BCC__
static int trace_connect_return(struct pt_regs *ctx, short ip_ver)
#else
static __alwaysinline int
exit_tcp_connect(struct pt_regs *ctx, int ret, int ip_ver)
#endif
{
#ifdef __BCC__
    int ret = PT_REGS_RC(ctx);
#endif
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;

    struct sock **entry;
    struct sock *sk;
    __u16 dport;

#ifdef __BCC__
    entry = currsock.lookup(&tid);
    
    if (entry == 0)
        return 0;
    if (ret != 0) {
        currsock.delete(&tid);
        return 0;
    }
#else
    bpf_map_lookup_elem(&currsock, &tid);
    if (!entry)
        return 0;

    if (ret)
        goto end;
#endif
    sk = *entry;

#ifdef __BCC__
    dport = sk->__sk_common.skc_dport;
    // TODO port filter
#else
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    for (int i = 0; i < ports_filter_len; i++) {
        if (dport == ports_filter[i])
            goto end;
    }
#endif

    if (count) {
        if (ip_ver == 4) {
            count_v4(sk, dport);
        } else {
            count_v6(sk, dport);
        }
    } else {
        if (ip_ver == 4) {
            trace_v4(ctx, pid, sk, dport);
        } else {
            trace_v6(ctx, pid, sk, dport);
        }
    }

#ifdef __BCC__
    currsock.delete(&tid);
#else
end:
    bpf_map_delete_elem(&currsock, &tid);
#endif
    return 0;
}

#ifdef __BCC__
int trace_connect_v4_return(struct pt_regs *ctx) {
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx) {
    return trace_connect_return(ctx, 6);
}
#else
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk) {
    return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret) {
    return exit_tcp_connect(ctx, ret, 4);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struck sock *sk) {
    return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_ret, int ret) {
    return exit_tcp_connect(ctx, ret, 6);
}
#endif

