#include "include/packrat_bpf_helpers.h"

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TCP_SYN_SENT 2
#define EVENT_VERSION 1
#define EVENT_SIZE 80
#define EVENT_TCP_CONNECT 1
#define EVENT_TCP_ACCEPT 2
#define EVENT_UDP_SEND 3
#define EVENT_UDP_RECEIVE 4
#define UDP_DEDUP_NS 250000000ULL

struct trace_entry {
    __u16 type;
    __u8 flags;
    __u8 preempt_count;
    __u32 pid;
};

/* Layout exported by tracepoint sock/inet_sock_set_state. */
struct inet_sock_set_state_ctx {
    struct trace_entry common;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct in6_addr {
    __u8 s6_addr[16];
} __attribute__((preserve_access_index));

struct sock_common {
    __u32 skc_daddr;
    __u32 skc_rcv_saddr;
    __u16 skc_dport;
    __u16 skc_num;
    __u16 skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
    unsigned long ax;
} __attribute__((preserve_access_index));
#define PT_REGS_RETURN(ctx) BPF_CORE_READ(ctx, ax)
#elif defined(__TARGET_ARCH_arm64)
struct pt_regs {
    unsigned long regs[31];
} __attribute__((preserve_access_index));
#define PT_REGS_RETURN(ctx) BPF_CORE_READ(ctx, regs[0])
#else
#error "set __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif

#define BPF_CORE_READ(source, field)                                            \
    ({                                                                          \
        typeof((source)->field) value = {};                                     \
        bpf_probe_read_kernel(                                                  \
            &value, sizeof(value),                                              \
            __builtin_preserve_access_index(&(source)->field));                 \
        value;                                                                  \
    })

struct socket_event {
    __u16 version;
    __u16 size;
    __u32 pid;
    __u32 uid;
    __u16 family;
    __u8 protocol;
    __u8 flags;
    __u16 local_port;
    __u16 remote_port;
    __u32 reserved;
    __u64 timestamp_ns;
    char comm[16];
    __u8 local_addr[16];
    __u8 remote_addr[16];
};

_Static_assert(sizeof(struct socket_event) == EVENT_SIZE,
               "socket event ABI size changed");
_Static_assert(__builtin_offsetof(struct socket_event, local_addr) == 48,
               "socket event ABI address offset changed");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} LOST_EVENTS SEC(".maps");

struct recent_socket_key {
    __u64 pid_tgid;
    __u64 socket_address;
    __u8 kind;
    __u8 padding[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct recent_socket_key);
    __type(value, __u64);
} RECENT_FD_EVENTS SEC(".maps");

static __always_inline void account_loss(void) {
    __u32 key = 0;
    __u64 *lost = bpf_map_lookup_elem(&LOST_EVENTS, &key);
    if (lost)
        __sync_fetch_and_add(lost, 1);
}

static __always_inline int emit_socket_event(__u8 kind, __u8 protocol,
                                              struct sock *sk,
                                              int deduplicate) {
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == 0)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    if (deduplicate) {
        struct recent_socket_key key = {
            .pid_tgid = pid_tgid,
            .socket_address = (__u64)sk,
            .kind = kind,
        };
        __u64 *previous = bpf_map_lookup_elem(&RECENT_FD_EVENTS, &key);
        if (previous && now - *previous < UDP_DEDUP_NS)
            return 0;
        bpf_map_update_elem(&RECENT_FD_EVENTS, &key, &now, BPF_ANY);
    }

    struct socket_event *event = bpf_ringbuf_reserve(&EVENTS, sizeof(*event), 0);
    if (!event) {
        account_loss();
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->version = EVENT_VERSION;
    event->size = EVENT_SIZE;
    event->pid = pid;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->family = family;
    event->protocol = protocol;
    event->flags = kind;
    event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->remote_port = __builtin_bswap16(
        BPF_CORE_READ(sk, __sk_common.skc_dport));
    event->timestamp_ns = now;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    if (event->family == AF_INET) {
        __u32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(event->local_addr, &local, sizeof(local));
        __builtin_memcpy(event->remote_addr, &remote, sizeof(remote));
    } else if (event->family == AF_INET6) {
        bpf_probe_read_kernel(
            event->local_addr, sizeof(event->local_addr),
            __builtin_preserve_access_index(
                &sk->__sk_common.skc_v6_rcv_saddr));
        bpf_probe_read_kernel(
            event->remote_addr, sizeof(event->remote_addr),
            __builtin_preserve_access_index(
                &sk->__sk_common.skc_v6_daddr));
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int packrat_inet_sock_state(struct inet_sock_set_state_ctx *ctx) {
    if (ctx->newstate != TCP_SYN_SENT || ctx->protocol != IPPROTO_TCP)
        return 0;
    if (ctx->family != AF_INET && ctx->family != AF_INET6)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == 0)
        return 0;

    struct socket_event *event = bpf_ringbuf_reserve(&EVENTS, sizeof(*event), 0);
    if (!event) {
        account_loss();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->version = EVENT_VERSION;
    event->size = EVENT_SIZE;
    event->pid = pid;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->family = ctx->family;
    event->protocol = IPPROTO_TCP;
    event->flags = EVENT_TCP_CONNECT;
    event->local_port = ctx->sport;
    event->remote_port = ctx->dport;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    if (ctx->family == AF_INET) {
        __builtin_memcpy(event->local_addr, ctx->saddr, 4);
        __builtin_memcpy(event->remote_addr, ctx->daddr, 4);
    } else {
        __builtin_memcpy(event->local_addr, ctx->saddr_v6, 16);
        __builtin_memcpy(event->remote_addr, ctx->daddr_v6, 16);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int packrat_tcp_accept(struct pt_regs *ctx) {
    return emit_socket_event(EVENT_TCP_ACCEPT, IPPROTO_TCP,
                             (struct sock *)PT_REGS_RETURN(ctx), 0);
}

SEC("fentry/udp_sendmsg")
int packrat_udp_sendmsg(__u64 *ctx) {
    return emit_socket_event(EVENT_UDP_SEND, IPPROTO_UDP,
                             (struct sock *)ctx[0], 1);
}

SEC("fentry/udp_recvmsg")
int packrat_udp_recvmsg(__u64 *ctx) {
    return emit_socket_event(EVENT_UDP_RECEIVE, IPPROTO_UDP,
                             (struct sock *)ctx[0], 1);
}

char LICENSE[] SEC("license") = "GPL";
