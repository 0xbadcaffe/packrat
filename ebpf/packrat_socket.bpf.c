#include "include/packrat_bpf_helpers.h"

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define TCP_SYN_SENT 2
#define EVENT_VERSION 1
#define EVENT_SIZE 80

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

static __always_inline void account_loss(void) {
    __u32 key = 0;
    __u64 *lost = bpf_map_lookup_elem(&LOST_EVENTS, &key);
    if (lost)
        __sync_fetch_and_add(lost, 1);
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
    event->flags = 1; /* outbound connect */
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

char LICENSE[] SEC("license") = "GPL";
