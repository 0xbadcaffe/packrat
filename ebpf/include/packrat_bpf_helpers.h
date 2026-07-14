#ifndef PACKRAT_BPF_HELPERS_H
#define PACKRAT_BPF_HELPERS_H

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define __always_inline inline __attribute__((always_inline))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

enum {
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_RINGBUF = 27,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buffer, __u32 size) = (void *)16;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

#endif
