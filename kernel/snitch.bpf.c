// SPDX-License-Identifier: AGPL-3.0-only
// Native kernel hooks for Rust Snitch. No BCC/Python runtime.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} connect_events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} blocked_v4 SEC(".maps");
struct ip6key { __u8 bytes[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ip6key);
    __type(value, __u8);
} blocked_v6 SEC(".maps");

struct connect_event {
    __u64 timestamp;
    __u32 pid;
    __s32 fd;
    __u16 family;
    __u16 port;
    __u8 address[16];
    char command[16];
    __u32 padding;
};
struct syscall_enter {
    __u64 common;
    __s64 syscall_nr;
    __u64 args[6];
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct syscall_enter *ctx) {
    void *sockaddr = (void *)ctx->args[1];
    __u16 family = 0;
    if (ctx->args[2] < 8 || bpf_probe_read_user(&family, sizeof(family), sockaddr))
        return 0;
    if (family != 2 && family != 10) return 0;
    struct connect_event *event = bpf_ringbuf_reserve(&connect_events, sizeof(*event), 0);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->fd = ctx->args[0];
    event->family = family;
    __u16 port = 0;
    bpf_probe_read_user(&port, 2, sockaddr + 2);
    event->port = __builtin_bswap16(port);
    if (family == 2)
        bpf_probe_read_user(event->address, 4, sockaddr + 4);
    else if (ctx->args[2] >= 28)
        bpf_probe_read_user(event->address, 16, sockaddr + 8);
    bpf_get_current_comm(event->command, sizeof(event->command));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("cgroup_skb/egress")
int filter_egress(struct __sk_buff *skb) {
    __u8 version = 0;
    if (bpf_skb_load_bytes(skb, 0, &version, 1)) return 1;
    if (version >> 4 == 4) {
        __u32 dst = 0;
        if (!bpf_skb_load_bytes(skb, 16, &dst, 4) && bpf_map_lookup_elem(&blocked_v4, &dst))
            return 0;
    } else if (version >> 4 == 6) {
        struct ip6key dst = {};
        if (!bpf_skb_load_bytes(skb, 24, &dst, 16) && bpf_map_lookup_elem(&blocked_v6, &dst))
            return 0;
    }
    return 1;
}

SEC("cgroup_skb/egress")
int isolate_egress(struct __sk_buff *skb) { return 0; }

// libbpf's kernel GPL-compatibility marker, matching upstream's BCC hooks.
char LICENSE[] SEC("license") = "GPL";
