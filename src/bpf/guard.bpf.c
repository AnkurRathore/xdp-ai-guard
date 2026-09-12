#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "guard.h"

#define ETH_P_IP 0x0800

//Stats Keys
#define STATS_PASS 0
#define STATS_DROP 1

// Rate limit map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);                 // IPv4 source address
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

// Per-CPU drop/pass counters (lock-free)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);             // 0 = PASS, 1 = DROP
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_guard_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Default: pass traffic
    __u32 key = STATS_PASS; // PASS
    __u64 *count = bpf_map_lookup_elem(&stats_map, &key);
    if (count) {
        *count += 1;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
