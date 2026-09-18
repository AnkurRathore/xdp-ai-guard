#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "guard.h"

#define ETH_P_IP 0x0800
#define IPPROTO_ICMP 1
#define IPPROTO_UDP  17
#define IPPROTO_TCP  6

#define STAT_PASS 0
#define STAT_DROP 1

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void record_stat(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&stats_map, &key);
    if (count) {
        *count += 1;
    }
}

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

    // === GUARD SECURITY POLICIES ===

    // Rule 1: Drop ICMP (Ping Flood / Reconnaissance Sweep)
    if (iph->protocol == IPPROTO_ICMP) {
        record_stat(STAT_DROP);
        return XDP_DROP; // Drop packet directly in the NIC/driver!
    }

    // Rule 2: Drop unsolicited UDP (Common DDoS Amplification vector against AI servers)
    if (iph->protocol == IPPROTO_UDP) {
        record_stat(STAT_DROP);
        return XDP_DROP;
    }

    // Default: Allow standard TCP (AI inference requests)
    record_stat(STAT_PASS);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
