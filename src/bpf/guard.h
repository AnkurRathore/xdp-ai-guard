#ifndef __GUARD_H
#define __GUARD_H

struct rate_limit_entry {
    __u64 last_seen_ns;
    __u64 tokens;
};

struct stats_record {
    __u64 pass_count;
    __u64 drop_count;
};

#endif
