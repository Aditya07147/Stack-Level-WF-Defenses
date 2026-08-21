#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

typedef __u64 u64;
typedef __u32 u32;

/*
 * Monotonic departure timestamp map:
 * Stores the most recent scheduled packet departure timestamp.
 * This guarantees packets exit in forward chronological order,
 * preventing TCP out-of-order packet retransmissions while still
 * injecting inter-arrival timing jitter.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} last_departure_map SEC(".maps");

SEC("classifier")
int stob_defense(struct __sk_buff *skb) {
    /* 
     * Stob Timing Primitive: Inter-arrival Jitter
     *
     * We modify the packet's departure timestamp (skb->tstamp). 
     * When the FQ (Fair Queuing) qdisc sees this, it will hold the packet
     * until that exact time. This destroys the 'inter-arrival time' 
     * features that the Random Forest model uses to identify sites.
     */
    
    u64 now = bpf_ktime_get_ns();
    u32 key = 0;
    u64 *last_tstamp = bpf_map_lookup_elem(&last_departure_map, &key);
    
    /* 
     * Base delay of 5ms (5,000,000 ns) 
     * plus a random jitter of 0-5ms (0-5,000,000 ns).
     */
    u32 jitter = bpf_get_prandom_u32() % 5000000; 
    u64 delay = 5000000 + (u64)jitter; 
    
    u64 departure = now + delay;
    if (last_tstamp) {
        if (*last_tstamp + delay > departure) {
            departure = *last_tstamp + delay;
        }
        *last_tstamp = departure;
    }
    
    skb->tstamp = departure;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";