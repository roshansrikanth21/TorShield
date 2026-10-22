// SPDX-License-Identifier: GPL-2.0
/*
 * TorShield TC egress classifier.
 *
 * Runs on the underlay interface's clsact egress hook.  It matches inner
 * packets whose destination falls inside a configured peer prefix (an LPM
 * trie populated from /proc/torshield/peers) and redirects them to the
 * torshield netdevice.  The device's ndo_start_xmit does the encapsulation;
 * AEAD is deliberately not attempted here because the crypto runs on a
 * synchronous in-kernel path, not in the BPF helper set.
 *
 * Outer frames emitted by the device are marked with TS_TC_MARK so they are
 * not redirected a second time.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TS_TC_MARK 0x5454

struct lpm4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct lpm6_key {
	__u32 prefixlen;
	__u8 addr[16];
};

/* Populated by torshieldctl tc-sync (or the attach helper). */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4_key);
	__type(value, __u32);
} allowed4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm6_key);
	__type(value, __u32);
} allowed6 SEC(".maps");

/* cfg[0] = ifindex of the torshield device to redirect to. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} cfg SEC(".maps");

/* redirects[0] = inner packets sent to the torshield device;
 * marked[0]    = already-encapsulated outer frames left alone. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} redirects SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} marked SEC(".maps");

static __always_inline void count(void *map, __u32 *zero)
{
	__u64 *v = bpf_map_lookup_elem(map, zero);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/*
 * A matching inner packet must never fall through to the wire.  If the
 * target device is missing from cfg, the classifier is attached but not
 * configured; drop rather than returning TC_ACT_OK (which the kernel-side
 * LOCAL_OUT/FORWARD guard cannot distinguish from a working redirect).
 */
static __always_inline int steer(__u32 *zero)
{
	__u32 *ifindex = bpf_map_lookup_elem(&cfg, zero);

	if (!ifindex || !*ifindex)
		return TC_ACT_SHOT;
	count(&redirects, zero);
	return bpf_redirect(*ifindex, 0);
}

SEC("tc")
int ts_tc_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u32 zero = 0;
	__u16 proto;

	/* Already encapsulated by the torshield device. */
	if (skb->mark == TS_TC_MARK) {
		count(&marked, &zero);
		return TC_ACT_OK;
	}

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	proto = eth->h_proto;

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		struct lpm4_key key;

		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;
		if (ip->version != 4)
			return TC_ACT_OK;
		/* Never steer multicast or link-local traffic.  A link-local
		 * source can never be a valid inner source either. */
		if ((bpf_ntohl(ip->daddr) & 0xf0000000) == 0xe0000000)
			return TC_ACT_OK;
		if ((bpf_ntohl(ip->daddr) & 0xffff0000) == 0xa9fe0000)
			return TC_ACT_OK;
		if ((bpf_ntohl(ip->saddr) & 0xffff0000) == 0xa9fe0000)
			return TC_ACT_OK;
		key.prefixlen = 32;
		key.addr = ip->daddr;
		if (bpf_map_lookup_elem(&allowed4, &key))
			return steer(&zero);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		struct lpm6_key key = {};

		if ((void *)(ip6 + 1) > data_end)
			return TC_ACT_OK;
		if (ip6->version != 6)
			return TC_ACT_OK;
		/* ff00::/8 multicast, fe80::/10 link-local. */
		if (ip6->daddr.s6_addr[0] == 0xff)
			return TC_ACT_OK;
		if (ip6->daddr.s6_addr[0] == 0xfe &&
		    (ip6->daddr.s6_addr[1] & 0xc0) == 0x80)
			return TC_ACT_OK;
		if (ip6->saddr.s6_addr[0] == 0xfe &&
		    (ip6->saddr.s6_addr[1] & 0xc0) == 0x80)
			return TC_ACT_OK;
		key.prefixlen = 128;
		__builtin_memcpy(key.addr, &ip6->daddr, sizeof(key.addr));
		if (bpf_map_lookup_elem(&allowed6, &key))
			return steer(&zero);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
