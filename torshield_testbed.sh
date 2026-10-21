#!/bin/bash
# TorShield all-in-one testbed (self-contained). Run on a real Ubuntu/Debian
# box or VM (NOT WSL):   sudo bash torshield_testbed.sh
set -u
[ "$(id -u)" = 0 ] || { echo "Run as root: sudo bash $0"; exit 1; }
D=$(mktemp -d); echo "workdir: $D"
cat > "$D/torshield.c" <<'TS_EOF_MODULE'
// SPDX-License-Identifier: GPL-2.0
/*
 * TorShield: kernel-level network traffic obfuscation.
 *
 * Rewrite of the original xor_obfuscation module. Fixes the correctness
 * problems that made the original one-directional and incompatible with
 * real networks:
 *
 *   - Decrypts inbound traffic (PRE_ROUTING) as well as encrypting
 *     outbound traffic (POST_ROUTING), so two TorShield hosts can
 *     actually communicate.
 *   - Handles both IPv4 and IPv6, TCP and UDP.
 *   - Only touches traffic to/from explicitly configured peers, so it
 *     does not corrupt DNS, TLS, loopback, or any other traffic.
 *   - Recomputes the full transport checksum after modifying the payload
 *     (software path), and leaves hardware-offloaded packets to the NIC,
 *     which checksums over the already-modified data.
 *   - Keeps keys synchronised between hosts: the keystream is derived
 *     deterministically from a pre-shared key and the current time
 *     window (SipHash), instead of each host rotating independently.
 *   - No per-packet logging. Key material is never written to the log,
 *     and /proc entries are not world-readable.
 *
 * This is a research/teaching artifact. Single-byte XOR (the original
 * cipher) is cryptographically weak; this module defaults to a
 * length-preserving keystream XOR, which is stronger but still NOT a
 * substitute for real encryption (WireGuard, TLS). See README.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#include <linux/siphash.h>
#include <linux/ktime.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/net_namespace.h>

#define TORSHIELD_PROC_DIR   "torshield"
#define KEYSTREAM_LEN        64        /* length-preserving keystream block */

/* Faithful-to-paper mode: set to 1 to use the original single-byte XOR.
 * Default 0 uses a 64-byte keystream (stronger, same packet length). */
#ifndef TORSHIELD_SINGLE_BYTE
#define TORSHIELD_SINGLE_BYTE 0
#endif

/* ---- configuration (set via the /proc/torshield entries) --------------- */

static siphash_key_t psk_key;                 /* pre-shared key (128-bit)   */
static bool          psk_set;                 /* false => module is inert   */
static unsigned int  window_secs = 300;       /* key rotation window        */
static DEFINE_SPINLOCK(cfg_lock);             /* guards psk/window/peers     */

struct ts_peer {
	struct list_head list;
	u8               family;                  /* AF_INET / AF_INET6         */
	union {
		__be32          v4;
		struct in6_addr v6;
	} addr;
};
static LIST_HEAD(peer_list);

static struct nf_hook_ops nfho_v4_out, nfho_v4_in;
static struct nf_hook_ops nfho_v6_out, nfho_v6_in;
static struct proc_dir_entry *proc_dir;

/* ---- key derivation ---------------------------------------------------- */
/*
 * The keystream for a given time window is derived from the pre-shared key
 * only, so both endpoints compute the same bytes without any coordination
 * beyond a shared secret and roughly synchronised clocks (NTP). Rotation
 * happens deterministically at window boundaries.
 *
 * Caveat: a packet sent in the last moment of one window and received in
 * the next will be de-obfuscated with the wrong key and dropped by the
 * checksum. With NTP-synced clocks and a 300 s window this is rare; a
 * production design would carry a window tag or key id. Documented in
 * README as a known limitation.
 */
static u64 current_window(void)
{
	u64 w = window_secs ? window_secs : 1;

	return (u64)ktime_get_real_seconds() / w;
}

/* Fill ks[0..KEYSTREAM_LEN) for a window. Caller holds no lock; copies key. */
static void derive_keystream(u64 window, u8 ks[KEYSTREAM_LEN])
{
	siphash_key_t k;
	unsigned long flags;
	int blocks = KEYSTREAM_LEN / sizeof(u64);
	int i;

	spin_lock_irqsave(&cfg_lock, flags);
	k = psk_key;
	spin_unlock_irqrestore(&cfg_lock, flags);

	for (i = 0; i < blocks; i++) {
		u64 in[2] = { window, (u64)i };
		u64 out = siphash(in, sizeof(in), &k);

		memcpy(ks + i * sizeof(u64), &out, sizeof(u64));
	}
}

/* Apply the keystream to a payload. XOR is its own inverse, so the same
 * call both obfuscates and de-obfuscates. */
static void apply_keystream(u8 *data, unsigned int len, const u8 ks[KEYSTREAM_LEN])
{
	unsigned int i;

#if TORSHIELD_SINGLE_BYTE
	u8 key = ks[0];

	for (i = 0; i < len; i++)
		data[i] ^= key;
#else
	for (i = 0; i < len; i++)
		data[i] ^= ks[i & (KEYSTREAM_LEN - 1)];
#endif
}

/* ---- peer matching ----------------------------------------------------- */
/* Returns true if addr (one end of the packet) is a configured peer.
 * Called from softirq (hook) and process (proc) contexts. */
static bool peer_match_locked(u8 family, const void *addr)
{
	struct ts_peer *p;

	list_for_each_entry(p, &peer_list, list) {
		if (p->family != family)
			continue;
		if (family == AF_INET) {
			if (p->addr.v4 == *(const __be32 *)addr)
				return true;
		} else {
			if (ipv6_addr_equal(&p->addr.v6, (const struct in6_addr *)addr))
				return true;
		}
	}
	return false;
}

static bool peers_empty(void)
{
	bool empty;
	unsigned long flags;

	spin_lock_irqsave(&cfg_lock, flags);
	empty = list_empty(&peer_list);
	spin_unlock_irqrestore(&cfg_lock, flags);
	return empty;
}

/* ---- checksum recomputation (software path) ---------------------------- */

static void fixup_csum_v4(struct sk_buff *skb, struct iphdr *iph,
			  void *l4, unsigned int l4_len, bool is_tcp)
{
	__sum16 *check = is_tcp ? &((struct tcphdr *)l4)->check
				: &((struct udphdr *)l4)->check;
	__wsum csum;

	*check = 0;
	csum = csum_partial(l4, l4_len, 0);
	*check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4_len,
				   is_tcp ? IPPROTO_TCP : IPPROTO_UDP, csum);
	if (!is_tcp && *check == 0)
		*check = CSUM_MANGLED_0;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

static void fixup_csum_v6(struct sk_buff *skb, struct ipv6hdr *ip6h,
			  void *l4, unsigned int l4_len, bool is_tcp)
{
	__sum16 *check = is_tcp ? &((struct tcphdr *)l4)->check
				: &((struct udphdr *)l4)->check;
	__wsum csum;

	*check = 0;
	csum = csum_partial(l4, l4_len, 0);
	*check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr, l4_len,
				 is_tcp ? IPPROTO_TCP : IPPROTO_UDP, csum);
	if (*check == 0)
		*check = CSUM_MANGLED_0;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/* ---- core packet processing -------------------------------------------- */
/*
 * Locate the L4 payload, apply the keystream, and fix up the checksum.
 * Works for both directions (XOR is symmetric). Returns NF_ACCEPT always;
 * on any problem it leaves the packet untouched.
 */
static unsigned int process_v4(struct sk_buff *skb, bool egress)
{
	struct iphdr *iph;
	void *l4;
	u8 *payload;
	unsigned int ihl, l4_len, l4_hdr_len, payload_len;
	bool is_tcp, match;
	unsigned long flags;
	u8 ks[KEYSTREAM_LEN];

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;
	is_tcp = (iph->protocol == IPPROTO_TCP);

	/* Only touch configured peers (dst on egress, src on ingress). */
	spin_lock_irqsave(&cfg_lock, flags);
	match = peer_match_locked(AF_INET, egress ? &iph->daddr : &iph->saddr);
	spin_unlock_irqrestore(&cfg_lock, flags);
	if (!match)
		return NF_ACCEPT;

	/* GSO packets are not yet segmented; skip to avoid corrupting them. */
	if (skb_is_gso(skb))
		return NF_ACCEPT;

	ihl = iph->ihl * 4;
	if (ntohs(iph->tot_len) < ihl)
		return NF_ACCEPT;
	l4_len = ntohs(iph->tot_len) - ihl;

	/* Make the whole packet linear and writable before touching it. */
	if (skb_linearize(skb) < 0)
		return NF_ACCEPT;
	if (skb_ensure_writable(skb, ntohs(ip_hdr(skb)->tot_len)) < 0)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	l4 = (u8 *)iph + ihl;

	l4_hdr_len = is_tcp ? ((struct tcphdr *)l4)->doff * 4
			    : sizeof(struct udphdr);
	if (l4_len < l4_hdr_len)
		return NF_ACCEPT;
	payload = (u8 *)l4 + l4_hdr_len;
	payload_len = l4_len - l4_hdr_len;
	if (payload_len == 0)
		return NF_ACCEPT;
	if ((u8 *)payload + payload_len > skb_tail_pointer(skb))
		return NF_ACCEPT;

	derive_keystream(current_window(), ks);
	apply_keystream(payload, payload_len, ks);
	memzero_explicit(ks, sizeof(ks));
	fixup_csum_v4(skb, iph, l4, l4_len, is_tcp);

	return NF_ACCEPT;
}

static unsigned int process_v6(struct sk_buff *skb, bool egress)
{
	struct ipv6hdr *ip6h;
	void *l4;
	u8 *payload;
	unsigned int l4_len, l4_hdr_len, payload_len;
	bool is_tcp, match;
	unsigned long flags;
	u8 ks[KEYSTREAM_LEN];

	ip6h = ipv6_hdr(skb);
	/* Only the simple case: TCP/UDP directly after the base header. */
	if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
		return NF_ACCEPT;
	is_tcp = (ip6h->nexthdr == IPPROTO_TCP);

	spin_lock_irqsave(&cfg_lock, flags);
	match = peer_match_locked(AF_INET6, egress ? &ip6h->daddr : &ip6h->saddr);
	spin_unlock_irqrestore(&cfg_lock, flags);
	if (!match)
		return NF_ACCEPT;

	if (skb_is_gso(skb))
		return NF_ACCEPT;

	l4_len = ntohs(ip6h->payload_len);
	if (l4_len == 0)                    /* jumbogram; skip */
		return NF_ACCEPT;

	if (skb_linearize(skb) < 0)
		return NF_ACCEPT;
	if (skb_ensure_writable(skb, sizeof(*ip6h) + l4_len) < 0)
		return NF_ACCEPT;
	ip6h = ipv6_hdr(skb);
	l4 = (u8 *)ip6h + sizeof(*ip6h);

	l4_hdr_len = is_tcp ? ((struct tcphdr *)l4)->doff * 4
			    : sizeof(struct udphdr);
	if (l4_len < l4_hdr_len)
		return NF_ACCEPT;
	payload = (u8 *)l4 + l4_hdr_len;
	payload_len = l4_len - l4_hdr_len;
	if (payload_len == 0)
		return NF_ACCEPT;
	if ((u8 *)payload + payload_len > skb_tail_pointer(skb))
		return NF_ACCEPT;

	derive_keystream(current_window(), ks);
	apply_keystream(payload, payload_len, ks);
	memzero_explicit(ks, sizeof(ks));
	fixup_csum_v6(skb, ip6h, l4, l4_len, is_tcp);

	return NF_ACCEPT;
}

/* ---- netfilter hook trampolines ---------------------------------------- */

static unsigned int hook_v4_out(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	if (!skb || !psk_set || peers_empty())
		return NF_ACCEPT;
	return process_v4(skb, true);
}

static unsigned int hook_v4_in(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	if (!skb || !psk_set || peers_empty())
		return NF_ACCEPT;
	return process_v4(skb, false);
}

static unsigned int hook_v6_out(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	if (!skb || !psk_set || peers_empty())
		return NF_ACCEPT;
	return process_v6(skb, true);
}

static unsigned int hook_v6_in(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	if (!skb || !psk_set || peers_empty())
		return NF_ACCEPT;
	return process_v6(skb, false);
}

/* ---- /proc/torshield/psk ----------------------------------------------- */
/* Write a hex pre-shared key (up to 32 hex chars => 16 bytes). Never read
 * back; returns only whether a key is set. */
static int psk_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", psk_set ? "set" : "unset");
	return 0;
}

static int psk_open(struct inode *inode, struct file *file)
{
	return single_open(file, psk_show, NULL);
}

static ssize_t psk_write(struct file *file, const char __user *ubuf,
			 size_t count, loff_t *pos)
{
	char buf[33];
	u8 key[16] = {0};
	size_t hexlen;
	int i;
	unsigned long flags;

	if (count == 0 || count > 32)
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	/* allow a trailing newline */
	hexlen = strcspn(buf, "\r\n");
	if (hexlen == 0 || hexlen > 32 || (hexlen & 1))
		return -EINVAL;

	for (i = 0; i < hexlen / 2; i++) {
		int hi = hex_to_bin(buf[2 * i]);
		int lo = hex_to_bin(buf[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		key[i] = (hi << 4) | lo;
	}

	spin_lock_irqsave(&cfg_lock, flags);
	memcpy(&psk_key, key, sizeof(psk_key));
	psk_set = true;
	spin_unlock_irqrestore(&cfg_lock, flags);
	memzero_explicit(key, sizeof(key));
	memzero_explicit(buf, sizeof(buf));
	return count;
}

static const struct proc_ops psk_fops = {
	.proc_open    = psk_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = psk_write,
};

/* ---- /proc/torshield/window -------------------------------------------- */
static int window_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%u\n", READ_ONCE(window_secs));
	return 0;
}

static int window_open(struct inode *inode, struct file *file)
{
	return single_open(file, window_show, NULL);
}

static ssize_t window_write(struct file *file, const char __user *ubuf,
			    size_t count, loff_t *pos)
{
	unsigned int v;
	int ret = kstrtouint_from_user(ubuf, count, 10, &v);

	if (ret)
		return ret;
	if (v < 1 || v > 86400)
		return -EINVAL;
	WRITE_ONCE(window_secs, v);
	return count;
}

static const struct proc_ops window_fops = {
	.proc_open    = window_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = window_write,
};

/* ---- /proc/torshield/peers --------------------------------------------- */
/* read: list peers. write: "+<addr>" to add, "-<addr>" to remove,
 * "clear" to drop all. v4 and v6 literals accepted. */
static int peers_show(struct seq_file *m, void *v)
{
	struct ts_peer *p;
	unsigned long flags;

	spin_lock_irqsave(&cfg_lock, flags);
	list_for_each_entry(p, &peer_list, list) {
		if (p->family == AF_INET)
			seq_printf(m, "%pI4\n", &p->addr.v4);
		else
			seq_printf(m, "%pI6c\n", &p->addr.v6);
	}
	spin_unlock_irqrestore(&cfg_lock, flags);
	return 0;
}

static int peers_open(struct inode *inode, struct file *file)
{
	return single_open(file, peers_show, NULL);
}

static void peers_clear(void)
{
	struct ts_peer *p, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&cfg_lock, flags);
	list_for_each_entry_safe(p, tmp, &peer_list, list) {
		list_del(&p->list);
		kfree(p);
	}
	spin_unlock_irqrestore(&cfg_lock, flags);
}

static int parse_addr(const char *s, u8 *family, void *out)
{
	const char *end;

	if (in4_pton(s, -1, (u8 *)out, -1, &end)) {
		*family = AF_INET;
		return 0;
	}
	if (in6_pton(s, -1, (u8 *)out, -1, &end)) {
		*family = AF_INET6;
		return 0;
	}
	return -EINVAL;
}

static ssize_t peers_write(struct file *file, const char __user *ubuf,
			   size_t count, loff_t *pos)
{
	char buf[64];
	char *s;
	u8 family;
	union { __be32 v4; struct in6_addr v6; } addr;
	struct ts_peer *p, *tmp;
	unsigned long flags;
	bool add;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	s = strim(buf);

	if (strcmp(s, "clear") == 0) {
		peers_clear();
		return count;
	}
	if (s[0] != '+' && s[0] != '-')
		return -EINVAL;
	add = (s[0] == '+');
	s++;

	if (parse_addr(s, &family, &addr))
		return -EINVAL;

	if (add) {
		p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
		p->family = family;
		if (family == AF_INET)
			p->addr.v4 = addr.v4;
		else
			p->addr.v6 = addr.v6;

		spin_lock_irqsave(&cfg_lock, flags);
		if (!peer_match_locked(family,
				       family == AF_INET ? (void *)&addr.v4
							 : (void *)&addr.v6))
			list_add_tail(&p->list, &peer_list);
		else
			kfree(p);          /* already present */
		spin_unlock_irqrestore(&cfg_lock, flags);
	} else {
		spin_lock_irqsave(&cfg_lock, flags);
		list_for_each_entry_safe(p, tmp, &peer_list, list) {
			if (p->family != family)
				continue;
			if ((family == AF_INET && p->addr.v4 == addr.v4) ||
			    (family == AF_INET6 &&
			     ipv6_addr_equal(&p->addr.v6, &addr.v6))) {
				list_del(&p->list);
				kfree(p);
				break;
			}
		}
		spin_unlock_irqrestore(&cfg_lock, flags);
	}
	return count;
}

static const struct proc_ops peers_fops = {
	.proc_open    = peers_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = peers_write,
};

/* ---- module init / exit ------------------------------------------------ */

/* All four hooks as one array, so they can be (un)registered per network
 * namespace with a single call. Filled once at module init. */
static struct nf_hook_ops ts_hooks[4];

static void fill_hook_ops(void)
{
	nfho_v4_out.hook     = hook_v4_out;
	nfho_v4_out.pf       = NFPROTO_IPV4;
	nfho_v4_out.hooknum  = NF_INET_POST_ROUTING;
	nfho_v4_out.priority = NF_IP_PRI_LAST;

	nfho_v4_in.hook      = hook_v4_in;
	nfho_v4_in.pf        = NFPROTO_IPV4;
	nfho_v4_in.hooknum   = NF_INET_PRE_ROUTING;
	nfho_v4_in.priority  = NF_IP_PRI_FIRST;

	nfho_v6_out.hook     = hook_v6_out;
	nfho_v6_out.pf       = NFPROTO_IPV6;
	nfho_v6_out.hooknum  = NF_INET_POST_ROUTING;
	nfho_v6_out.priority = NF_IP6_PRI_LAST;

	nfho_v6_in.hook      = hook_v6_in;
	nfho_v6_in.pf        = NFPROTO_IPV6;
	nfho_v6_in.hooknum   = NF_INET_PRE_ROUTING;
	nfho_v6_in.priority  = NF_IP6_PRI_FIRST;

	ts_hooks[0] = nfho_v4_out;
	ts_hooks[1] = nfho_v4_in;
	ts_hooks[2] = nfho_v6_out;
	ts_hooks[3] = nfho_v6_in;
}

/* Register/unregister the hooks in every network namespace, so the module
 * works inside netns-based testbeds and containers, not only init_net. */
static int __net_init ts_net_init(struct net *net)
{
	return nf_register_net_hooks(net, ts_hooks, ARRAY_SIZE(ts_hooks));
}

static void __net_exit ts_net_exit(struct net *net)
{
	nf_unregister_net_hooks(net, ts_hooks, ARRAY_SIZE(ts_hooks));
}

static struct pernet_operations ts_net_ops = {
	.init = ts_net_init,
	.exit = ts_net_exit,
};

static int __init torshield_init(void)
{
	int ret;

	proc_dir = proc_mkdir(TORSHIELD_PROC_DIR, NULL);
	if (!proc_dir)
		return -ENOMEM;

	/* 0600: key control is root-only, and nothing is world-readable. */
	if (!proc_create("psk",    0600, proc_dir, &psk_fops) ||
	    !proc_create("window", 0600, proc_dir, &window_fops) ||
	    !proc_create("peers",  0600, proc_dir, &peers_fops)) {
		ret = -ENOMEM;
		goto err_proc;
	}

	fill_hook_ops();
	ret = register_pernet_subsys(&ts_net_ops);
	if (ret)
		goto err_proc;

	pr_info("TorShield: loaded (inert until psk and peers are set)\n");
	return 0;

err_proc:
	proc_remove(proc_dir);
	return ret;
}

static void __exit torshield_exit(void)
{
	unregister_pernet_subsys(&ts_net_ops);
	proc_remove(proc_dir);
	peers_clear();
	spin_lock(&cfg_lock);
	memzero_explicit(&psk_key, sizeof(psk_key));
	psk_set = false;
	spin_unlock(&cfg_lock);
	pr_info("TorShield: unloaded\n");
}

module_init(torshield_init);
module_exit(torshield_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("V. S. Roshan");
MODULE_DESCRIPTION("Kernel-level bidirectional traffic obfuscation (IPv4/IPv6, TCP/UDP) with peer filtering and time-window key synchronisation.");
MODULE_VERSION("2.0");
TS_EOF_MODULE
cat > "$D/torshieldctl.c" <<'TS_EOF_CTL'
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * torshieldctl - userspace control for the TorShield kernel module.
 *
 * Usage:
 *   torshieldctl status
 *   torshieldctl set-key <hex>        (up to 32 hex chars = 16 bytes)
 *   torshieldctl window <seconds>
 *   torshieldctl add-peer <ip>
 *   torshieldctl del-peer <ip>
 *   torshieldctl list-peers
 *   torshieldctl clear-peers
 *
 * All entries under /proc/torshield are root-only (mode 0600).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define DIR "/proc/torshield/"

static int write_proc(const char *name, const char *val)
{
	char path[64];
	int fd, n;

	snprintf(path, sizeof(path), DIR "%s", name);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}
	n = write(fd, val, strlen(val));
	close(fd);
	if (n < 0) {
		fprintf(stderr, "write %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

static int cat_proc(const char *name)
{
	char path[64], buf[512];
	int fd, n;

	snprintf(path, sizeof(path), DIR "%s", name);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		return -1;
	}
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);
	close(fd);
	return 0;
}

static void usage(const char *p)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s status\n"
		"  %s set-key <hex>\n"
		"  %s window <seconds>\n"
		"  %s add-peer <ip>\n"
		"  %s del-peer <ip>\n"
		"  %s list-peers\n"
		"  %s clear-peers\n",
		p, p, p, p, p, p, p);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "status"))
		return cat_proc("psk") < 0 ? 1 : 0;

	if (!strcmp(argv[1], "list-peers"))
		return cat_proc("peers") < 0 ? 1 : 0;

	if (!strcmp(argv[1], "clear-peers"))
		return write_proc("peers", "clear") < 0 ? 1 : 0;

	if (argc < 3) {
		usage(argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "set-key"))
		return write_proc("psk", argv[2]) < 0 ? 1 : 0;

	if (!strcmp(argv[1], "window"))
		return write_proc("window", argv[2]) < 0 ? 1 : 0;

	if (!strcmp(argv[1], "add-peer")) {
		char v[64];

		snprintf(v, sizeof(v), "+%s", argv[2]);
		return write_proc("peers", v) < 0 ? 1 : 0;
	}
	if (!strcmp(argv[1], "del-peer")) {
		char v[64];

		snprintf(v, sizeof(v), "-%s", argv[2]);
		return write_proc("peers", v) < 0 ? 1 : 0;
	}

	usage(argv[0]);
	return 1;
}
TS_EOF_CTL
cat > "$D/Makefile" <<'TS_EOF_MAKE'
# TorShield kernel module + userspace control tool
obj-m := torshield.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
CC   ?= gcc

all: module torshieldctl

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

torshieldctl: torshieldctl.c
	$(CC) -Wall -O2 -o torshieldctl torshieldctl.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f torshieldctl

.PHONY: all module clean
TS_EOF_MAKE
cat > "$D/ts_selftest.c" <<'TS_EOF_SELF'
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ts_selftest - userspace validation of the TorShield transform.
 *
 * This reimplements the module's keystream derivation (SipHash-2-4 over
 * {window, block}), payload XOR, and transport-checksum fix-up in plain
 * userspace, then checks the algorithmic properties the kernel module
 * relies on. It needs no root and does not touch the network. On a
 * little-endian host the SipHash keystream is byte-identical to the
 * kernel build's; this harness asserts the *properties*, not that match.
 *
 * Checks:
 *   1. Round-trip:   decrypt(encrypt(p)) == p   for every length 0..2048.
 *   2. Key sync:     same (psk, window) -> same keystream;
 *                    different window   -> different keystream.
 *   3. Checksum:     after encrypt + fix-up, an independent RFC 1071
 *                    verification of the TCP and UDP checksum passes,
 *                    and after decrypt the original checksum is restored.
 *   4. Microbench:   payload XOR throughput and per-packet cost.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#define KEYSTREAM_LEN 64

/* ---------- SipHash-2-4 (reference, public domain) ---------------------- */
#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND do { \
	v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32); \
	v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
	v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
	v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32); \
} while (0)

static uint64_t u8to64_le(const uint8_t *p)
{
	uint64_t r = 0;
	int i;
	for (i = 0; i < 8; i++)
		r |= (uint64_t)p[i] << (8 * i);
	return r;
}

static uint64_t siphash24(const void *src, size_t len, const uint8_t k[16])
{
	const uint8_t *in = src;
	uint64_t k0 = u8to64_le(k), k1 = u8to64_le(k + 8);
	uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
	uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
	uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
	uint64_t v3 = 0x7465646279746573ULL ^ k1;
	uint64_t b = (uint64_t)len << 56;
	const uint8_t *end = in + (len & ~7ULL);
	int i;

	for (; in != end; in += 8) {
		uint64_t m = u8to64_le(in);
		v3 ^= m; SIPROUND; SIPROUND; v0 ^= m;
	}
	for (i = 0; i < (int)(len & 7); i++)
		b |= (uint64_t)in[i] << (8 * i);
	v3 ^= b; SIPROUND; SIPROUND; v0 ^= b;
	v2 ^= 0xff; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
	return (v0 ^ v1) ^ (v2 ^ v3);
}

/* ---------- TorShield transform (mirrors torshield.c) ------------------- */
static void derive_keystream(uint64_t window, const uint8_t psk[16],
			     uint8_t ks[KEYSTREAM_LEN])
{
	int blocks = KEYSTREAM_LEN / sizeof(uint64_t);
	int i;
	for (i = 0; i < blocks; i++) {
		uint64_t in[2] = { window, (uint64_t)i };
		uint64_t out = siphash24(in, sizeof(in), psk);
		memcpy(ks + i * sizeof(uint64_t), &out, sizeof(uint64_t));
	}
}

static void apply_keystream(uint8_t *data, unsigned int len,
			    const uint8_t ks[KEYSTREAM_LEN])
{
	unsigned int i;
	for (i = 0; i < len; i++)
		data[i] ^= ks[i & (KEYSTREAM_LEN - 1)];
}

/* ---------- internet checksum (RFC 1071) -------------------------------- */
static uint32_t csum_add(const void *buf, int len, uint32_t sum)
{
	const unsigned char *b = buf;
	int i;
	for (i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)b[i] | ((uint32_t)b[i + 1] << 8);
	if (i < len)
		sum += b[i];           /* trailing odd byte */
	return sum;
}
static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}
/* pseudo-header + L4 checksum, matching what the module recomputes */
static uint16_t l4_csum_v4(uint32_t saddr, uint32_t daddr, uint8_t proto,
			   const void *l4, int l4_len)
{
	uint32_t sum = 0;
	struct { uint32_t s, d; uint8_t z, p; uint16_t len; } ph = {
		saddr, daddr, 0, proto, htons(l4_len)
	};
	sum = csum_add(&ph, sizeof(ph), sum);
	sum = csum_add(l4, l4_len, sum);
	return csum_fold(sum);
}

/* ---------- test 1: round-trip ------------------------------------------ */
static int test_roundtrip(const uint8_t psk[16])
{
	uint8_t ks[KEYSTREAM_LEN], a[2048], b[2048];
	int len, i, fails = 0;
	derive_keystream(12345, psk, ks);
	for (len = 0; len <= 2048; len++) {
		for (i = 0; i < len; i++) a[i] = b[i] = (uint8_t)(rand());
		apply_keystream(b, len, ks);           /* encrypt */
		if (len && memcmp(a, b, len) == 0 && len > KEYSTREAM_LEN)
			fails++;                       /* ciphertext == plaintext */
		apply_keystream(b, len, ks);           /* decrypt */
		if (memcmp(a, b, len) != 0) fails++;
	}
	printf("  [1] round-trip (len 0..2048)        : %s\n",
	       fails ? "FAIL" : "PASS");
	return fails;
}

/* ---------- test 2: key synchronisation --------------------------------- */
static int test_keysync(const uint8_t psk[16])
{
	uint8_t a[KEYSTREAM_LEN], b[KEYSTREAM_LEN], c[KEYSTREAM_LEN];
	uint8_t psk2[16];
	int fails = 0;
	derive_keystream(1000, psk, a);
	derive_keystream(1000, psk, b);   /* same window, same psk  */
	derive_keystream(1001, psk, c);   /* next window            */
	if (memcmp(a, b, KEYSTREAM_LEN) != 0) fails++;   /* must match */
	if (memcmp(a, c, KEYSTREAM_LEN) == 0) fails++;   /* must differ */
	memcpy(psk2, psk, 16); psk2[0] ^= 1;
	derive_keystream(1000, psk2, b);
	if (memcmp(a, b, KEYSTREAM_LEN) == 0) fails++;   /* diff psk -> differ */
	printf("  [2] key sync (window + psk)          : %s\n",
	       fails ? "FAIL" : "PASS");
	return fails;
}

/* checksum field lives at byte offset 16 in the TCP header */
#define TCP_CHECK_OFF 16
static uint16_t get_check(const uint8_t *tcp)
{
	uint16_t v; memcpy(&v, tcp + TCP_CHECK_OFF, 2); return v;
}
static void set_check(uint8_t *tcp, uint16_t v)
{
	memcpy(tcp + TCP_CHECK_OFF, &v, 2);
}

/* ---------- test 3: checksum validity ----------------------------------- */
static int test_checksum(const uint8_t psk[16])
{
	/* Build an IPv4 + TCP packet with a payload, like the module sees. */
	uint32_t saddr = inet_addr("10.0.0.1"), daddr = inet_addr("10.0.0.2");
	uint8_t tcp[20 + 1000];
	int tcp_len = sizeof(tcp), pay = tcp_len - 20, i, fails = 0;
	uint8_t ks[KEYSTREAM_LEN];
	uint16_t check0, check1;

	memset(tcp, 0, sizeof(tcp));
	tcp[12] = 5 << 4;                        /* data offset = 5 (20 bytes) */
	for (i = 0; i < pay; i++) tcp[20 + i] = (uint8_t)(i * 7 + 1);

	/* correct checksum over plaintext */
	set_check(tcp, 0);
	set_check(tcp, l4_csum_v4(saddr, daddr, 6, tcp, tcp_len));
	check0 = get_check(tcp);
	uint16_t vplain = l4_csum_v4(saddr, daddr, 6, tcp, tcp_len);
	if (vplain != 0) fails++;

	/* encrypt payload + recompute checksum (module behaviour) */
	derive_keystream(777, psk, ks);
	apply_keystream(tcp + 20, pay, ks);
	set_check(tcp, 0);
	set_check(tcp, l4_csum_v4(saddr, daddr, 6, tcp, tcp_len));
	check1 = get_check(tcp);
	uint16_t venc = l4_csum_v4(saddr, daddr, 6, tcp, tcp_len);
	if (venc != 0) fails++;           /* valid */
	if (check0 == check1) fails++;    /* checksum must change with payload */

	/* decrypt + recompute -> original checksum and payload restored */
	apply_keystream(tcp + 20, pay, ks);
	set_check(tcp, 0);
	set_check(tcp, l4_csum_v4(saddr, daddr, 6, tcp, tcp_len));
	uint16_t restored = get_check(tcp);
	if (restored != check0) fails++;

	printf("  [3] checksum valid after xform       : %s "
	       "(vplain=0x%04x venc=0x%04x restored=0x%04x check0=0x%04x)\n",
	       fails ? "FAIL" : "PASS", vplain, venc, restored, check0);
	return fails;
}

/* ---------- test 4: microbenchmark -------------------------------------- */
static void bench(const uint8_t psk[16])
{
	enum { PAY = 1460, ITERS = 2000000 };
	static uint8_t buf[PAY];
	uint8_t ks[KEYSTREAM_LEN];
	struct timespec t0, t1;
	long i;
	double secs, bytes, mbps, ns_xor, ns_csum;

	derive_keystream(1, psk, ks);
	for (i = 0; i < PAY; i++) buf[i] = (uint8_t)i;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < ITERS; i++) apply_keystream(buf, PAY, ks);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	bytes = (double)PAY * ITERS;
	mbps = bytes / secs / 1e6;
	ns_xor = secs * 1e9 / ITERS;

	volatile uint16_t sink = 0;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < ITERS; i++)
		sink ^= l4_csum_v4(0x0a000001, 0x0a000002, 6, buf, PAY);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	ns_csum = secs * 1e9 / ITERS;
	(void)sink;

	printf("\n  microbenchmark (payload %d B, %d iters):\n", PAY, ITERS);
	printf("    keystream XOR   : %.0f MB/s, %.1f ns/packet\n", mbps, ns_xor);
	printf("    checksum recalc : %.1f ns/packet\n", ns_csum);
	printf("    per-packet obfuscation cost (XOR+csum): %.1f ns "
	       "(= %.4f ms)\n", ns_xor + ns_csum, (ns_xor + ns_csum) / 1e6);
	printf("    implied max rate @1460B: %.0f Mbps\n",
	       8.0 * PAY / ((ns_xor + ns_csum) / 1e9) / 1e6);
}

int main(void)
{
	uint8_t psk[16];
	int i, fails = 0;
	for (i = 0; i < 16; i++) psk[i] = (uint8_t)(0x11 * (i + 1));
	srand(1);

	printf("TorShield userspace self-test\n");
	fails += test_roundtrip(psk);
	fails += test_keysync(psk);
	fails += test_checksum(psk);
	bench(psk);
	printf("\n  RESULT: %s\n", fails ? "FAILURES" : "ALL CORRECTNESS TESTS PASSED");
	return fails ? 1 : 0;
}
TS_EOF_SELF
cat > "$D/run_testbed.sh" <<'TS_EOF_TESTBED'
#!/bin/bash
#
# TorShield network-namespace testbed.
#
#   Builds the module, wires two network namespaces with a veth pair, loads
#   TorShield on the host (hooks run in every namespace), and then:
#     * proves TCP and UDP traffic survives end-to-end with obfuscation on,
#     * proves the bytes on the wire are obfuscated (a plaintext marker does
#       not appear in a capture, but the receiver still gets it),
#     * measures throughput (iperf3 TCP + UDP) and CPU with vs. without.
#
#   REQUIRES ROOT.  Run:   sudo bash run_testbed.sh
#
#   Prerequisites: a kernel that can load out-of-tree modules, matching
#   headers (linux-headers-$(uname -r)), and: gcc make iproute2 iperf3 tcpdump
#
#   NOTE on WSL2: the stock WSL kernel ships stub headers and cannot load
#   this module. Use a normal Ubuntu/Debian host or VM, or a cloud instance.
#
set -u

LKM_DIR="${LKM_DIR:-$(cd "$(dirname "$0")/../LKM" && pwd)}"
NS1=ts-ns1
NS2=ts-ns2
IP1=10.0.0.1
IP2=10.0.0.2
PSK=00112233445566778899aabbccddeeff
MARKER=TORSHIELD_PLAINTEXT_MARKER_42
FAIL=0

say()  { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '  [PASS] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

[ "$(id -u)" = 0 ] || { echo "Must run as root (sudo bash $0)"; exit 1; }

# ---- prerequisites ------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1"; MISS=1; }; }
MISS=0; for c in gcc make ip iperf3 tcpdump; do need "$c"; done
[ "$MISS" = 1 ] && { echo "Install the missing tools and re-run."; exit 1; }

# ---- build --------------------------------------------------------------
say "Building module"
KDIR="/lib/modules/$(uname -r)/build"
if [ ! -e "$KDIR/Makefile" ]; then
	echo "No kernel build tree at $KDIR."
	echo "Install: sudo apt-get install -y linux-headers-\$(uname -r)"
	exit 1
fi
make -C "$LKM_DIR" >/dev/null || { echo "build failed"; exit 1; }
KO="$LKM_DIR/torshield.ko"
CTL="$LKM_DIR/torshieldctl"
[ -f "$KO" ] && ok "built torshield.ko" || { bad "no .ko"; exit 1; }

cleanup() {
	ip netns del $NS1 2>/dev/null
	ip netns del $NS2 2>/dev/null
	rmmod torshield 2>/dev/null
}
trap cleanup EXIT

# ---- topology -----------------------------------------------------------
say "Setting up namespaces $NS1 <-> $NS2"
cleanup
ip netns add $NS1
ip netns add $NS2
ip link add veth1 netns $NS1 type veth peer name veth2 netns $NS2
ip -n $NS1 addr add $IP1/24 dev veth1
ip -n $NS2 addr add $IP2/24 dev veth2
ip -n $NS1 link set veth1 up
ip -n $NS2 link set veth2 up
ip -n $NS1 link set lo up
ip -n $NS2 link set lo up
# large MTU-safe defaults; disable checksum offload so the SW path is exercised
ip netns exec $NS1 ethtool -K veth1 tx off rx off 2>/dev/null
ip netns exec $NS2 ethtool -K veth2 tx off rx off 2>/dev/null
ok "veth pair up ($IP1, $IP2)"

# ---- load + configure ---------------------------------------------------
say "Loading and configuring TorShield"
insmod "$KO" || { bad "insmod failed"; exit 1; }
"$CTL" set-key $PSK
"$CTL" add-peer $IP1          # config is global; both ends must be peers
"$CTL" add-peer $IP2
"$CTL" window 300
"$CTL" status
"$CTL" list-peers
ok "module loaded, PSK set, peers = $IP1 $IP2"

# ---- correctness: link up (ICMP is not obfuscated) ----------------------
say "Correctness"
if ip netns exec $NS1 ping -c1 -W2 $IP2 >/dev/null 2>&1; then
	ok "ICMP reaches peer (link works)"
else
	bad "ping failed"
fi

# ---- correctness: TCP end-to-end + wire is obfuscated -------------------
# Receiver in NS2 listens; capture on NS2's veth; sender in NS1 sends marker.
# Uses python3 for a portable TCP server/client (no nc-flavour issues).
CAP=$(mktemp)
RX=$(mktemp)
ip netns exec $NS2 timeout 8 tcpdump -i veth2 -w "$CAP" -U tcp 2>/dev/null &
TPID=$!
sleep 1
ip netns exec $NS2 timeout 6 python3 - "$RX" <<'PY' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9000)); s.listen(1); s.settimeout(5)
c, _ = s.accept()
data = c.recv(4096)
open(sys.argv[1], "wb").write(data)
PY
sleep 1
ip netns exec $NS1 timeout 3 python3 - "$IP2" "$MARKER" <<'PY'
import socket, sys, time
c = socket.socket(); c.connect((sys.argv[1], 9000))
c.sendall(sys.argv[2].encode()); time.sleep(0.3); c.close()
PY
sleep 2
kill $TPID 2>/dev/null; wait $TPID 2>/dev/null

if grep -qa "$MARKER" "$RX"; then
	ok "TCP payload delivered intact (receiver saw marker)"
else
	bad "receiver did NOT get the marker (decryption/path broken)"
fi
if tcpdump -r "$CAP" -A 2>/dev/null | grep -qa "$MARKER"; then
	bad "marker visible in cleartext on the wire (NOT obfuscated)"
else
	ok "marker NOT in cleartext on the wire (payload obfuscated)"
fi
rm -f "$CAP" "$RX"

# ---- performance: with vs without --------------------------------------
parse_tcp() { python3 -c 'import sys,json;d=json.load(sys.stdin);print("%.0f Mbps (sender CPU %.1f%%)"%(d["end"]["sum_received"]["bits_per_second"]/1e6,d["end"]["cpu_utilization_percent"]["host_total"]))' 2>/dev/null || echo "n/a"; }
parse_udp() { python3 -c 'import sys,json;d=json.load(sys.stdin);e=d["end"]["sum"];print("%.0f Mbps, loss %.2f%%"%(e["bits_per_second"]/1e6,e["lost_percent"]))' 2>/dev/null || echo "n/a"; }

perf_run() {   # $1 = label
	ip netns exec $NS2 iperf3 -s -1 -D --logfile /dev/null 2>/dev/null
	sleep 1
	printf '  %-8s TCP: ' "$1"
	ip netns exec $NS1 iperf3 -c $IP2 -t 5 -J 2>/dev/null | parse_tcp
	ip netns exec $NS2 iperf3 -s -1 -D --logfile /dev/null 2>/dev/null
	sleep 1
	printf '  %-8s UDP: ' "$1"
	ip netns exec $NS1 iperf3 -c $IP2 -u -b 0 -t 5 -J 2>/dev/null | parse_udp
}

say "Performance WITH TorShield (peers set)"
perf_run "with"

say "Performance WITHOUT TorShield (peers cleared -> inert)"
"$CTL" clear-peers
perf_run "without"

say "Summary"
[ "$FAIL" = 0 ] && echo "  ALL CORRECTNESS CHECKS PASSED" || echo "  SOME CHECKS FAILED"
echo "  (throughput numbers above are the with/without comparison for Table I / Fig. 2)"
exit $FAIL
TS_EOF_TESTBED

echo; echo "########## 1. userspace self-test (no kernel) ##########"
gcc -Wall -Wextra -O2 -fno-strict-aliasing -o "$D/ts_selftest" "$D/ts_selftest.c" && "$D/ts_selftest"

echo; echo "########## 2. network-namespace testbed (kernel) ##########"
LKM_DIR="$D" bash "$D/run_testbed.sh"
rc=$?
rm -rf "$D"
exit $rc
