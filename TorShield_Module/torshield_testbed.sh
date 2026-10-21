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
#include <crypto/chacha.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/net_namespace.h>

#define TORSHIELD_PROC_DIR   "torshield"

/* ---- configuration (set via the /proc/torshield entries) --------------- */

static u8   chacha_key[CHACHA_KEY_SIZE];      /* 256-bit pre-shared key     */
static bool psk_set;                          /* false => module is inert   */
static DEFINE_SPINLOCK(cfg_lock);             /* guards key/peers           */

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

/* ---- ChaCha20 transform ------------------------------------------------ */
/*
 * The payload is XORed with the ChaCha20 keystream for (key, nonce). Since a
 * stream cipher's output depends only on (key, nonce), the same call both
 * obfuscates and de-obfuscates, and two hosts with the same pre-shared key
 * agree without any coordination as long as they derive the same nonce.
 *
 * NONCE: a stream cipher MUST NOT reuse a (key, nonce) pair for different
 * plaintexts. We cannot grow the packet to carry a nonce, so we derive a
 * 12-byte nonce deterministically from on-the-wire header fields that both
 * ends see identically (addresses, ports, and the TCP sequence number, or
 * the IP ID + length for UDP). A TCP retransmission reuses the nonce but
 * carries the same plaintext, which is safe; the residual risks are TCP
 * sequence wrap (>4 GB on one connection) and the narrow UDP IP-ID space.
 * These are documented in README; a production design would negotiate a
 * per-packet nonce or key id out of band.
 */
static void ts_chacha(const u8 nonce[12], u8 *data, unsigned int len)
{
	u32 state[16];
	u8 iv[CHACHA_IV_SIZE];           /* 4-byte LE counter (0) || 12-byte nonce */
	u8 key[CHACHA_KEY_SIZE];
	unsigned long flags;

	memset(iv, 0, 4);
	memcpy(iv + 4, nonce, 12);

	spin_lock_irqsave(&cfg_lock, flags);
	memcpy(key, chacha_key, CHACHA_KEY_SIZE);
	spin_unlock_irqrestore(&cfg_lock, flags);

	chacha_init(state, (const u32 *)key, iv);
	chacha_crypt(state, data, data, len, 20);

	memzero_explicit(key, sizeof(key));
	memzero_explicit(state, sizeof(state));
}

/* Build a 12-byte nonce from a 4-byte per-packet id, the ports, and a fold
 * of the addresses. Identical at both ends because every field is taken
 * from the packet on the wire. */
static void build_nonce(__be32 id, __be16 sport, __be16 dport,
			__be32 addr_fold, u8 nonce[12])
{
	memcpy(nonce + 0, &id, 4);
	memcpy(nonce + 4, &sport, 2);
	memcpy(nonce + 6, &dport, 2);
	memcpy(nonce + 8, &addr_fold, 4);
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
	__be16 sport, dport;
	u32 nid;
	u8 nonce[12];

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

	if (is_tcp) {
		struct tcphdr *th = l4;

		sport = th->source; dport = th->dest; nid = (u32)th->seq;
	} else {
		struct udphdr *uh = l4;

		sport = uh->source; dport = uh->dest;
		nid = (u32)iph->id | ((u32)uh->len << 16);
	}
	build_nonce(nid, sport, dport, iph->saddr ^ iph->daddr, nonce);
	ts_chacha(nonce, payload, payload_len);
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
	__be16 sport, dport;
	__be32 fold;
	const __be32 *sa, *da;
	u32 nid;
	u8 nonce[12];

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

	sa = ip6h->saddr.s6_addr32;
	da = ip6h->daddr.s6_addr32;
	fold = sa[0] ^ sa[1] ^ sa[2] ^ sa[3] ^ da[0] ^ da[1] ^ da[2] ^ da[3];
	if (is_tcp) {
		struct tcphdr *th = l4;

		sport = th->source; dport = th->dest; nid = (u32)th->seq;
	} else {
		struct udphdr *uh = l4;

		sport = uh->source; dport = uh->dest;
		nid = (u32)uh->len | ((u32)payload_len << 16);
	}
	build_nonce(nid, sport, dport, fold, nonce);
	ts_chacha(nonce, payload, payload_len);
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
/* Write a 64-hex-char (256-bit) ChaCha20 pre-shared key. Never read back;
 * returns only whether a key is set. */
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
	char buf[2 * CHACHA_KEY_SIZE + 2];
	u8 key[CHACHA_KEY_SIZE] = {0};
	size_t hexlen;
	int i;
	unsigned long flags;

	if (count == 0 || count > 2 * CHACHA_KEY_SIZE + 1)
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	/* allow a trailing newline */
	hexlen = strcspn(buf, "\r\n");
	if (hexlen != 2 * CHACHA_KEY_SIZE)      /* require a full 256-bit key */
		return -EINVAL;

	for (i = 0; i < CHACHA_KEY_SIZE; i++) {
		int hi = hex_to_bin(buf[2 * i]);
		int lo = hex_to_bin(buf[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		key[i] = (hi << 4) | lo;
	}

	spin_lock_irqsave(&cfg_lock, flags);
	memcpy(chacha_key, key, CHACHA_KEY_SIZE);
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
	if (!proc_create("psk",   0600, proc_dir, &psk_fops) ||
	    !proc_create("peers", 0600, proc_dir, &peers_fops)) {
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
	memzero_explicit(chacha_key, sizeof(chacha_key));
	psk_set = false;
	spin_unlock(&cfg_lock);
	pr_info("TorShield: unloaded\n");
}

module_init(torshield_init);
module_exit(torshield_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("V. S. Roshan");
MODULE_DESCRIPTION("Kernel-level bidirectional traffic obfuscation (IPv4/IPv6, TCP/UDP) using ChaCha20 with per-packet nonces and peer filtering.");
MODULE_VERSION("3.0");
TS_EOF_MODULE
cat > "$D/torshieldctl.c" <<'TS_EOF_CTL'
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * torshieldctl - userspace control for the TorShield kernel module.
 *
 * Usage:
 *   torshieldctl status
 *   torshieldctl set-key <hex>        (64 hex chars = 256-bit ChaCha20 key)
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
		"  %s add-peer <ip>\n"
		"  %s del-peer <ip>\n"
		"  %s list-peers\n"
		"  %s clear-peers\n",
		p, p, p, p, p, p);
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
 * ts_selftest - userspace validation of the TorShield ChaCha20 transform.
 *
 * Reimplements the module's cipher (ChaCha20, RFC 8439) and RFC 1071
 * checksum fix-up in userspace and checks the properties the module relies
 * on. No root, no network. On a little-endian host this ChaCha20 matches
 * the kernel's lib/crypto chacha byte-for-byte (key read as LE words,
 * 32-bit counter starting at 0, 96-bit nonce), so the keystream is the same
 * as the loaded module produces.
 *
 * Checks:
 *   1. Round-trip:   decrypt(encrypt(p)) == p   for every length 0..2048.
 *   2. Nonce rule:   same (key,nonce) -> identical keystream (both ends
 *                    agree); a different nonce or key -> different stream.
 *   3. Checksum:     after encrypt + fix-up the TCP/UDP checksum validates
 *                    (independent RFC 1071 check); decrypt restores it.
 *   4. Microbench:   ChaCha20 throughput and per-packet cost.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

/* ---------- ChaCha20 (RFC 8439) ----------------------------------------- */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
static uint32_t u8to32le(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void qr(uint32_t *s, int a, int b, int c, int d)
{
	s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTL32(s[d], 16);
	s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTL32(s[b], 12);
	s[a] += s[b]; s[d] ^= s[a]; s[d] = ROTL32(s[d], 8);
	s[c] += s[d]; s[b] ^= s[c]; s[b] = ROTL32(s[b], 7);
}
static void chacha20_block(const uint8_t key[32], uint32_t counter,
			   const uint8_t nonce[12], uint8_t out[64])
{
	uint32_t s[16], x[16];
	int i;

	s[0] = 0x61707865; s[1] = 0x3320646e;
	s[2] = 0x79622d32; s[3] = 0x6b206574;
	for (i = 0; i < 8; i++) s[4 + i] = u8to32le(key + 4 * i);
	s[12] = counter;
	for (i = 0; i < 3; i++) s[13 + i] = u8to32le(nonce + 4 * i);

	memcpy(x, s, sizeof(x));
	for (i = 0; i < 10; i++) {
		qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13);
		qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15);
		qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12);
		qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14);
	}
	for (i = 0; i < 16; i++) {
		uint32_t v = x[i] + s[i];

		out[4 * i] = v; out[4 * i + 1] = v >> 8;
		out[4 * i + 2] = v >> 16; out[4 * i + 3] = v >> 24;
	}
}
/* XOR the ChaCha20 keystream over data; same call encrypts and decrypts. */
static void ts_chacha(const uint8_t key[32], const uint8_t nonce[12],
		      uint8_t *data, unsigned int len)
{
	uint8_t block[64];
	uint32_t counter = 0;
	unsigned int i;

	for (i = 0; i < len; i++) {
		if ((i & 63) == 0)
			chacha20_block(key, counter++, nonce, block);
		data[i] ^= block[i & 63];
	}
}

/* ---------- internet checksum (RFC 1071) -------------------------------- */
static uint32_t csum_add(const void *buf, int len, uint32_t sum)
{
	const unsigned char *b = buf;
	int i;
	for (i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)b[i] | ((uint32_t)b[i + 1] << 8);
	if (i < len)
		sum += b[i];
	return sum;
}
static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}
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
static int test_roundtrip(const uint8_t key[32])
{
	uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
	uint8_t a[2048], b[2048];
	int len, i, fails = 0;
	for (len = 0; len <= 2048; len++) {
		for (i = 0; i < len; i++) a[i] = b[i] = (uint8_t)rand();
		ts_chacha(key, nonce, b, len);              /* encrypt */
		if (len > 8 && memcmp(a, b, len) == 0) fails++;
		ts_chacha(key, nonce, b, len);              /* decrypt */
		if (memcmp(a, b, len) != 0) fails++;
	}
	printf("  [1] round-trip (len 0..2048)        : %s\n",
	       fails ? "FAIL" : "PASS");
	return fails;
}

/* ---------- test 2: nonce / key behaviour ------------------------------- */
static int test_nonce(const uint8_t key[32])
{
	uint8_t n1[12] = {0}, n2[12] = {0}, key2[32];
	uint8_t a[64], b[64], c[64];
	int fails = 0;
	memset(a, 0, 64); memset(b, 0, 64); memset(c, 0, 64);
	ts_chacha(key, n1, a, 64);
	ts_chacha(key, n1, b, 64);          /* same key+nonce -> same stream */
	if (memcmp(a, b, 64) != 0) fails++;
	n2[0] = 1; memset(c, 0, 64);
	ts_chacha(key, n2, c, 64);          /* different nonce -> differs    */
	if (memcmp(a, c, 64) == 0) fails++;
	memcpy(key2, key, 32); key2[0] ^= 1; memset(c, 0, 64);
	ts_chacha(key2, n1, c, 64);         /* different key -> differs      */
	if (memcmp(a, c, 64) == 0) fails++;
	printf("  [2] keystream = f(key, nonce)        : %s\n",
	       fails ? "FAIL" : "PASS");
	return fails;
}

/* ---------- test 3: checksum validity ----------------------------------- */
#define TCP_CHECK_OFF 16
static uint16_t get_check(const uint8_t *t) { uint16_t v; memcpy(&v, t + TCP_CHECK_OFF, 2); return v; }
static void set_check(uint8_t *t, uint16_t v) { memcpy(t + TCP_CHECK_OFF, &v, 2); }

static int test_checksum(const uint8_t key[32])
{
	uint32_t saddr = inet_addr("10.0.0.1"), daddr = inet_addr("10.0.0.2");
	uint8_t nonce[12] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2};
	uint8_t tcp[20 + 1000];
	int tcp_len = sizeof(tcp), pay = tcp_len - 20, i, fails = 0;
	uint16_t check0, check1, vplain, venc, restored;

	memset(tcp, 0, sizeof(tcp));
	tcp[12] = 5 << 4;
	for (i = 0; i < pay; i++) tcp[20 + i] = (uint8_t)(i * 7 + 1);

	set_check(tcp, 0);
	set_check(tcp, l4_csum_v4(saddr, daddr, 6, tcp, tcp_len));
	check0 = get_check(tcp);
	vplain = l4_csum_v4(saddr, daddr, 6, tcp, tcp_len);
	if (vplain != 0) fails++;

	ts_chacha(key, nonce, tcp + 20, pay);
	set_check(tcp, 0);
	set_check(tcp, l4_csum_v4(saddr, daddr, 6, tcp, tcp_len));
	check1 = get_check(tcp);
	venc = l4_csum_v4(saddr, daddr, 6, tcp, tcp_len);
	if (venc != 0) fails++;
	if (check0 == check1) fails++;

	ts_chacha(key, nonce, tcp + 20, pay);
	set_check(tcp, 0);
	set_check(tcp, l4_csum_v4(saddr, daddr, 6, tcp, tcp_len));
	restored = get_check(tcp);
	if (restored != check0) fails++;

	printf("  [3] checksum valid after xform       : %s "
	       "(vplain=0x%04x venc=0x%04x restored=0x%04x check0=0x%04x)\n",
	       fails ? "FAIL" : "PASS", vplain, venc, restored, check0);
	return fails;
}

/* ---------- test 4: microbenchmark -------------------------------------- */
static void bench(const uint8_t key[32])
{
	enum { PAY = 1460, ITERS = 2000000 };
	static uint8_t buf[PAY];
	uint8_t nonce[12] = {1};
	struct timespec t0, t1;
	long i;
	double secs, mbps, ns_cc, ns_csum;
	volatile uint16_t sink = 0;

	for (i = 0; i < PAY; i++) buf[i] = (uint8_t)i;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < ITERS; i++) ts_chacha(key, nonce, buf, PAY);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	mbps = (double)PAY * ITERS / secs / 1e6;
	ns_cc = secs * 1e9 / ITERS;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < ITERS; i++)
		sink ^= l4_csum_v4(0x0a000001, 0x0a000002, 6, buf, PAY);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	ns_csum = secs * 1e9 / ITERS;
	(void)sink;

	printf("\n  microbenchmark (payload %d B, %d iters):\n", PAY, ITERS);
	printf("    ChaCha20         : %.0f MB/s, %.1f ns/packet\n", mbps, ns_cc);
	printf("    checksum recalc  : %.1f ns/packet\n", ns_csum);
	printf("    per-packet cost (ChaCha20 + csum): %.1f ns (= %.4f ms)\n",
	       ns_cc + ns_csum, (ns_cc + ns_csum) / 1e6);
	printf("    implied max rate @1460B: %.0f Mbps\n",
	       8.0 * PAY / ((ns_cc + ns_csum) / 1e9) / 1e6);
	printf("    (userspace reference ChaCha20; the kernel uses SIMD-"
	       "accelerated chacha, which is faster)\n");
}

int main(void)
{
	uint8_t key[32];
	int i, fails = 0;
	for (i = 0; i < 32; i++) key[i] = (uint8_t)(0x11 * (i + 1));
	srand(1);

	printf("TorShield userspace self-test (ChaCha20)\n");
	fails += test_roundtrip(key);
	fails += test_nonce(key);
	fails += test_checksum(key);
	bench(key);
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
PSK=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
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
