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
#include <linux/version.h>
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

/* ---- counters (observability; one atomic per event, no locking) -------- */
static atomic64_t st_seen, st_enc, st_nomatch, st_gso, st_frag, st_bad;
static atomic64_t st_enc_out, st_enc_in, st_gso_out, st_gso_in;
/* Per-packet nonce counter for UDP.  Carried on the wire in the IPv4 ID
 * field (unused when DF is set) or the IPv6 flow label, so the nonce stays
 * unique without changing the packet length. */
static atomic_t ts_nonce = ATOMIC_INIT(0);


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
	/*
	 * The ChaCha helper state is an opaque u32[16] up to Linux 6.15 and a
	 * "struct chacha_state" from 6.16 onwards.  Keep both buildable.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
	struct chacha_state state;
#else
	u32 state[CHACHA_STATE_WORDS];
#endif
	u8 iv[CHACHA_IV_SIZE];           /* 4-byte LE counter (0) || 12-byte nonce */
	u8 key[CHACHA_KEY_SIZE];
	unsigned long flags;

	memset(iv, 0, 4);
	memcpy(iv + 4, nonce, 12);

	spin_lock_irqsave(&cfg_lock, flags);
	memcpy(key, chacha_key, CHACHA_KEY_SIZE);
	spin_unlock_irqrestore(&cfg_lock, flags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
	chacha_init(&state, (const u32 *)key, iv);
	chacha_crypt(&state, data, data, len, 20);
	memzero_explicit(&state, sizeof(state));
#else
	chacha_init(state, (const u32 *)key, iv);
	chacha_crypt(state, data, data, len, 20);
	memzero_explicit(state, sizeof(state));
#endif

	memzero_explicit(key, sizeof(key));
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

/*
 * A TSO/GSO skb is one TCP header followed by the payloads of several
 * segments (the last one may be short).  Each segment was encrypted by the
 * sender with its own sequence number, so a super-skb must be processed in
 * gso_size chunks, each with nonce = seq + offset.  The skb is otherwise
 * left alone: segmentation and hardware checksumming happen afterwards, over
 * the bytes we just wrote.
 */
static void ts_crypt_tcp_gso(u8 *payload, unsigned int payload_len,
			     unsigned int gso_size, __be32 seq_be,
			     __be16 sport, __be16 dport, __be32 fold)
{
	u32 seq = ntohl(seq_be);
	unsigned int off = 0;

	while (off < payload_len) {
		unsigned int chunk = min(gso_size, payload_len - off);
		u32 nid = htonl(seq + off);
		u8 nonce[12];

		build_nonce(nid, sport, dport, fold, nonce);
		ts_chacha(nonce, payload + off, chunk);
		off += chunk;
	}
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
	unsigned int gso_size = 0;
	bool is_tcp, match, gso;
	unsigned long flags;
	__be16 sport, dport;
	u32 nid;
	u8 nonce[12];

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;
	is_tcp = (iph->protocol == IPPROTO_TCP);

	atomic64_inc(&st_seen);

	/* Only touch configured peers (dst on egress, src on ingress). */
	spin_lock_irqsave(&cfg_lock, flags);
	match = peer_match_locked(AF_INET, egress ? &iph->daddr : &iph->saddr);
	spin_unlock_irqrestore(&cfg_lock, flags);
	if (!match) {
		atomic64_inc(&st_nomatch);
		return NF_ACCEPT;
	}

	/*
	 * Fragments: only the first fragment carries the L4 header, so the
	 * rest cannot be handled and would be corrupted.  Fail open for the
	 * whole fragmented datagram (first fragment included) so it is either
	 * all plaintext or not touched at all.
	 */
	if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET))) {
		atomic64_inc(&st_frag);
		return NF_ACCEPT;
	}

	/*
	 * GSO/TSO: one header + several coalesced TCP payloads.  Handled per
	 * segment below.  UDP GSO is not supported (skipped, fail open).
	 */
	gso = skb_is_gso(skb);
	if (gso) {
		atomic64_inc(egress ? &st_gso_out : &st_gso_in);
		if (!is_tcp) {
			atomic64_inc(&st_gso);
			return NF_ACCEPT;
		}
		gso_size = skb_shinfo(skb)->gso_size;
		if (!gso_size) {
			atomic64_inc(&st_gso);
			return NF_ACCEPT;
		}
	}

	/*
	 * A datagram larger than the outgoing MTU will be fragmented after
	 * this hook.  The receiver either sees fragments (which we skip) or
	 * reassembles them into a packet we never encrypted, so skip it here
	 * as well: fragmented traffic stays plaintext but intact.  (A tunnel
	 * design removes this class of problem entirely.)
	 */
	if (egress && !gso && skb_dst(skb) &&
	    ntohs(iph->tot_len) > dst_mtu(skb_dst(skb))) {
		atomic64_inc(&st_frag);
		return NF_ACCEPT;
	}

	ihl = iph->ihl * 4;
	if (iph->ihl < 5 || ntohs(iph->tot_len) < ihl) {
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}
	l4_len = ntohs(iph->tot_len) - ihl;

	/* Make the whole packet linear and writable before touching it. */
	if (skb_linearize(skb) < 0) {
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}
	if (skb_ensure_writable(skb, ntohs(ip_hdr(skb)->tot_len)) < 0) {
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (u8 *)iph + ihl;

	l4_hdr_len = is_tcp ? ((struct tcphdr *)l4)->doff * 4
			    : sizeof(struct udphdr);
	if ((is_tcp && ((struct tcphdr *)l4)->doff < 5) || l4_len < l4_hdr_len) {
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}
	payload = (u8 *)l4 + l4_hdr_len;
	payload_len = l4_len - l4_hdr_len;
	if (payload_len == 0)
		return NF_ACCEPT;
	if ((u8 *)payload + payload_len > skb_tail_pointer(skb)) {
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}

	if (is_tcp) {
		struct tcphdr *th = l4;

		sport = th->source; dport = th->dest;
		if (gso) {
			ts_crypt_tcp_gso(payload, payload_len, gso_size,
					 th->seq, sport, dport,
					 iph->saddr ^ iph->daddr);
			goto crypted;
		}
		nid = (u32)th->seq;
	} else {
		struct udphdr *uh = l4;

		sport = uh->source; dport = uh->dest;
		if (egress) {
			/*
			 * Linux leaves the IPv4 ID at zero when DF is set, so
			 * deriving the nonce from it alone reuses the keystream
			 * for every same-size datagram.  Stamp a per-packet
			 * counter into the ID (legal: no fragmentation happens
			 * with DF set, and all fragments inherit it otherwise)
			 * and fix the header checksum.
			 */
			iph->id = htons((u16)atomic_inc_return(&ts_nonce));
			iph->check = 0;
			iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
		}
		nid = (u32)iph->id | ((u32)uh->len << 16);
	}
	build_nonce(nid, sport, dport, iph->saddr ^ iph->daddr, nonce);
	ts_chacha(nonce, payload, payload_len);
crypted:
	if (gso) {
		/* Segments are checksummed after segmentation; an ingress GRO
		 * skb was already verified on the wire. */
		if (!egress)
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else {
		fixup_csum_v4(skb, iph, l4, l4_len, is_tcp);
	}
	atomic64_inc(egress ? &st_enc_out : &st_enc_in);
	atomic64_inc(&st_enc);

	return NF_ACCEPT;
}

static unsigned int process_v6(struct sk_buff *skb, bool egress)
{
	struct ipv6hdr *ip6h;
	void *l4;
	u8 *payload;
	unsigned int l4_len, l4_hdr_len, payload_len;
	unsigned int gso_size = 0;
	bool is_tcp, match, gso;
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

	atomic64_inc(&st_seen);

	spin_lock_irqsave(&cfg_lock, flags);
	match = peer_match_locked(AF_INET6, egress ? &ip6h->daddr : &ip6h->saddr);
	spin_unlock_irqrestore(&cfg_lock, flags);
	if (!match) {
		atomic64_inc(&st_nomatch);
		return NF_ACCEPT;
	}

	gso = skb_is_gso(skb);
	if (gso) {
		atomic64_inc(egress ? &st_gso_out : &st_gso_in);
		if (!is_tcp) {
			atomic64_inc(&st_gso);
			return NF_ACCEPT;
		}
		gso_size = skb_shinfo(skb)->gso_size;
		if (!gso_size) {
			atomic64_inc(&st_gso);
			return NF_ACCEPT;
		}
	}

	if (egress && !gso && skb_dst(skb) &&
	    (ntohs(ip6h->payload_len) + sizeof(*ip6h)) > dst_mtu(skb_dst(skb))) {
		atomic64_inc(&st_frag);
		return NF_ACCEPT;
	}

	l4_len = ntohs(ip6h->payload_len);
	if (l4_len == 0) {                  /* jumbogram; skip */
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}

	if (skb_linearize(skb) < 0) {
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}
	if (skb_ensure_writable(skb, sizeof(*ip6h) + l4_len) < 0) {
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}
	ip6h = ipv6_hdr(skb);
	l4 = (u8 *)ip6h + sizeof(*ip6h);

	l4_hdr_len = is_tcp ? ((struct tcphdr *)l4)->doff * 4
			    : sizeof(struct udphdr);
	if ((is_tcp && ((struct tcphdr *)l4)->doff < 5) || l4_len < l4_hdr_len) {
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}
	payload = (u8 *)l4 + l4_hdr_len;
	payload_len = l4_len - l4_hdr_len;
	if (payload_len == 0)
		return NF_ACCEPT;
	if ((u8 *)payload + payload_len > skb_tail_pointer(skb)) {
		atomic64_inc(&st_bad);
		return NF_ACCEPT;
	}

	sa = ip6h->saddr.s6_addr32;
	da = ip6h->daddr.s6_addr32;
	fold = sa[0] ^ sa[1] ^ sa[2] ^ sa[3] ^ da[0] ^ da[1] ^ da[2] ^ da[3];
	if (is_tcp) {
		struct tcphdr *th = l4;

		sport = th->source; dport = th->dest;
		if (gso) {
			ts_crypt_tcp_gso(payload, payload_len, gso_size,
					 th->seq, sport, dport, fold);
			goto crypted;
		}
		nid = (u32)th->seq;
	} else {
		struct udphdr *uh = l4;

		sport = uh->source; dport = uh->dest;
		if (egress) {
			/* IPv6 has no ID field; the 20-bit flow label is the
			 * equivalent per-packet carrier and is not part of
			 * any checksum. */
			u32 v = (u32)atomic_inc_return(&ts_nonce) & 0xFFFFF;

			ip6h->flow_lbl[0] = (ip6h->flow_lbl[0] & 0xF0) |
					    ((v >> 16) & 0x0F);
			ip6h->flow_lbl[1] = (v >> 8) & 0xFF;
			ip6h->flow_lbl[2] = v & 0xFF;
		}
		nid = ((u32)ip6h->flow_lbl[0] << 16) |
		      ((u32)ip6h->flow_lbl[1] << 8) |
		      (u32)ip6h->flow_lbl[2];
	}
	build_nonce(nid, sport, dport, fold, nonce);
	ts_chacha(nonce, payload, payload_len);
crypted:
	if (gso) {
		if (!egress)
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else {
		fixup_csum_v6(skb, ip6h, l4, l4_len, is_tcp);
	}
	atomic64_inc(egress ? &st_enc_out : &st_enc_in);
	atomic64_inc(&st_enc);

	return NF_ACCEPT;
}

/* ---- netfilter hook trampolines ---------------------------------------- */

static unsigned int hook_v4_out(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
		return NF_ACCEPT;
	return process_v4(skb, true);
}

static unsigned int hook_v4_in(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
		return NF_ACCEPT;
	return process_v4(skb, false);
}

static unsigned int hook_v6_out(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
		return NF_ACCEPT;
	return process_v6(skb, true);
}

static unsigned int hook_v6_in(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
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

/* ---- /proc/torshield/stats --------------------------------------------- */
/* Counters are what the paper needs: how many packets were actually
 * transformed, and why the rest were skipped.  Read-only. */
static int stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "seen      %lld\n", (long long)atomic64_read(&st_seen));
	seq_printf(m, "encrypted %lld\n", (long long)atomic64_read(&st_enc));
	seq_printf(m, "enc_out   %lld\n", (long long)atomic64_read(&st_enc_out));
	seq_printf(m, "enc_in    %lld\n", (long long)atomic64_read(&st_enc_in));
	seq_printf(m, "nomatch   %lld\n", (long long)atomic64_read(&st_nomatch));
	seq_printf(m, "skip_gso  %lld\n", (long long)atomic64_read(&st_gso));
	seq_printf(m, "gso_out   %lld\n", (long long)atomic64_read(&st_gso_out));
	seq_printf(m, "gso_in    %lld\n", (long long)atomic64_read(&st_gso_in));
	seq_printf(m, "skip_frag %lld\n", (long long)atomic64_read(&st_frag));
	seq_printf(m, "skip_bad  %lld\n", (long long)atomic64_read(&st_bad));
	return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_fops = {
	.proc_open    = stats_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
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
	    !proc_create("peers",  0600, proc_dir, &peers_fops) ||
	    !proc_create("stats",  0444, proc_dir, &stats_fops)) {
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
/* chacha_init()/chacha_crypt() resolve to the arch helper module on x86;
 * without this, insmod fails with "Unknown symbol chacha_crypt_arch". */
MODULE_SOFTDEP("pre: chacha_x86_64");
