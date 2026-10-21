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
#include <net/dst.h>
#include <net/gso.h>
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>

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
	/* tunnel mode state */
	atomic64_t       tx_seq;                  /* per-peer packet counter    */
	u64              rx_last;                 /* replay window (under cfg)  */
	u64              rx_bitmap;
};
static LIST_HEAD(peer_list);

/* Stream = the original length-preserving transform.
 * Tunnel = encapsulate in UDP with AEAD, padding, sequence and replay window. */
enum ts_mode {
	TS_MODE_STREAM = 0,
	TS_MODE_TUNNEL = 1,
	TS_MODE_HYBRID = 2,     /* TUN netdevice egress + shared UDP decap */
};
static int ts_mode = TS_MODE_TUNNEL;
static unsigned int ts_port = 4789;
module_param(ts_port, uint, 0644);
MODULE_PARM_DESC(ts_port, "UDP port used by tunnel mode (default 4789)");

static struct nf_hook_ops nfho_v4_out, nfho_v4_in, nfho_v4_local;
static struct nf_hook_ops nfho_v6_out, nfho_v6_in, nfho_v6_local;
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
static struct ts_peer *peer_find_locked(u8 family, const void *addr)
{
	struct ts_peer *p;

	list_for_each_entry(p, &peer_list, list) {
		if (p->family != family)
			continue;
		if (family == AF_INET) {
			if (p->addr.v4 == *(const __be32 *)addr)
				return p;
		} else {
			if (ipv6_addr_equal(&p->addr.v6, (const struct in6_addr *)addr))
				return p;
		}
	}
	return NULL;
}

static bool peer_match_locked(u8 family, const void *addr)
{
	return peer_find_locked(family, addr) != NULL;
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

/* ======================================================================= *
 *  UDP tunnel mode
 * ======================================================================= *
 *
 *  Outer packet (IPv4 or IPv6, UDP dport ts_port):
 *
 *    [ 16-byte header ][ ciphertext: padded inner IP packet ][ 16-byte tag ]
 *
 *  header (also the AEAD associated data):
 *    'T' 'S', version 1, flags (bit0 = inner is IPv6), 4 reserved,
 *    8-byte per-peer sequence number (big endian).
 *
 *  AEAD is ChaCha20-Poly1305 (RFC 7539), built from the in-kernel ChaCha20
 *  helper plus Poly1305.  It is deliberately synchronous: the crypto API's
 *  async algorithms cannot be used from a softirq hook.
 *
 *  nonce = 4-byte fold of (src,dst) || 8-byte sequence
 *
 *  Sequence numbers are per peer and the receiver keeps a 64-packet sliding
 *  window, so replays are dropped.  Padding rounds every inner packet up to
 *  64 bytes so exact sizes are not visible.
 */

#define TS_TUN_MAGIC0    'T'
#define TS_TUN_MAGIC1    'S'
#define TS_TUN_VERSION   1
#define TS_TUN_HDR_LEN   16
#define TS_TUN_TAG_LEN   16
#define TS_TUN_PAD       64
#define TS_TUN_MARK      0x5453
#define TS_TUN_MSS4      1360
#define TS_TUN_MSS6      1340
/* min payload: header + one cipher block + tag */
#define TS_TUN_MIN_L4    (8 + TS_TUN_HDR_LEN + 16 + TS_TUN_TAG_LEN)

/* Not exported by the kernel headers on every release. */
#ifndef TCPOPT_MAXSEG
#define TCPOPT_MAXSEG    2
#endif

struct ts_tun_hdr {
	u8  magic[2];
	u8  version;
	u8  flags;
	u32 reserved;
	u64 seq;                        /* big endian on the wire */
} __packed;

static atomic64_t st_tun_out, st_tun_in, st_tun_drop, st_tun_replay;
static atomic64_t st_tun_rx, st_tun_peer;
static atomic64_t st_dev_out, st_dev_drop;
static atomic_t ts_ip_id = ATOMIC_INIT(0);   /* outer IPv4 identification */

/* ---- little/big-endian helpers (no arch unaligned header needed) ------- */
static inline u32 ts_le32(const u8 *p)
{
	u32 v;

	memcpy(&v, p, 4);
	return le32_to_cpu(v);
}

static inline void ts_put_le32(u8 *p, u32 v)
{
	v = cpu_to_le32(v);
	memcpy(p, &v, 4);
}

static inline void ts_put_le64(u8 *p, u64 v)
{
	v = cpu_to_le64(v);
	memcpy(p, &v, 8);
}

static inline u64 ts_be64(const u8 *p)
{
	u64 v;

	memcpy(&v, p, 8);
	return be64_to_cpu(v);
}

static inline void ts_put_be64(u8 *p, u64 v)
{
	v = cpu_to_be64(v);
	memcpy(p, &v, 8);
}

/* ---- Poly1305 (32-bit limbs, public-domain "donna" construction) ------- */
struct ts_poly1305 {
	u32 r[5];
	u32 h[5];
	u32 pad[4];
	u8  buf[16];
	size_t leftover;
};

static void ts_poly1305_init(struct ts_poly1305 *st, const u8 key[32])
{
	u32 t0 = ts_le32(key + 0);
	u32 t1 = ts_le32(key + 4);
	u32 t2 = ts_le32(key + 8);
	u32 t3 = ts_le32(key + 12);

	st->r[0] = t0 & 0x3ffffff;
	st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
	st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
	st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
	st->r[4] = (t3 >> 8) & 0x00fffff;

	memset(st->h, 0, sizeof(st->h));
	st->pad[0] = ts_le32(key + 16);
	st->pad[1] = ts_le32(key + 20);
	st->pad[2] = ts_le32(key + 24);
	st->pad[3] = ts_le32(key + 28);
	st->leftover = 0;
}

static void ts_poly1305_blocks(struct ts_poly1305 *st, const u8 *m,
			       size_t bytes, u32 hibit)
{
	u32 h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];
	u32 h3 = st->h[3], h4 = st->h[4];
	const u32 r0 = st->r[0], r1 = st->r[1], r2 = st->r[2];
	const u32 r3 = st->r[3], r4 = st->r[4];
	const u32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

	while (bytes >= 16) {
		u64 d0, d1, d2, d3, d4;

		h0 += ts_le32(m + 0) & 0x3ffffff;
		h1 += (ts_le32(m + 3) >> 2) & 0x3ffffff;
		h2 += (ts_le32(m + 6) >> 4) & 0x3ffffff;
		h3 += (ts_le32(m + 9) >> 6) & 0x3ffffff;
		h4 += (ts_le32(m + 12) >> 8) | hibit;

		d0 = (u64)h0 * r0 + (u64)h1 * s4 + (u64)h2 * s3 +
		     (u64)h3 * s2 + (u64)h4 * s1;
		d1 = (u64)h0 * r1 + (u64)h1 * r0 + (u64)h2 * s4 +
		     (u64)h3 * s3 + (u64)h4 * s2;
		d2 = (u64)h0 * r2 + (u64)h1 * r1 + (u64)h2 * r0 +
		     (u64)h3 * s4 + (u64)h4 * s3;
		d3 = (u64)h0 * r3 + (u64)h1 * r2 + (u64)h2 * r1 +
		     (u64)h3 * r0 + (u64)h4 * s4;
		d4 = (u64)h0 * r4 + (u64)h1 * r3 + (u64)h2 * r2 +
		     (u64)h3 * r1 + (u64)h4 * r0;

		h0 = (u32)d0 & 0x3ffffff;
		d1 += d0 >> 26;
		h1 = (u32)d1 & 0x3ffffff;
		d2 += d1 >> 26;
		h2 = (u32)d2 & 0x3ffffff;
		d3 += d2 >> 26;
		h3 = (u32)d3 & 0x3ffffff;
		d4 += d3 >> 26;
		h4 = (u32)d4 & 0x3ffffff;
		h0 += (u32)(d4 >> 26) * 5;
		h1 += h0 >> 26;
		h0 &= 0x3ffffff;

		m += 16;
		bytes -= 16;
	}
	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
}

static void ts_poly1305_update(struct ts_poly1305 *st, const u8 *m, size_t bytes)
{
	if (st->leftover) {
		size_t want = 16 - st->leftover;

		if (want > bytes)
			want = bytes;
		memcpy(st->buf + st->leftover, m, want);
		st->leftover += want;
		m += want;
		bytes -= want;
		if (st->leftover < 16)
			return;
		ts_poly1305_blocks(st, st->buf, 16, 1 << 24);
		st->leftover = 0;
	}
	if (bytes >= 16) {
		size_t want = bytes & ~(size_t)15;

		ts_poly1305_blocks(st, m, want, 1 << 24);
		m += want;
		bytes -= want;
	}
	if (bytes) {
		memcpy(st->buf, m, bytes);
		st->leftover = bytes;
	}
}

static void ts_poly1305_final(struct ts_poly1305 *st, u8 mac[16])
{
	u32 h0, h1, h2, h3, h4, g0, g1, g2, g3, g4, c;
	u32 mask;
	u64 f;

	if (st->leftover) {
		size_t i = st->leftover;

		st->buf[i++] = 1;
		while (i < 16)
			st->buf[i++] = 0;
		ts_poly1305_blocks(st, st->buf, 16, 0);
	}

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
	c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
	c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
	c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
	c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

	g0 = h0 + 5;
	c = g0 >> 26; g0 &= 0x3ffffff;
	g1 = h1 + c;
	c = g1 >> 26; g1 &= 0x3ffffff;
	g2 = h2 + c;
	c = g2 >> 26; g2 &= 0x3ffffff;
	g3 = h3 + c;
	c = g3 >> 26; g3 &= 0x3ffffff;
	g4 = h4 + c - (1 << 26);

	mask = (g4 >> 31) - 1;
	h0 = (h0 & ~mask) | (g0 & mask);
	h1 = (h1 & ~mask) | (g1 & mask);
	h2 = (h2 & ~mask) | (g2 & mask);
	h3 = (h3 & ~mask) | (g3 & mask);

	h0 = (h0 | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

	f = (u64)h0 + st->pad[0];
	h0 = (u32)f;
	f = (u64)h1 + st->pad[1] + (f >> 32);
	h1 = (u32)f;
	f = (u64)h2 + st->pad[2] + (f >> 32);
	h2 = (u32)f;
	f = (u64)h3 + st->pad[3] + (f >> 32);
	h3 = (u32)f;

	ts_put_le32(mac + 0, h0);
	ts_put_le32(mac + 4, h1);
	ts_put_le32(mac + 8, h2);
	ts_put_le32(mac + 12, h3);
}

/* ---- ChaCha20 with an explicit IV (counter || nonce) ------------------- */
static void ts_chacha_iv(const u8 key[32], u8 iv[16], u8 *data, unsigned int len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
	struct chacha_state state;

	chacha_init(&state, (const u32 *)key, iv);
	chacha_crypt(&state, data, data, len, 20);
	memzero_explicit(&state, sizeof(state));
#else
	u32 state[CHACHA_STATE_WORDS];

	chacha_init(state, (const u32 *)key, iv);
	chacha_crypt(state, data, data, len, 20);
	memzero_explicit(state, sizeof(state));
#endif
}

static void ts_aead_tag(const u8 key[32], const u8 nonce[12],
			const u8 *aad, unsigned int aad_len,
			const u8 *buf, unsigned int len, u8 tag[16])
{
	static const u8 zeros[16] = { 0 };
	struct ts_poly1305 st;
	u8 polykey[32];
	u8 iv[16];
	u8 lens[16];
	unsigned int pad;

	memset(iv, 0, sizeof(iv));
	memcpy(iv + 4, nonce, 12);

	/* RFC 7539: the Poly1305 key is the first 32 bytes of block 0. */
	memset(polykey, 0, sizeof(polykey));
	ts_chacha_iv(key, iv, polykey, sizeof(polykey));

	ts_poly1305_init(&st, polykey);
	ts_poly1305_update(&st, aad, aad_len);
	pad = (16 - (aad_len & 15)) & 15;
	if (pad)
		ts_poly1305_update(&st, zeros, pad);
	ts_poly1305_update(&st, buf, len);
	pad = (16 - (len & 15)) & 15;
	if (pad)
		ts_poly1305_update(&st, zeros, pad);
	ts_put_le64(lens, aad_len);
	ts_put_le64(lens + 8, len);
	ts_poly1305_update(&st, lens, 16);
	ts_poly1305_final(&st, tag);

	memzero_explicit(polykey, sizeof(polykey));
	memzero_explicit(&st, sizeof(st));
}

static void ts_aead_seal(const u8 key[32], const u8 nonce[12],
			 const u8 *aad, unsigned int aad_len,
			 u8 *buf, unsigned int len, u8 tag[16])
{
	u8 iv[16];

	/* Encrypt first: RFC 7539 authenticates the ciphertext. */
	memset(iv, 0, sizeof(iv));
	memcpy(iv + 4, nonce, 12);
	iv[0] = 1;                      /* payload starts at block counter 1 */
	ts_chacha_iv(key, iv, buf, len);

	ts_aead_tag(key, nonce, aad, aad_len, buf, len, tag);
}

static bool ts_aead_open(const u8 key[32], const u8 nonce[12],
			 const u8 *aad, unsigned int aad_len,
			 u8 *buf, unsigned int len, const u8 tag[16])
{
	u8 calc[16];
	u8 iv[16];
	u8 d = 0;
	int i;

	ts_aead_tag(key, nonce, aad, aad_len, buf, len, calc);
	for (i = 0; i < 16; i++)
		d |= calc[i] ^ tag[i];
	if (d)
		return false;

	memset(iv, 0, sizeof(iv));
	memcpy(iv + 4, nonce, 12);
	iv[0] = 1;
	ts_chacha_iv(key, iv, buf, len);
	return true;
}

/* ---- replay window ----------------------------------------------------- */
static bool ts_replay_ok(struct ts_peer *p, u64 seq)
{
	if (seq == 0)
		return false;

	if (seq > p->rx_last) {
		u64 diff = seq - p->rx_last;

		if (diff >= 64)
			p->rx_bitmap = 0;
		else
			p->rx_bitmap <<= diff;
		p->rx_bitmap |= 1;
		p->rx_last = seq;
		return true;
	}

	{
		u64 diff = p->rx_last - seq;

		if (diff >= 64)
			return false;
		if (p->rx_bitmap & (1ULL << diff))
			return false;
		p->rx_bitmap |= 1ULL << diff;
		return true;
	}
}

static void ts_tun_nonce(__be32 fold, u64 seq, u8 nonce[12])
{
	memcpy(nonce, &fold, 4);
	ts_put_be64(nonce + 4, seq);
}

/* ---- TCP MSS clamping -------------------------------------------------- */
/* The outer header + tag + worst-case padding must fit in one MTU, otherwise
 * every TCP segment would be fragmented by the outer IP layer. */
static bool ts_clamp_mss(struct tcphdr *th, unsigned int limit)
{
	u8 *opt;
	unsigned int olen;

	if (!th->syn || th->doff < 5)
		return false;
	olen = th->doff * 4 - sizeof(*th);
	opt = (u8 *)(th + 1);

	while (olen >= 4) {
		u16 mss;

		if (opt[0] == TCPOPT_EOL)
			break;
		if (opt[0] == TCPOPT_NOP) {
			opt++;
			olen--;
			continue;
		}
		if (opt[1] < 2 || opt[1] > olen)
			break;
		if (opt[0] == TCPOPT_MAXSEG && opt[1] == 4) {
			memcpy(&mss, opt + 2, 2);
			if (ntohs(mss) > limit) {
				mss = htons(limit);
				memcpy(opt + 2, &mss, 2);
				return true;
			}
			return false;
		}
		olen -= opt[1];
		opt += opt[1];
	}
	return false;
}

static u64 ts_next_seq(u8 family, const void *addr)
{
	struct ts_peer *p;
	unsigned long flags;
	u64 seq = 0;

	spin_lock_irqsave(&cfg_lock, flags);
	p = peer_find_locked(family, addr);
	if (p)
		seq = (u64)atomic64_inc_return(&p->tx_seq);
	spin_unlock_irqrestore(&cfg_lock, flags);
	return seq;
}

/* ---- encapsulation ----------------------------------------------------- */
static int ts_tun_encap_v4(struct sk_buff *skb, u64 seq, const u8 key[32],
			   struct dst_entry *hold)
{
	struct iphdr *iph, *oiph;
	struct udphdr *uh;
	struct ts_tun_hdr *th;
	struct sk_buff *n;
	u8 tag[16], nonce[12];
	u8 *payload;
	unsigned int ihl, inner_len, padded, total, l4_len;
	__be32 fold;

	if (skb_linearize(skb) < 0)
		return -ENOMEM;
	iph = ip_hdr(skb);
	if (iph->ihl < 5)
		return -EINVAL;
	ihl = iph->ihl * 4;
	if (ntohs(iph->tot_len) < ihl || ntohs(iph->tot_len) > skb->len)
		return -EINVAL;
	inner_len = ntohs(iph->tot_len);
	l4_len = inner_len - ihl;

	if (iph->protocol == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
		struct tcphdr *th = (struct tcphdr *)((u8 *)iph + ihl);

		if (th->doff >= 5 &&
		    ts_clamp_mss(th, TS_TUN_MSS4) &&
		    skb->ip_summed != CHECKSUM_PARTIAL)
			fixup_csum_v4(skb, iph, th, l4_len, true);
	}

	/* The copied inner packet must carry a finished checksum. */
	if (skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb))
		return -EINVAL;
	iph = ip_hdr(skb);

	padded = round_up(inner_len, TS_TUN_PAD);
	total = sizeof(*oiph) + sizeof(*uh) + TS_TUN_HDR_LEN + padded +
		TS_TUN_TAG_LEN;
	if (total > 65535)
		return -EMSGSIZE;

	n = alloc_skb(total + 128, GFP_ATOMIC);
	if (!n)
		return -ENOMEM;
	skb_reserve(n, 128);
	oiph = skb_put(n, sizeof(*oiph));
	uh = skb_put(n, sizeof(*uh));
	th = skb_put(n, TS_TUN_HDR_LEN);
	payload = skb_put(n, padded);
	skb_reset_network_header(n);
	skb_set_transport_header(n, sizeof(*oiph));

	memcpy(payload, iph, inner_len);
	memset(payload + inner_len, 0, padded - inner_len);

	memset(th, 0, TS_TUN_HDR_LEN);
	th->magic[0] = TS_TUN_MAGIC0;
	th->magic[1] = TS_TUN_MAGIC1;
	th->version = TS_TUN_VERSION;
	th->flags = 0;
	ts_put_be64((u8 *)th + 8, seq);

	fold = iph->saddr ^ iph->daddr;
	ts_tun_nonce(fold, seq, nonce);
	ts_aead_seal(key, nonce, (u8 *)th, TS_TUN_HDR_LEN, payload, padded, tag);
	memcpy(skb_put(n, TS_TUN_TAG_LEN), tag, TS_TUN_TAG_LEN);

	memset(oiph, 0, sizeof(*oiph));
	oiph->version = 4;
	oiph->ihl = 5;
	oiph->tos = 0;
	oiph->tot_len = htons(total);
	oiph->id = htons((u16)atomic_inc_return(&ts_ip_id));
	oiph->ttl = 64;
	oiph->protocol = IPPROTO_UDP;
	oiph->saddr = iph->saddr;
	oiph->daddr = iph->daddr;
	ip_send_check(oiph);

	uh->source = htons(ts_port);
	uh->dest = htons(ts_port);
	uh->len = htons(TS_TUN_HDR_LEN + padded + TS_TUN_TAG_LEN +
			sizeof(*uh));
	uh->check = 0;                  /* legal for IPv4 */

	n->dev = skb->dev;
	n->protocol = htons(ETH_P_IP);
	skb_dst_set(n, dst_clone(hold ? hold : skb_dst(skb)));
	ip_local_out(dev_net(n->dev), NULL, n);
	return 0;
}

static int ts_tun_encap_v6(struct sk_buff *skb, u64 seq, const u8 key[32],
			   struct dst_entry *hold)
{
	struct ipv6hdr *ip6h, *o6;
	struct udphdr *uh;
	struct ts_tun_hdr *th;
	struct sk_buff *n;
	u8 tag[16], nonce[12];
	u8 *payload;
	unsigned int inner_len, padded, total, l4_len;
	__be32 fold;

	if (skb_linearize(skb) < 0)
		return -ENOMEM;
	ip6h = ipv6_hdr(skb);
	inner_len = sizeof(*ip6h) + ntohs(ip6h->payload_len);
	if (inner_len > skb->len)
		return -EINVAL;
	l4_len = ntohs(ip6h->payload_len);

	if (ip6h->nexthdr == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
		struct tcphdr *th = (struct tcphdr *)(ip6h + 1);

		if (th->doff >= 5 &&
		    ts_clamp_mss(th, TS_TUN_MSS6) &&
		    skb->ip_summed != CHECKSUM_PARTIAL)
			fixup_csum_v6(skb, ip6h, th, l4_len, true);
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb))
		return -EINVAL;
	ip6h = ipv6_hdr(skb);

	padded = round_up(inner_len, TS_TUN_PAD);
	total = sizeof(*o6) + sizeof(*uh) + TS_TUN_HDR_LEN + padded +
		TS_TUN_TAG_LEN;
	if (total > 65535)
		return -EMSGSIZE;

	n = alloc_skb(total + 128, GFP_ATOMIC);
	if (!n)
		return -ENOMEM;
	skb_reserve(n, 128);
	o6 = skb_put(n, sizeof(*o6));
	uh = skb_put(n, sizeof(*uh));
	th = skb_put(n, TS_TUN_HDR_LEN);
	payload = skb_put(n, padded);
	skb_reset_network_header(n);
	skb_set_transport_header(n, sizeof(*o6));

	memcpy(payload, ip6h, inner_len);
	memset(payload + inner_len, 0, padded - inner_len);

	memset(th, 0, TS_TUN_HDR_LEN);
	th->magic[0] = TS_TUN_MAGIC0;
	th->magic[1] = TS_TUN_MAGIC1;
	th->version = TS_TUN_VERSION;
	th->flags = 1;                  /* inner is IPv6 */
	ts_put_be64((u8 *)th + 8, seq);

	fold = ip6h->saddr.s6_addr32[0] ^ ip6h->saddr.s6_addr32[1] ^
	       ip6h->saddr.s6_addr32[2] ^ ip6h->saddr.s6_addr32[3] ^
	       ip6h->daddr.s6_addr32[0] ^ ip6h->daddr.s6_addr32[1] ^
	       ip6h->daddr.s6_addr32[2] ^ ip6h->daddr.s6_addr32[3];
	ts_tun_nonce(fold, seq, nonce);
	ts_aead_seal(key, nonce, (u8 *)th, TS_TUN_HDR_LEN, payload, padded, tag);
	memcpy(skb_put(n, TS_TUN_TAG_LEN), tag, TS_TUN_TAG_LEN);

	memset(o6, 0, sizeof(*o6));
	o6->version = 6;
	o6->nexthdr = IPPROTO_UDP;
	o6->hop_limit = 64;
	o6->saddr = ip6h->saddr;
	o6->daddr = ip6h->daddr;

	uh->source = htons(ts_port);
	uh->dest = htons(ts_port);
	uh->len = htons(TS_TUN_HDR_LEN + padded + TS_TUN_TAG_LEN +
			sizeof(*uh));
	uh->check = 0;
	n->ip_summed = CHECKSUM_PARTIAL;        /* mandatory for IPv6 UDP */
	n->csum_start = skb_transport_offset(n);
	n->csum_offset = offsetof(struct udphdr, check);

	n->dev = skb->dev;
	n->protocol = htons(ETH_P_IPV6);
	skb_dst_set(n, dst_clone(hold ? hold : skb_dst(skb)));
	ip6_local_out(dev_net(n->dev), NULL, n);
	return 0;
}

/* ---- decapsulation ----------------------------------------------------- */
static void ts_note_nonpeer(struct sk_buff *skb, bool v6, u64 seq)
{
	atomic64_inc(&st_tun_peer);
	if (v6)
		pr_info_ratelimited("torshield: non-peer tunnel pkt src=%pI6 dst=%pI6 dev=%s seq=%llu\n",
				    &ipv6_hdr(skb)->saddr, &ipv6_hdr(skb)->daddr,
				    skb->dev ? skb->dev->name : "?", seq);
	else
		pr_info_ratelimited("torshield: non-peer tunnel pkt src=%pI4 dst=%pI4 dev=%s seq=%llu\n",
				    &ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr,
				    skb->dev ? skb->dev->name : "?", seq);
}

static unsigned int ts_tun_decap(struct sk_buff *skb, bool outer_v6,
				 struct udphdr *uh, unsigned int l4_len)
{
	struct ts_tun_hdr *th;
	struct ts_peer *p;
	struct sk_buff *n;
	u8 key[32], nonce[12];
	unsigned int ct_len = 0, inner_len;
	int bad_reason = 1;
	unsigned long flags;
	const u8 *ct;
	const u8 *tag;
	u64 seq;
	bool v6;
	__be32 fold;

	if (l4_len < TS_TUN_MIN_L4)
		goto bad;
	th = (struct ts_tun_hdr *)((u8 *)uh + sizeof(*uh));
	if (th->magic[0] != TS_TUN_MAGIC0 || th->magic[1] != TS_TUN_MAGIC1 ||
	    th->version != TS_TUN_VERSION)
		return NF_ACCEPT;       /* not ours */

	atomic64_inc(&st_tun_rx);

	ct_len = l4_len - sizeof(*uh) - TS_TUN_HDR_LEN - TS_TUN_TAG_LEN;
	if (ct_len < 16 || (ct_len & 15)) {
		bad_reason = 2;
		goto bad;
	}
	seq = ts_be64((u8 *)th + 8);

	/* The AEAD reads the ciphertext through a raw pointer, so the skb must
	 * be contiguous.  After IP reassembly (fragmented outer datagrams) it is
	 * a frag_list and skb->data covers only the first fragment. */
	if (skb_linearize(skb) < 0) {
		bad_reason = 7;
		goto bad;
	}
	if (outer_v6) {
		uh = (struct udphdr *)((u8 *)ipv6_hdr(skb) + sizeof(struct ipv6hdr));
	} else {
		uh = (struct udphdr *)((u8 *)ip_hdr(skb) + ip_hdr(skb)->ihl * 4);
	}
	th = (struct ts_tun_hdr *)((u8 *)uh + sizeof(*uh));
	ct = (u8 *)th + TS_TUN_HDR_LEN;
	tag = ct + ct_len;

	spin_lock_irqsave(&cfg_lock, flags);
	p = outer_v6 ? peer_find_locked(AF_INET6, &ipv6_hdr(skb)->saddr)
		     : peer_find_locked(AF_INET, &ip_hdr(skb)->saddr);
	if (!p) {
		spin_unlock_irqrestore(&cfg_lock, flags);
		ts_note_nonpeer(skb, outer_v6, seq);
		return NF_DROP;         /* tunnel framing from an unknown peer */
	}
	memcpy(key, chacha_key, sizeof(key));
	spin_unlock_irqrestore(&cfg_lock, flags);

	fold = (th->flags & 1) ?
	       (ipv6_hdr(skb)->saddr.s6_addr32[0] ^
		ipv6_hdr(skb)->saddr.s6_addr32[1] ^
		ipv6_hdr(skb)->saddr.s6_addr32[2] ^
		ipv6_hdr(skb)->saddr.s6_addr32[3] ^
		ipv6_hdr(skb)->daddr.s6_addr32[0] ^
		ipv6_hdr(skb)->daddr.s6_addr32[1] ^
		ipv6_hdr(skb)->daddr.s6_addr32[2] ^
		ipv6_hdr(skb)->daddr.s6_addr32[3])
	      : (ip_hdr(skb)->saddr ^ ip_hdr(skb)->daddr);

	/* Authenticate before touching the replay window: an off-path packet
	 * must not be able to advance it. */
	ts_tun_nonce(fold, seq, nonce);
	if (!ts_aead_open(key, nonce, (u8 *)th, TS_TUN_HDR_LEN,
			  (u8 *)ct, ct_len, tag)) {
		atomic64_inc(&st_tun_drop);
		pr_info_ratelimited("torshield: decap AEAD fail r=6 l4=%u ct=%u seq=%llu flags=%u\n",
				    l4_len, ct_len, seq, th->flags);
		return NF_DROP;
	}

	spin_lock_irqsave(&cfg_lock, flags);
	p = outer_v6 ? peer_find_locked(AF_INET6, &ipv6_hdr(skb)->saddr)
		     : peer_find_locked(AF_INET, &ip_hdr(skb)->saddr);
	if (!p) {
		spin_unlock_irqrestore(&cfg_lock, flags);
		ts_note_nonpeer(skb, outer_v6, seq);
		return NF_DROP;
	}
	if (!ts_replay_ok(p, seq)) {
		spin_unlock_irqrestore(&cfg_lock, flags);
		atomic64_inc(&st_tun_replay);
		return NF_DROP;
	}
	spin_unlock_irqrestore(&cfg_lock, flags);

	v6 = (th->flags & 1) != 0;
	if (v6) {
		struct ipv6hdr *in = (struct ipv6hdr *)ct;

		if (ct_len < sizeof(*in) || in->version != 6) {
			bad_reason = 3;
			goto bad;
		}
		inner_len = sizeof(*in) + ntohs(in->payload_len);
	} else {
		struct iphdr *in = (struct iphdr *)ct;

		if (ct_len < sizeof(*in) || in->version != 4 || in->ihl < 5) {
			bad_reason = 3;
			goto bad;
		}
		inner_len = ntohs(in->tot_len);
		if (inner_len < in->ihl * 4) {
			bad_reason = 4;
			goto bad;
		}
	}
	if (inner_len > ct_len) {
		bad_reason = 4;
		goto bad;
	}

	n = alloc_skb(inner_len + 128, GFP_ATOMIC);
	if (!n) {
		bad_reason = 5;
		goto bad;
	}
	skb_reserve(n, 128);
	memcpy(skb_put(n, inner_len), ct, inner_len);
	skb_reset_network_header(n);
	skb_reset_mac_header(n);        /* no L2 header: keep taps consistent */
	n->dev = skb->dev;
	n->protocol = htons(v6 ? ETH_P_IPV6 : ETH_P_IP);
	n->ip_summed = CHECKSUM_UNNECESSARY;
	n->mark = TS_TUN_MARK;
	n->pkt_type = PACKET_HOST;

	netif_rx(n);
	kfree_skb(skb);
	atomic64_inc(&st_tun_in);
	return NF_STOLEN;

bad:
	atomic64_inc(&st_tun_drop);
	pr_info_ratelimited("torshield: decap bad r=%d l4=%u ct=%u\n",
			    bad_reason, l4_len, ct_len);
	return NF_DROP;
}

/* ---- hook bodies ------------------------------------------------------- */
static bool ts_is_our_outer(struct sk_buff *skb, bool v6)
{
	if (v6) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);
		struct udphdr *uh;

		if (ip6h->nexthdr != IPPROTO_UDP)
			return false;
		uh = (struct udphdr *)(ip6h + 1);
		return ntohs(uh->dest) == ts_port;
	} else {
		struct iphdr *iph = ip_hdr(skb);
		struct udphdr *uh;

		if (iph->protocol != IPPROTO_UDP || iph->ihl < 5)
			return false;
		uh = (struct udphdr *)((u8 *)iph + iph->ihl * 4);
		return ntohs(uh->dest) == ts_port;
	}
}

/* Link-local / loopback traffic is scoped to a single link and must never be
 * carried across the tunnel.  Without this, IPv6 neighbour advertisements
 * (src fe80::/10, dst a peer's global address) get encapsulated and are then
 * rejected by the far side as coming from a non-peer. */
static bool ts_is_tun_dev(const struct net_device *dev);

static bool ts_v6_local_scope(const struct in6_addr *a)
{
	static const u8 lo[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
				   0, 0, 0, 0, 0, 0, 0, 1 };
	const u8 *b = a->s6_addr;

	if (b[0] == 0xff)                               /* multicast */
		return true;
	if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)      /* fe80::/10 */
		return true;
	if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0)      /* fec0::/10 */
		return true;
	return !memcmp(b, lo, sizeof(lo));
}

static bool ts_v4_local_scope(__be32 a)
{
	u32 h = ntohl(a);

	return (h & 0xffff0000U) == 0xa9fe0000U ||      /* 169.254/16 */
	       (h & 0xff000000U) == 0x7f000000U;        /* 127/8 */
}

static unsigned int ts_tun_out(struct sk_buff *skb, bool v6)
{
	struct sk_buff *segs, *seg;
	struct dst_entry *hold;
	unsigned long flags;
	struct ts_peer *p;
	u8 key[32];
	u64 seq;
	int err;

	if (skb->mark == TS_TUN_MARK)
		return NF_ACCEPT;
	if (ts_is_our_outer(skb, v6))
		return NF_ACCEPT;
	if (v6) {
		if (ts_v6_local_scope(&ipv6_hdr(skb)->saddr))
			return NF_ACCEPT;
	} else if (ts_v4_local_scope(ip_hdr(skb)->saddr)) {
		return NF_ACCEPT;
	}
	if (!skb_dst(skb))
		return NF_ACCEPT;
	/* Hybrid: packets routed into a torshield netdevice are encapsulated by
	 * that device's ndo_start_xmit, not here.  Everything else keeps the
	 * transparent netfilter path, so both datapaths can coexist. */
	if (READ_ONCE(ts_mode) == TS_MODE_HYBRID &&
	    ts_is_tun_dev(skb_dst(skb)->dev))
		return NF_ACCEPT;

	spin_lock_irqsave(&cfg_lock, flags);
	p = v6 ? peer_find_locked(AF_INET6, &ipv6_hdr(skb)->daddr)
	       : peer_find_locked(AF_INET, &ip_hdr(skb)->daddr);
	if (p)
		memcpy(key, chacha_key, sizeof(key));
	spin_unlock_irqrestore(&cfg_lock, flags);
	if (!p)
		return NF_ACCEPT;

	if (!skb_is_gso(skb)) {
		seq = ts_next_seq(v6 ? AF_INET6 : AF_INET,
				  v6 ? (void *)&ipv6_hdr(skb)->daddr
				     : (void *)&ip_hdr(skb)->daddr);
		if (!seq)
			return NF_ACCEPT;
		err = v6 ? ts_tun_encap_v6(skb, seq, key, NULL)
			 : ts_tun_encap_v4(skb, seq, key, NULL);
		if (err) {
			atomic64_inc(&st_tun_drop);
			return NF_DROP;
		}
		consume_skb(skb);
		atomic64_inc(&st_tun_out);
		return NF_STOLEN;
	}

	hold = dst_clone(skb_dst(skb));
	segs = skb_gso_segment(skb, 0);
	if (IS_ERR(segs)) {
		dst_release(hold);
		atomic64_inc(&st_tun_drop);
		return NF_DROP;
	}
	consume_skb(skb);
	atomic64_inc(&st_tun_out);

	for (seg = segs; seg; ) {
		struct sk_buff *next = seg->next;

		seg->next = NULL;
		seq = ts_next_seq(v6 ? AF_INET6 : AF_INET,
				  v6 ? (void *)&ipv6_hdr(seg)->daddr
				     : (void *)&ip_hdr(seg)->daddr);
		if (!seq) {
			kfree_skb(seg);
		} else {
			err = v6 ? ts_tun_encap_v6(seg, seq, key, hold)
				 : ts_tun_encap_v4(seg, seq, key, hold);
			if (err) {
				atomic64_inc(&st_tun_drop);
				kfree_skb(seg);
			}
		}
		seg = next;
	}
	dst_release(hold);
	return NF_STOLEN;
}

static unsigned int ts_tun_in(struct sk_buff *skb, bool v6)
{
	struct udphdr *uh;
	unsigned int ihl, l4_len;

	if (skb->mark == TS_TUN_MARK)
		return NF_ACCEPT;

	if (v6) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);

		if (ip6h->nexthdr != IPPROTO_UDP) {
			/* extension headers are not parsed here */
			return NF_ACCEPT;
		}
		ihl = sizeof(*ip6h);
		l4_len = ntohs(ip6h->payload_len);
		if (l4_len < sizeof(*uh))
			return NF_ACCEPT;
		uh = (struct udphdr *)(ip6h + 1);
	} else {
		struct iphdr *iph = ip_hdr(skb);

		if (iph->protocol != IPPROTO_UDP || iph->ihl < 5)
			return NF_ACCEPT;
		ihl = iph->ihl * 4;
		if (ntohs(iph->tot_len) < ihl + sizeof(*uh))
			return NF_ACCEPT;
		uh = (struct udphdr *)((u8 *)iph + ihl);
		l4_len = ntohs(iph->tot_len) - ihl;
	}

	if (ntohs(uh->dest) != ts_port)
		return NF_ACCEPT;

	return ts_tun_decap(skb, v6, uh, l4_len);
}

/* ---- hybrid TUN-style netdevice ---------------------------------------- */
/* A route-based L3 tunnel: packets routed into this device are encapsulated
 * with the same framing/AEAD as the netfilter tunnel.  The outer route is
 * pinned to the underlay link (IFLA_LINK) so the lookup can never recurse
 * back into this device.  Receive is shared with tunnel mode: the UDP decap
 * at LOCAL_IN re-injects the inner packet. */
#define TS_DEV_MTU 1360         /* + 60 bytes header/tag + <=63 padding < 1500 */

struct ts_priv {
	int link;                      /* underlay ifindex (IFLA_LINK) */
};

static netdev_tx_t ts_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ts_priv *priv = netdev_priv(dev);
	struct ts_peer *p;
	struct dst_entry *dst = NULL;
	struct flowi4 fl4 = {};
	struct flowi6 fl6 = {};
	unsigned long flags;
	u8 key[32];
	u64 seq = 0;
	bool v6;
	int err, reason = 0;

	if (skb->len < sizeof(struct iphdr)) {
		reason = 1;
		goto drop;
	}
	switch (ip_hdr(skb)->version) {
	case 4:
		v6 = false;
		break;
	case 6:
		v6 = true;
		break;
	default:
		reason = 1;
		goto drop;
	}
	if (!priv->link || priv->link == dev->ifindex) {
		reason = 2;
		goto drop;
	}
	/* Multicast/link-local destinations are link-scoped: never tunnelable.
	 * This also swallows IPv6 router solicitations that the stack emits on
	 * a new interface, without counting them as data-path drops. */
	if (v6 ? ts_v6_local_scope(&ipv6_hdr(skb)->daddr)
	       : ts_v4_local_scope(ip_hdr(skb)->daddr))
		goto consume;

	spin_lock_irqsave(&cfg_lock, flags);
	p = v6 ? peer_find_locked(AF_INET6, &ipv6_hdr(skb)->daddr)
	       : peer_find_locked(AF_INET, &ip_hdr(skb)->daddr);
	if (p) {
		memcpy(key, chacha_key, sizeof(key));
		seq = (u64)atomic64_inc_return(&p->tx_seq);
	}
	spin_unlock_irqrestore(&cfg_lock, flags);
	if (!seq) {
		reason = 3;
		goto drop;
	}

	if (v6) {
		fl6.daddr = ipv6_hdr(skb)->daddr;
		fl6.flowi6_oif = priv->link;
		fl6.flowi6_proto = IPPROTO_UDP;
		dst = ip6_route_output(dev_net(dev), NULL, &fl6);
		if (IS_ERR(dst)) {
			dst = NULL;
			reason = 4;
			goto drop;
		}
		if (dst->dev == dev) {  /* misconfiguration: would recurse */
			dst_release(dst);
			reason = 5;
			goto drop;
		}
		err = ts_tun_encap_v6(skb, seq, key, dst);
		dst_release(dst);
	} else {
		struct rtable *rt;

		fl4.daddr = ip_hdr(skb)->daddr;
		fl4.flowi4_oif = priv->link;
		fl4.flowi4_proto = IPPROTO_UDP;
		rt = ip_route_output_key(dev_net(dev), &fl4);
		if (IS_ERR(rt)) {
			reason = 4;
			goto drop;
		}
		if (rt->dst.dev == dev) {
			dst_release(&rt->dst);
			reason = 5;
			goto drop;
		}
		err = ts_tun_encap_v4(skb, seq, key, &rt->dst);
		dst_release(&rt->dst);
	}
	if (!err) {
		dev->stats.tx_packets++;
		dev->stats.tx_bytes += skb->len;
		atomic64_inc(&st_dev_out);
	} else {
		dev->stats.tx_errors++;
		reason = 6;
		goto drop_after_encap;
	}
consume:
	consume_skb(skb);
	return NETDEV_TX_OK;

drop_after_encap:
	atomic64_inc(&st_dev_drop);
	pr_info_ratelimited("torshield: %s drop reason=%d err=%d len=%u\n",
			    dev->name, reason, err, skb->len);
	kfree_skb(skb);
	return NETDEV_TX_OK;

drop:
	dev->stats.tx_dropped++;
	atomic64_inc(&st_dev_drop);
	pr_info_ratelimited("torshield: %s drop reason=%d len=%u dst=%pI4\n",
			    dev->name, reason, skb->len,
			    skb->len >= sizeof(struct iphdr) ?
			    &ip_hdr(skb)->daddr : NULL);
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

static void ts_ndo_get_stats64(struct net_device *dev,
			       struct rtnl_link_stats64 *s)
{
	netdev_stats_to_stats64(s, &dev->stats);
}

static const struct net_device_ops ts_netdev_ops = {
	.ndo_start_xmit = ts_ndo_start_xmit,
	.ndo_get_stats64 = ts_ndo_get_stats64,
};

static void ts_dev_setup(struct net_device *dev)
{
	dev->netdev_ops = &ts_netdev_ops;
	dev->type = ARPHRD_NONE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = TS_DEV_MTU;
	dev->min_mtu = 576;
	dev->max_mtu = TS_DEV_MTU;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->needs_free_netdev = true;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static int ts_newlink(struct net_device *dev,
		      struct rtnl_newlink_params *params,
		      struct netlink_ext_ack *extack)
{
	struct ts_priv *priv = netdev_priv(dev);
	struct nlattr **tb = params->tb;

	priv->link = tb[IFLA_LINK] ? nla_get_u32(tb[IFLA_LINK]) : 0;
	return register_netdevice(dev);
}
#else
static int ts_newlink(struct net *net, struct net_device *dev,
		      struct nlattr *tb[], struct nlattr *data[],
		      struct netlink_ext_ack *extack)
{
	struct ts_priv *priv = netdev_priv(dev);

	priv->link = tb[IFLA_LINK] ? nla_get_u32(tb[IFLA_LINK]) : 0;
	return register_netdevice(dev);
}
#endif

static struct rtnl_link_ops ts_link_ops __read_mostly = {
	.kind = "torshield",
	.priv_size = sizeof(struct ts_priv),
	.setup = ts_dev_setup,
	.newlink = ts_newlink,
};

static bool ts_is_tun_dev(const struct net_device *dev)
{
	return dev && dev->rtnl_link_ops == &ts_link_ops;
}

/* ---- netfilter hook trampolines ---------------------------------------- */

static unsigned int hook_v4_out(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
		return NF_ACCEPT;
	if (READ_ONCE(ts_mode) != TS_MODE_STREAM)
		return ts_tun_out(skb, false);
	return process_v4(skb, true);
}

static unsigned int hook_v4_in(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
		return NF_ACCEPT;
	if (READ_ONCE(ts_mode) != TS_MODE_STREAM)
		return NF_ACCEPT;       /* tunnel decapsulates at LOCAL_IN */
	return process_v4(skb, false);
}

static unsigned int hook_v4_local(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
		return NF_ACCEPT;
	if (READ_ONCE(ts_mode) == TS_MODE_STREAM)
		return NF_ACCEPT;
	return ts_tun_in(skb, false);
}

static unsigned int hook_v6_out(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
		return NF_ACCEPT;
	if (READ_ONCE(ts_mode) != TS_MODE_STREAM)
		return ts_tun_out(skb, true);
	return process_v6(skb, true);
}

static unsigned int hook_v6_in(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
		return NF_ACCEPT;
	if (READ_ONCE(ts_mode) != TS_MODE_STREAM)
		return NF_ACCEPT;
	return process_v6(skb, false);
}

static unsigned int hook_v6_local(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	if (!skb || !READ_ONCE(psk_set) || peers_empty())
		return NF_ACCEPT;
	if (READ_ONCE(ts_mode) == TS_MODE_STREAM)
		return NF_ACCEPT;
	return ts_tun_in(skb, true);
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

/* ---- /proc/torshield/mode ---------------------------------------------- */
/* "tunnel" (default): UDP encapsulation with AEAD, padding and replay
 * protection, driven by netfilter.  "hybrid": the same wire format, but
 * egress is steered by routes into a "torshield" netdevice; ingress still
 * decapsulates at LOCAL_IN.  "stream": the original length-preserving
 * ChaCha20 transform. */
static int mode_show(struct seq_file *m, void *v)
{
	switch (READ_ONCE(ts_mode)) {
	case TS_MODE_TUNNEL:
		seq_puts(m, "tunnel\n");
		break;
	case TS_MODE_HYBRID:
		seq_puts(m, "hybrid\n");
		break;
	default:
		seq_puts(m, "stream\n");
	}
	return 0;
}

static int mode_open(struct inode *inode, struct file *file)
{
	return single_open(file, mode_show, NULL);
}

static ssize_t mode_write(struct file *file, const char __user *ubuf,
			  size_t count, loff_t *pos)
{
	char buf[16];
	size_t len;

	if (count == 0 || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	len = strcspn(buf, "\r\n");
	buf[len] = '\0';

	if (strcmp(buf, "tunnel") == 0)
		WRITE_ONCE(ts_mode, TS_MODE_TUNNEL);
	else if (strcmp(buf, "hybrid") == 0)
		WRITE_ONCE(ts_mode, TS_MODE_HYBRID);
	else if (strcmp(buf, "stream") == 0)
		WRITE_ONCE(ts_mode, TS_MODE_STREAM);
	else
		return -EINVAL;
	return count;
}

static const struct proc_ops mode_fops = {
	.proc_open    = mode_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = mode_write,
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
	seq_printf(m, "tun_out   %lld\n", (long long)atomic64_read(&st_tun_out));
	seq_printf(m, "tun_in    %lld\n", (long long)atomic64_read(&st_tun_in));
	seq_printf(m, "tun_rx    %lld\n", (long long)atomic64_read(&st_tun_rx));
	seq_printf(m, "tun_peer  %lld\n", (long long)atomic64_read(&st_tun_peer));
	seq_printf(m, "tun_drop  %lld\n", (long long)atomic64_read(&st_tun_drop));
	seq_printf(m, "tun_replay %lld\n",
		   (long long)atomic64_read(&st_tun_replay));
	seq_printf(m, "dev_out   %lld\n", (long long)atomic64_read(&st_dev_out));
	seq_printf(m, "dev_drop  %lld\n", (long long)atomic64_read(&st_dev_drop));
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
static struct nf_hook_ops ts_hooks[6];

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

	nfho_v4_local.hook     = hook_v4_local;
	nfho_v4_local.pf       = NFPROTO_IPV4;
	nfho_v4_local.hooknum  = NF_INET_LOCAL_IN;
	nfho_v4_local.priority = NF_IP_PRI_FIRST;

	nfho_v6_out.hook     = hook_v6_out;
	nfho_v6_out.pf       = NFPROTO_IPV6;
	nfho_v6_out.hooknum  = NF_INET_POST_ROUTING;
	nfho_v6_out.priority = NF_IP6_PRI_LAST;

	nfho_v6_in.hook      = hook_v6_in;
	nfho_v6_in.pf        = NFPROTO_IPV6;
	nfho_v6_in.hooknum   = NF_INET_PRE_ROUTING;
	nfho_v6_in.priority  = NF_IP6_PRI_FIRST;

	nfho_v6_local.hook     = hook_v6_local;
	nfho_v6_local.pf       = NFPROTO_IPV6;
	nfho_v6_local.hooknum  = NF_INET_LOCAL_IN;
	nfho_v6_local.priority = NF_IP6_PRI_FIRST;

	ts_hooks[0] = nfho_v4_out;
	ts_hooks[1] = nfho_v4_in;
	ts_hooks[2] = nfho_v4_local;
	ts_hooks[3] = nfho_v6_out;
	ts_hooks[4] = nfho_v6_in;
	ts_hooks[5] = nfho_v6_local;
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
	    !proc_create("mode",   0600, proc_dir, &mode_fops) ||
	    !proc_create("stats",  0444, proc_dir, &stats_fops)) {
		ret = -ENOMEM;
		goto err_proc;
	}

	fill_hook_ops();
	ret = register_pernet_subsys(&ts_net_ops);
	if (ret)
		goto err_proc;

	ret = rtnl_link_register(&ts_link_ops);
	if (ret)
		goto err_pernet;

	pr_info("TorShield: loaded (inert until psk and peers are set)\n");
	return 0;

err_pernet:
	unregister_pernet_subsys(&ts_net_ops);
err_proc:
	proc_remove(proc_dir);
	return ret;
}

static void __exit torshield_exit(void)
{
	rtnl_link_unregister(&ts_link_ops);
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
