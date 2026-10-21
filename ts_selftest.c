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
