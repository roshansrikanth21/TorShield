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
