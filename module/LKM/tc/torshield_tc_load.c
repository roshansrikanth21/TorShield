// SPDX-License-Identifier: GPL-2.0
/*
 * torshield-tc: load and attach the TorShield TC egress classifier.
 *
 * Run inside the network namespace that owns the underlay interface:
 *
 *   torshield-tc attach -i veth1 -d ts0 \
 *       -4 10.0.0.1/32 -4 10.0.0.2/32 \
 *       -6 fd00::1/128 -6 fd00::2/128
 *
 * The helper loads tc/torshield_tc.o, reads every allowed prefix from
 * /proc/torshield/peers (plus any extra -4/-6 arguments), fills the LPM tries,
 * points cfg at the torshield netdevice, and attaches the program to the
 * underlay's clsact egress hook.  Only then does it switch
 * /proc/torshield/mode to "tc".  detach reverses the order, so traffic falls
 * back to the netfilter tunnel path before the classifier disappears.  A peer
 * add/del/clear while mode is "tc" forces mode back to "tunnel"; rerun attach
 * to rebuild the maps.
 *
 * The kernel module's LOCAL_OUT/FORWARD guard is the fail-closed boundary; the
 * attach/detach ordering and the optional "watch" subcommand only reduce the
 * time spent in the TC path after an unexpected classifier removal.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

#define MAX_PREFIXES 64

struct lpm4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct lpm6_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct prefix4 {
	struct lpm4_key key;
};

struct prefix6 {
	struct lpm6_key key;
};

static struct prefix4 p4[MAX_PREFIXES];
static struct prefix6 p6[MAX_PREFIXES];
static int n4, n6;

static int set_mode(const char *path, const char *mode);

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s attach|detach -i UNDERLAY -d TORSHIELD_DEV\n"
		"       [-o OBJECT] [-4 CIDR]... [-6 CIDR]...\n"
		"       [-m MODE_FILE]\n"
		"       (allowed prefixes are read from /proc/torshield/peers;\n"
		"        -4/-6 add extra prefixes)\n"
		"       %s watch -i UNDERLAY [-m MODE_FILE] [-n INTERVAL_MS] [-x]\n",
		prog, prog);
}

static bool valid_ifname(const char *s)
{
	size_t i, n = strlen(s);

	if (!n || n >= IFNAMSIZ)
		return false;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		if (!isalnum(c) && c != '.' && c != '_' && c != '-')
			return false;
	}
	return true;
}

static int read_mode(const char *path, char *buf, size_t len)
{
	FILE *f = fopen(path, "r");

	if (!f)
		return -1;
	if (!fgets(buf, (int)len, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	buf[strcspn(buf, "\r\n")] = '\0';
	return 0;
}

static bool tc_filter_present(const char *ifname)
{
	char cmd[256], line[512];
	bool found = false;
	FILE *p;

	if (snprintf(cmd, sizeof(cmd), "tc filter show dev %s egress 2>/dev/null",
		     ifname) >= (int)sizeof(cmd))
		return false;
	p = popen(cmd, "r");
	if (!p)
		return false;
	while (fgets(line, sizeof(line), p)) {
		if (strstr(line, "ts_tc_egress")) {
			found = true;
			break;
		}
	}
	pclose(p);
	return found;
}

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

/*
 * The kernel's LOCAL_OUT/FORWARD guard (see torshield.c) is the fail-closed
 * security boundary: it drops peer packets when the egress classifier is
 * missing.  This watchdog is a recovery aid: while the mode is "tc" it checks
 * that the classifier is still on the underlay and reverts to "tunnel"
 * (netfilter encapsulation) if it is not.  Run it under a supervisor so the
 * system returns to the transparent path promptly after an accidental
 * qdisc/filter removal; do not treat it as the thing that prevents a leak.
 */
static int run_watch(const char *ifname, const char *mode_path,
		     int interval_ms, bool exit_after)
{
	char mode[32];
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	fprintf(stderr, "torshield-tc: watching %s egress every %d ms\n",
		ifname, interval_ms);
	while (!stop) {
		if (!read_mode(mode_path, mode, sizeof(mode)) &&
		    !strcmp(mode, "tc") && !tc_filter_present(ifname)) {
			fprintf(stderr,
				"torshield-tc: classifier missing on %s while mode=tc; reverting to tunnel\n",
				ifname);
			if (set_mode(mode_path, "tunnel"))
				return 1;
			if (exit_after)
				return 0;
		}
		usleep((useconds_t)interval_ms * 1000);
	}
	return 0;
}

static int parse_prefix(const char *s, int family)
{
	char buf[INET6_ADDRSTRLEN + 8];
	char *slash;
	int len;

	if (strlen(s) >= sizeof(buf))
		return -1;
	strcpy(buf, s);
	slash = strchr(buf, '/');
	if (!slash)
		return -1;
	*slash++ = '\0';
	len = atoi(slash);
	if (len < 0)
		return -1;

	if (family == AF_INET) {
		if (n4 >= MAX_PREFIXES || len > 32)
			return -1;
		p4[n4].key.prefixlen = (__u32)len;
		if (inet_pton(AF_INET, buf, &p4[n4].key.addr) != 1)
			return -1;
		n4++;
	} else {
		if (n6 >= MAX_PREFIXES || len > 128)
			return -1;
		p6[n6].key.prefixlen = (__u32)len;
		if (inet_pton(AF_INET6, buf, p6[n6].key.addr) != 1)
			return -1;
		n6++;
	}
	return 0;
}

/*
 * The kernel peer table is the source of truth for cryptokey routing.  Read
 * every "allowed=" prefix from /proc/torshield/peers and add it to the maps.
 * This means an operator cannot forget a prefix on the command line and leave
 * a live classifier that silently fails to redirect it; -4/-6 remain additive
 * for exceptional cases.  If the peer list changes later, the kernel forces
 * mode back to "tunnel" until this loader is run again.
 */
static int add_kernel_peer_prefixes(void)
{
	FILE *f;
	char line[4096];

	f = fopen("/proc/torshield/peers", "r");
	if (!f) {
		fprintf(stderr, "torshield-tc: cannot read /proc/torshield/peers: %s\n",
			strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char *allowed = strstr(line, "allowed=");
		char *nl;
		char *tok;

		if (!allowed)
			continue;
		allowed += strlen("allowed=");
		nl = strpbrk(allowed, "\r\n");
		if (nl)
			*nl = '\0';
		for (tok = strtok(allowed, ","); tok; tok = strtok(NULL, ",")) {
			int family = strchr(tok, ':') ? AF_INET6 : AF_INET;

			if (parse_prefix(tok, family)) {
				fprintf(stderr, "torshield-tc: bad peer prefix: %s\n",
					tok);
				fclose(f);
				return -1;
			}
		}
	}
	fclose(f);
	return 0;
}

static int set_mode(const char *path, const char *mode)
{
	FILE *f = fopen(path, "w");

	if (!f) {
		fprintf(stderr, "torshield-tc: cannot open %s: %s\n", path,
			strerror(errno));
		return -1;
	}
	fprintf(f, "%s\n", mode);
	fclose(f);
	return 0;
}

static int fill_map(int map_fd, const void *key)
{
	__u32 one = 1;

	return bpf_map_update_elem(map_fd, key, &one, BPF_ANY);
}

int main(int argc, char **argv)
{
	const char *obj_path = "torshield_tc.o";
	const char *mode_path = "/proc/torshield/mode";
	const char *underlay, *tsdev;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	LIBBPF_OPTS(bpf_tc_hook, hook);
	LIBBPF_OPTS(bpf_tc_opts, opts);
	int cfg_fd, m4_fd, m6_fd;
	int underlay_ifindex, ts_ifindex;
	__u32 zero = 0;
	int err, opt, i;
	int interval_ms = 1000;
	bool exit_after = false;
	enum { OP_ATTACH, OP_DETACH, OP_WATCH } op;

	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "attach"))
		op = OP_ATTACH;
	else if (!strcmp(argv[1], "detach"))
		op = OP_DETACH;
	else if (!strcmp(argv[1], "watch"))
		op = OP_WATCH;
	else {
		usage(argv[0]);
		return 2;
	}
	optind = 2;
	underlay = tsdev = NULL;
	while ((opt = getopt(argc, argv, "i:d:o:4:6:m:n:x")) != -1) {
		switch (opt) {
		case 'i':
			underlay = optarg;
			break;
		case 'd':
			tsdev = optarg;
			break;
		case 'o':
			obj_path = optarg;
			break;
		case 'm':
			mode_path = optarg;
			break;
		case 'n':
			interval_ms = atoi(optarg);
			if (interval_ms < 50)
				interval_ms = 50;
			break;
		case 'x':
			exit_after = true;
			break;
		case '4':
			if (parse_prefix(optarg, AF_INET)) {
				fprintf(stderr, "bad IPv4 prefix: %s\n", optarg);
				return 2;
			}
			break;
		case '6':
			if (parse_prefix(optarg, AF_INET6)) {
				fprintf(stderr, "bad IPv6 prefix: %s\n", optarg);
				return 2;
			}
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}
	if (!underlay || !valid_ifname(underlay)) {
		usage(argv[0]);
		return 2;
	}
	underlay_ifindex = if_nametoindex(underlay);
	if (!underlay_ifindex) {
		fprintf(stderr, "torshield-tc: no such interface %s\n", underlay);
		return 1;
	}

	if (op == OP_WATCH)
		return run_watch(underlay, mode_path, interval_ms, exit_after);

	hook.ifindex = underlay_ifindex;
	hook.attach_point = BPF_TC_EGRESS;

	if (op == OP_DETACH) {
		/* Fall back to the netfilter path before removing the classifier. */
		if (set_mode(mode_path, "tunnel"))
			return 1;
		err = bpf_tc_hook_destroy(&hook);
		if (err && err != -ENOENT) {
			fprintf(stderr, "torshield-tc: detach: %s\n",
				strerror(-err));
			return 1;
		}
		printf("detached from %s\n", underlay);
		return 0;
	}

	if (!tsdev) {
		usage(argv[0]);
		return 2;
	}
	ts_ifindex = if_nametoindex(tsdev);
	if (!ts_ifindex) {
		fprintf(stderr, "torshield-tc: no such interface %s\n", tsdev);
		return 1;
	}

	if (add_kernel_peer_prefixes())
		return 1;

	obj = bpf_object__open_file(obj_path, NULL);
	if (!obj) {
		fprintf(stderr, "torshield-tc: cannot open %s\n", obj_path);
		return 1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "torshield-tc: load failed: %s\n", strerror(-err));
		goto out;
	}
	prog = bpf_object__find_program_by_name(obj, "ts_tc_egress");
	if (!prog) {
		fprintf(stderr, "torshield-tc: ts_tc_egress not found\n");
		err = -ENOENT;
		goto out;
	}

	cfg_fd = bpf_object__find_map_fd_by_name(obj, "cfg");
	m4_fd = bpf_object__find_map_fd_by_name(obj, "allowed4");
	m6_fd = bpf_object__find_map_fd_by_name(obj, "allowed6");
	if (cfg_fd < 0 || m4_fd < 0 || m6_fd < 0) {
		fprintf(stderr, "torshield-tc: maps missing\n");
		err = -ENOENT;
		goto out;
	}
	err = bpf_map_update_elem(cfg_fd, &zero, &ts_ifindex, BPF_ANY);
	if (err) {
		fprintf(stderr, "torshield-tc: cfg update: %s\n", strerror(-err));
		goto out;
	}
	for (i = 0; i < n4; i++) {
		err = fill_map(m4_fd, &p4[i].key);
		if (err) {
			fprintf(stderr, "torshield-tc: allowed4 update: %s\n",
				strerror(-err));
			goto out;
		}
	}
	for (i = 0; i < n6; i++) {
		err = fill_map(m6_fd, &p6[i].key);
		if (err) {
			fprintf(stderr, "torshield-tc: allowed6 update: %s\n",
				strerror(-err));
			goto out;
		}
	}

	err = bpf_tc_hook_create(&hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "torshield-tc: clsact create: %s\n",
			strerror(-err));
		goto out;
	}
	opts.prog_fd = bpf_program__fd(prog);
	opts.flags = BPF_TC_F_REPLACE;
	err = bpf_tc_attach(&hook, &opts);
	if (err) {
		fprintf(stderr, "torshield-tc: attach: %s\n", strerror(-err));
		goto out;
	}

	/* The classifier is live; now make TC mode authoritative. */
	if (set_mode(mode_path, "tc")) {
		bpf_tc_detach(&hook, &opts);
		err = -EIO;
		goto out;
	}
	printf("attached to %s (egress) -> %s; %d IPv4, %d IPv6 prefixes; mode=tc\n",
	       underlay, tsdev, n4, n6);
	err = 0;
out:
	bpf_object__close(obj);
	return err ? 1 : 0;
}
