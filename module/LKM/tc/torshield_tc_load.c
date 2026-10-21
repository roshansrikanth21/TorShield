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
 * The helper loads tc/torshield_tc.o, fills the LPM tries with the supplied
 * peer prefixes, points cfg at the torshield netdevice, and attaches the
 * program to the underlay's clsact egress hook.  Only then does it switch
 * /proc/torshield/mode to "tc".  detach reverses the order, so traffic falls
 * back to the netfilter tunnel path before the classifier disappears.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
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

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s attach|detach -i UNDERLAY -d TORSHIELD_DEV\n"
		"       [-o OBJECT] [-4 CIDR]... [-6 CIDR]...\n"
		"       [-m MODE_FILE]\n",
		prog);
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
	bool attach;

	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "attach"))
		attach = true;
	else if (!strcmp(argv[1], "detach"))
		attach = false;
	else {
		usage(argv[0]);
		return 2;
	}
	optind = 2;
	underlay = tsdev = NULL;
	while ((opt = getopt(argc, argv, "i:d:o:4:6:m:")) != -1) {
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
	if (!underlay) {
		usage(argv[0]);
		return 2;
	}
	underlay_ifindex = if_nametoindex(underlay);
	if (!underlay_ifindex) {
		fprintf(stderr, "torshield-tc: no such interface %s\n", underlay);
		return 1;
	}

	hook.ifindex = underlay_ifindex;
	hook.attach_point = BPF_TC_EGRESS;

	if (!attach) {
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
