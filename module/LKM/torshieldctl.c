/* SPDX-License-Identifier: GPL-2.0 */
/*
 * torshieldctl - userspace control for the TorShield kernel module.
 *
 * Usage:
 *   torshieldctl status
 *   torshieldctl set-key <hex>        (64 hex chars = 256-bit ChaCha20 key)
 *   torshieldctl add-peer <ip> [key <hex>] [allowed <cidr,...>]
 *   torshieldctl del-peer <ip>
 *   torshieldctl rekey-peer <ip> <hex>   (keep old key accepted)
 *   torshieldctl rekey-commit <ip>       (drop the old key)
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
		"  %s add-peer <endpoint> [key <64 hex>] [allowed <cidr[,cidr...]>]\n"
		"  %s del-peer <endpoint>\n"
		"  %s rekey-peer <endpoint> <64 hex>\n"
		"  %s rekey-commit <endpoint>\n"
		"  %s list-peers\n"
		"  %s clear-peers\n",
		p, p, p, p, p, p, p, p);
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

	if (!strcmp(argv[1], "rekey-peer")) {
		char v[160];

		if (argc < 4)
			return 1;
		snprintf(v, sizeof(v), "%s %s", argv[2], argv[3]);
		return write_proc("rekey", v) < 0 ? 1 : 0;
	}
	if (!strcmp(argv[1], "rekey-commit")) {
		char v[96];

		snprintf(v, sizeof(v), "%s commit", argv[2]);
		return write_proc("rekey", v) < 0 ? 1 : 0;
	}

	if (!strcmp(argv[1], "add-peer")) {
		char v[1024];
		size_t n;
		int i;

		n = (size_t)snprintf(v, sizeof(v), "+%s", argv[2]);
		for (i = 3; i < argc; i++) {
			int r = snprintf(v + n, sizeof(v) - n, " %s", argv[i]);

			if (r < 0 || (size_t)r >= sizeof(v) - n)
				return 1;
			n += (size_t)r;
		}
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
