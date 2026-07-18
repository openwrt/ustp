#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "netif_utils.h"

#define TEST_ROOT "/tmp/ustp-test-sysfs"

int log_level;

void Dprintf(int level, const char *fmt, ...);
void Dprintf(int level, const char *fmt, ...)
{
	(void)level;
	(void)fmt;
}

static void remove_tree(void)
{
	assert(system("rm -rf " TEST_ROOT) == 0);
}

static void make_parent(const char *ifname, const char *subdir)
{
	char path[256];

	snprintf(path, sizeof(path), TEST_ROOT "/%s", ifname);
	assert(mkdir(TEST_ROOT, 0700) == 0 || errno == EEXIST);
	assert(mkdir(path, 0700) == 0 || errno == EEXIST);
	snprintf(path, sizeof(path), TEST_ROOT "/%s/%s", ifname, subdir);
	assert(mkdir(path, 0700) == 0 || errno == EEXIST);
}

static void write_value(const char *ifname, const char *subdir,
			const char *file, const char *value)
{
	char path[256];
	int fd;
	ssize_t len = strlen(value);

	make_parent(ifname, subdir);
	snprintf(path, sizeof(path), TEST_ROOT "/%s/%s/%s", ifname, subdir,
		 file);
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	assert(fd >= 0);
	assert(write(fd, value, len) == len);
	assert(close(fd) == 0);
}

static int open_fd_count(void)
{
	DIR *dir = opendir("/proc/self/fd");
	struct dirent *entry;
	int count = 0;

	assert(dir);
	while ((entry = readdir(dir)) != NULL)
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
			count++;
	closedir(dir);
	return count;
}

static void test_priority_values(void)
{
	static const struct {
		const char *text;
		int expected;
	} cases[] = {
		{ "0\n", 0 }, { "4096\n", 4096 }, { "32768\n", 32768 },
		{ "61440\n", 61440 }, { "", -1 }, { "-1\n", -1 },
		{ "4097\n", -1 }, { "65536\n", -1 }, { "garbage\n", -1 },
	};
	unsigned int i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		write_value("br-test", "bridge", "priority", cases[i].text);
		assert(get_bridge_priority("br-test") == cases[i].expected);
	}
	unlink(TEST_ROOT "/br-test/bridge/priority");
	assert(get_bridge_priority("br-test") == -1);
}

static void test_read_error_closes_fd(void)
{
	int before;

	make_parent("port-test", "brport");
	assert(mkdir(TEST_ROOT "/port-test/brport/bpdu_filter", 0700) == 0);
	before = open_fd_count();
	assert(get_bpdu_filter("port-test") == -1);
	assert(open_fd_count() == before);
}

static void test_invalid_bpdu_filter(void)
{
	write_value("bad-filter", "brport", "bpdu_filter", "invalid\n");
	assert(get_bpdu_filter("bad-filter") == -1);
}

int main(void)
{
	remove_tree();
	test_priority_values();
	test_read_error_closes_fd();
	test_invalid_bpdu_filter();
	remove_tree();
	return 0;
}
