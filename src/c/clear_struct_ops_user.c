#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <bpf/bpf.h>

#define PATH_MAX_SIZE 256

int main(int argc, char **argv)
{
	int zero = 0, map_fd;
	char path[PATH_MAX_SIZE];

	if (argc < 2) {
		fprintf(stderr, "usage: %s MAP_FILENAME\n", argv[0]);
		exit(1);
	}

	fprintf(stderr, "clearing struct_ops pinned with filename %s\n",
		argv[1]);
	snprintf(path, PATH_MAX_SIZE, "/sys/fs/bpf/%s", argv[1]);
	if ((map_fd = bpf_obj_get(path)) < 0) {
		fprintf(stderr, "error: bpf_obj_get failed: %s (%d)\n",
			strerror(errno), errno);
		goto err;
	}
	if ((remove(path))) {
		fprintf(stderr, "error: remove failed: %s (%d)\n",
			strerror(errno), errno);
		goto err;
	}
	if ((bpf_map_delete_elem(map_fd, &zero))) {
		fprintf(stderr, "error: bpf_map_delete_elem failed: %s (%d)\n",
			strerror(errno), errno);
		goto err;
	}

	return 0;
err:
	return errno;
}
