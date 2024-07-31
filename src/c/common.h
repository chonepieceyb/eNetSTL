#ifndef EBPF_DEMO_USER_DEMO_H
#define EBPF_DEMO_USER_DEMO_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

static int __default_callback_load(void *skel)
{
	return 0;
}

#define BPF_XDP_SKEL_LOADER_WITH_CALLBACK(__skel, _ifname, _prog,            \
					  _callback_load, mode)              \
	struct __skel *skel = NULL;                                          \
	struct bpf_program *prog;                                            \
	int fd, ifindex, res;                                                \
	res = 0;                                                             \
	ifindex = if_nametoindex((_ifname));                                 \
	if (ifindex == 0) {                                                  \
		printf("failed to get ifindex %s\n", strerror(errno));       \
		return -1;                                                   \
	}                                                                    \
	skel = __skel##__open();                                             \
	if (skel == NULL) {                                                  \
		printf("faild to open and load %s\n", #__skel);              \
		return -1;                                                   \
	}                                                                    \
	prog = skel->progs._prog;                                            \
	res = __skel##__load(skel);                                          \
	if (res) {                                                           \
		printf("faild to load, res %d %s\n", res, strerror(errno));  \
		goto clean;                                                  \
	}                                                                    \
	if ((res = _callback_load(skel))) {                                  \
		printf("failed to invoke callback, res %d\n", res);          \
		goto clean;                                                  \
	}                                                                    \
	fd = bpf_program__fd(prog);                                          \
	res = bpf_xdp_attach(ifindex, fd, (mode), NULL);                     \
	if (res < 0) {                                                       \
		printf("failed to attach prog %d to nic %d, res: %d , %s\n", \
		       fd, ifindex, res, strerror(errno));                   \
		goto clean;                                                  \
	}                                                                    \
clean:;                                                                      \
	__skel##__destroy(skel);                                             \
	return res;

#define BPF_XDP_SKEL_LOADER(__skel, _ifname, _prog, mode)         \
	BPF_XDP_SKEL_LOADER_WITH_CALLBACK(__skel, _ifname, _prog, \
					  __default_callback_load, mode)

#define BPF_MOD_LOAD_STRUCT_OPS(__skel, _map, module_name)                  \
	struct __skel *skel = NULL;                                         \
	int res;                                                            \
	skel = __skel##__open();                                            \
	if (skel == NULL) {                                                 \
		printf("faild to open and load %s\n", #__skel);             \
		return NULL;                                                \
	}                                                                   \
	res = bpf_map__set_struct_ops_module(skel->maps._map, module_name); \
	if (res != 0) {                                                     \
		printf("failed to set struct_ops_module, res %d\n", res);   \
		goto clean_stops;                                           \
	}                                                                   \
	res = __skel##__load(skel);                                         \
	if (res) {                                                          \
		printf("faild to load, res %d %s\n", res, strerror(errno)); \
		goto clean_stops;                                           \
	}                                                                   \
	res = bpf_map__pin(skel->maps._map, "/sys/fs/bpf/" module_name);    \
	if (res) {                                                          \
		printf("failed to pin map: %d %s\n", res, strerror(errno)); \
		goto clean_stops;                                           \
	}                                                                   \
	void *bpf_link = bpf_map__attach_struct_ops(skel->maps._map);       \
	if (bpf_link == NULL) {                                             \
		printf("failed to attach struct ops error: %d", errno);     \
		goto clean_stops;                                           \
	}                                                                   \
	return skel;                                                        \
clean_stops:;                                                               \
	__skel##__destroy(skel);                                            \
	return NULL;

#define BPF_MOD_CLEAR_STRUCT_OPS(__skel, module_name)                            \
	int __skel##_map_fd = bpf_obj_get("/sys/fs/bpf/" module_name),           \
	    __skel##_zero = 0;                                                   \
	if (__skel##_map_fd < 0) {                                               \
		printf("failed to get struct ops map fd: %d %s; ignoring\n",     \
		       -(__skel##_map_fd), strerror(errno));                     \
		goto __skel##_clear_struct_ops_done;                             \
	}                                                                        \
	if (remove("/sys/fs/bpf/" module_name)) {                                \
		printf("failed to remove pinned map: %d %s; ignoring\n",         \
		       errno, strerror(errno));                                  \
		goto __skel##_clear_struct_ops_done;                             \
	}                                                                        \
	if (bpf_map_delete_elem(__skel##_map_fd, &(__skel##_zero)) != 0) {       \
		printf("failed to delete struct ops element: %d %s; ignoring\n", \
		       errno, strerror(errno));                                  \
		goto __skel##_clear_struct_ops_done;                             \
	}                                                                        \
	__skel##_clear_struct_ops_done:;

#endif
