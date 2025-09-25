#ifndef EBPF_DEMO_USER_DEMO_H
#define EBPF_DEMO_USER_DEMO_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/types.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

static int __default_callback_load(void *skel)
{
	return 0;
}

static int __default_callback_after_attach(void *skel)
{
	return 0;
}

#define BPF_XDP_SKEL_LOADER_WITH_CALLBACK(__skel, _ifname, _prog,            \
					  _callback_load, _callback_after_attach, mode) \
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
	if ((res = _callback_after_attach(skel))) {                           \
		printf("failed to invoke after attach callback, res %d\n", res); \
		goto clean;                                                  \
	}                                                                    \
clean:;                                                                      \
	__skel##__destroy(skel);                                             \
	return res;

#define BPF_XDP_SKEL_LOADER(__skel, _ifname, _prog, mode)         \
	BPF_XDP_SKEL_LOADER_WITH_CALLBACK(__skel, _ifname, _prog, \
					  __default_callback_load, __default_callback_after_attach, mode)

#endif
