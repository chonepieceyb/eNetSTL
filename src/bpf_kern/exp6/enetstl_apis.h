#pragma once 

#include "../common.h"

struct bpf_bkt_list {
	int fd;
};

extern struct bpf_bkt_list* bpf_bktlist_new(void) __ksym;

extern void bpf_bktlist_free(struct bpf_bkt_list* bktlist) __ksym;

extern int bpf_bktlist_pop_front(int fd, void *val, size_t size__kz, size_t slot) __ksym;

extern int bpf_bktlist_push_back(int fd, const void *val, size_t size__kz, size_t slot) __ksym;