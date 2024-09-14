#pragma once 

#include "common.h"

struct bkt_list {
    int fd;
	void __percpu *map_mem;  //use for rust
};

int init_bktlist_module(void);
void free_bktlist_module(void);
struct bkt_list* bktlist_new(void);
void bktlist_free(struct bkt_list *bktlist);
int bktlist_pop_front(int fd, void *buf, size_t size, size_t slot);
int bktlist_push_back(int fd, const void *buf, size_t size, size_t slot);