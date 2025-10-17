#pragma once

#define MAX_SKIPLIST_HEIGHT 1

struct pkt_5tuple_with_pad {
	__u8 pad[30];
	__u16 key;
} __attribute__((packed));

struct value_with_pad {
	__u8 pad[120];
	__u64 data;
} __attribute__((packed));

typedef struct pkt_5tuple_with_pad skip_key_type_t;
typedef struct value_with_pad skip_value_type_t;

struct sl_entry;

struct sl_entry {
	skip_key_type_t key;
	skip_value_type_t value;
	//int ref_cnt;
	int height;
	struct sl_entry *next[MAX_SKIPLIST_HEIGHT];
	//int hit_cnt;
};