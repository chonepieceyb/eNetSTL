#include <linux/module.h>

struct hash_callback_ops {
	int (*callback)(void *ctx, int i, u32 hash);
	struct module *owner;
};

extern int hash_callback_register(struct hash_callback_ops *ops, u32 prog_fd);

extern void hash_callback_unregister(struct hash_callback_ops *ops);
