#include <linux/module.h>

struct empty_scmap_callback_ops {
	int (*callback)(u64 param1, u64 param2, u64 param3, u64 param4,
			u64 param5);
	struct module *owner;
};

extern int empty_scmap_callback_register(struct empty_scmap_callback_ops *ops);

extern void
empty_scmap_callback_unregister(struct empty_scmap_callback_ops *ops);
