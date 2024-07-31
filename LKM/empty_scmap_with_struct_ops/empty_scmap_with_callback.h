#include <linux/module.h>

struct empty_scmap_callback_ops {
#if USE_CALLBACK_PARAM_COUNT == 0
	int (*callback)(void);
#elif USE_CALLBACK_PARAM_COUNT == 1
	int (*callback)(u64 param1);
#elif USE_CALLBACK_PARAM_COUNT == 5
	int (*callback)(u64 param1, u64 param2, u64 param3, u64 param4,
			u64 param5);
#else
#error "Unsupported USE_CALLBACK_PARAM_COUNT"
#endif
	struct module *owner;
};

#if USE_CALLBACK_WORKAROUND == 1
extern int empty_scmap_callback_register(struct empty_scmap_callback_ops *ops,
					 u32 prog_fd);
#else
extern int empty_scmap_callback_register(struct empty_scmap_callback_ops *ops);
#endif

extern void
empty_scmap_callback_unregister(struct empty_scmap_callback_ops *ops);
