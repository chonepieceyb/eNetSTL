#ifndef MOD_STRUCT_OPS_DEMO_H
#define MOD_STRUCT_OPS_DEMO_H

#include <linux/module.h>

struct mod_struct_ops_ctx {
	int val;
};

struct mod_struct_ops_demo {
	int (*hello_world)(struct mod_struct_ops_ctx *ctx); 
	struct module *owner;
};
#endif
