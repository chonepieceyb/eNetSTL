#include <linux/module.h>
#include "bpf_ptr_base_ext_ops.h"

extern void unreg_node_base_ext_ops(struct node_base_ext_ops *ops);
extern int reg_node_base_ext_ops(struct node_base_ext_ops *new_ext_ops);



#define BKT_NEXT 0
#define BKT_PREV 1
#define BKT_ELEM_NEXT 2
#define BKT_ELEM_PREV 3
#define ELEM_NEXT 0
#define ELEM_PREV 1
#define ELEM_BUCKET 2

// update 函数转换
#define BUCKETS_HEAD 0
#define ELEMENT_IDX 1 //new element or hash found element 
#define BUCKET_IDX 2
#define NEW_BUCKET_IDX 3
#define NEIGHBOR_BUCKET_IDX 4

void ss_user_configure(struct node_base_user_config *config)
{
        config->child_num = 4;
}

struct ss_map_data {
        bool is_init;
        int idx;
};

#define CMD_ROUTE_BUCKET 0
#define CMD_ROUTE_ELEM 1
#define CMD_GET_BUCKET_LIST_HEAD 2 
struct ss_tmp_context {
        int cmd;
        union {
                struct {
                        bool write_key;
                } elem_ctx;
                struct {
                        u64 val; 
                } bucket_ctx;
        };
};

static void ss_manipulate(struct node_base_ctx *ctx, struct node_common *node)
{
        pr_info("call ssmanipulate");
        struct ss_tmp_context *context = (struct ss_tmp_context *)&ctx->mctx;
        if (ctx->event == EVENT_GET_ROOT_ALLOC) {
                node_init_double_list_fast(ctx, node);
                return; 
        } else if (ctx->event == EVENT_GET_CHILD) {
                if (context->cmd == CMD_ROUTE_BUCKET) {
                        u64 val = 0;
                        node_get_val_u64(ctx, node, &val);
                        context->bucket_ctx.val = val;
                } else {
                        if (context->elem_ctx.write_key) {
                                node_write_key(ctx, node);
                        }
                 }
        } else if (ctx->event == EVENT_ALLOC) {
                if (context->cmd == CMD_ROUTE_ELEM) {
                        node_write_key(ctx, node);
                } else {
                        // alloc a new bucket 
                        node_set_val_u64(ctx, node, context->bucket_ctx.val);
                        //init list
                        node_init_double_list(ctx, node, BKT_ELEM_NEXT, BKT_ELEM_PREV);
                }
        }
}

void ss_manipulate_1_1(struct node_base_ctx *ctx, struct node_common *node1)
{
        pr_info("call ssmanipulate 1_1");
        //add element to bucket, node1 bucket, node2 element 
        *((u64*)&node1->user_data) = 101;
}


void ss_manipulate_2_1(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
        pr_info("call ssmanipulate 2_1");
        //add element to bucket, node1 bucket, node2 element 
        node_list_double_add(ctx, node1, node2, BKT_ELEM_NEXT, ELEM_NEXT);
}

void ss_manipulate_3_1(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2, struct node_common *node3)
{
        pr_info("call ssmanipulate 3_1");
        //node1 head , node2 bucket1 node3 bucket2
        node_list_add_double_entry_fast(ctx, node1, node2);
        node_list_add_double_entry_fast(ctx, node2, node3);
}

void ss_manipulate_2_2(struct node_base_ctx *ctx, struct node_common *node1, struct node_common *node2)
{
        pr_info("call ssmanipulate 2_2");
        //node1: bucket, node2: element, delete element and add to bucket
        node_list_del_double_entry_fast(ctx, node2); 
        node_list_double_add(ctx, node1, node2, BKT_ELEM_NEXT, ELEM_NEXT);
        //element->parent = new_bucket;
        node_setchild(ctx, node1, ELEM_BUCKET, node2);
        node_set_val_u64(ctx, node1, 1);
}

#define BUCKETS_HEAD 0 
#define BUCKET_0 1
#define BUCKET_1 2
#define ELEMENT 3
#define HASH_IDX 4

int ss_update(struct node_base_ctx *ctx, struct node_base_meta *meta)
{
        //test:
        //1. cal hash 
        //2. get node 
        //3. get neighbor bucket
        //4. move to neighbor
        //4. calculate value 
        struct ss_map_data *ss_map = (struct ss_map_data*)meta;
        int ret = 0;
        if (unlikely(!ss_map->is_init)) {
                //init : create two bucktes and one element 
                struct ss_tmp_context *context = (struct ss_tmp_context *)&ctx->mctx;
                context->bucket_ctx.val = 0;
                context->cmd = CMD_ROUTE_BUCKET;
                node_base_get_root(ctx, BUCKETS_HEAD);
               alloc_new_node(ctx, BUCKET_0);
                context->bucket_ctx.val = 1;
                alloc_new_node(ctx, BUCKET_1);
                manipulate_nodes_3_1(ctx, BUCKETS_HEAD, BUCKET_0, BUCKET_1);
                context->cmd = CMD_ROUTE_ELEM;
                alloc_new_node(ctx, ELEMENT);
                manipulate_nodes_2_1(ctx, BUCKET_0, ELEMENT);
                alloc_new_node(ctx, ELEMENT);
                manipulate_nodes_2_1(ctx, BUCKET_1, ELEMENT);
                alloc_new_node(ctx, ELEMENT);
                manipulate_nodes_2_1(ctx, BUCKET_0, ELEMENT);
                manipulate_node_1_1(ctx, ELEMENT);
                ss_map->is_init = 1; 
                ss_map->idx = 0; //last
                // pr_info("start init test");
                //  //check that current has 101
                // if (*(ctx->pproot) == NULL) {
                //         pr_err("pproot is NYLL");
                //         goto error;
                // } 
                // struct node_common *head = *(ctx->pproot);
                // struct node_common *node0 = head->childs[BKT_NEXT];
                // if (node0 == NULL) {
                //         pr_err("node0 is NYLL");
                //         goto error;
                // }
                // struct node_common *node1 = node0->childs[BKT_NEXT];
                // if (node1 == NULL) {
                //         pr_err("node1 is NULL");
                //         goto error;
                // }
                // struct node_common *ele = node0->childs[BKT_ELEM_NEXT];
                // if (ele == NULL) {
                // pr_err("ele is NULL");
                //         goto error;  
                // }
                // if (*((u64*)&ele->user_data)) 
                //         pr_err("ele is not 101");

                // pr_info("init success");

                 return 0;
        }
        //test 

        ret =  node_base_get_root(ctx, BUCKETS_HEAD);
        if (ret < 0) {
                //should not happen
                pr_err("failed to get  or init root, ret %d", ret);
                goto error;
        }
        u32 hash = xxhash32_key(ctx);
        get_node_by_hash(ctx, hash, HASH_IDX);
        node_getchild(ctx, BUCKETS_HEAD, BKT_NEXT, BUCKET_0);
        node_getchild(ctx, BUCKET_0, BKT_NEXT, BUCKET_1);
        if (ss_map->idx == 0) {
                //element in idx 0 now 
                node_getchild(ctx, BUCKET_0, BKT_ELEM_NEXT, ELEMENT);
                manipulate_nodes_2_2(ctx, BUCKET_1, ELEMENT);
                ss_map->idx = 1;
        } else {
                node_getchild(ctx, BUCKET_1, BKT_ELEM_NEXT, ELEMENT);
                manipulate_nodes_2_2(ctx, BUCKET_0, ELEMENT);
                ss_map->idx = 0;
        }

        // //check that current has 101
        // if (*(ctx->pproot) == NULL) {
        //         pr_err("pproot is NYLL");
        //         goto error;
        // } 
        // struct node_common *head = *(ctx->pproot);
        // struct node_common *node0 = head->childs[BKT_NEXT];
        // if (node0 == NULL) {
        //         pr_err("node0 is NYLL");
        //         goto error;
        // }
        // struct node_common *node1 = node0->childs[BKT_NEXT];
        // if (node1 == NULL) {
        //         pr_err("node1 is NULL");
        //         goto error;
        // }
        // if (ss_map->idx == 0) {
        //         struct node_common *ele = node0->childs[BKT_ELEM_NEXT];
        //         if (ele == NULL) {
        //                pr_err("ele is NULL");
        //                 goto error;  
        //         }
        //         if (*((u64*)&ele->user_data)) 
        //                 pr_err("ele is not 101");
        // } else {
        //         struct node_common *ele = node1->childs[BKT_ELEM_NEXT];
        //         if (ele == NULL) {
        //                pr_err("ele is NULL");
        //                 goto error;  
        //         }
        //         if (*((u64*)&ele->user_data)) 
        //                 pr_err("ele is not 101");
        // }
        // pr_info("element current in bucket %d", ss_map->idx);
        //testing 
        return 0;
error:
        return -1;
}

struct node_base_ext_ops ext_ops = {
        .update = (void*)ss_update,
        .manipulate = (void*)ss_manipulate,
        .user_configure = (void*)ss_user_configure,
        .manipulate_2_1 = (void*)ss_manipulate_2_1,
        .manipulate_2_2 = (void*)ss_manipulate_2_2,
        .manipulate_3_1 = (void*)ss_manipulate_3_1,
};

static int __init ss_ext_test_init(void) {
	return reg_node_base_ext_ops(&ext_ops);
}

static void __exit ss_ext_test_exit(void) {
	unreg_node_base_ext_ops(&ext_ops);
}

/* Register module functions */
module_init(ss_ext_test_init);
module_exit(ss_ext_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chonepieceyb");
MODULE_DESCRIPTION("BPF networking datapath pointer-based data structrue sets");
MODULE_VERSION("0.01");