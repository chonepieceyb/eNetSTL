#ifndef BPF_CUSTOM_MAP_SKETCH_LIB_H
#define BPF_CUSTOM_MAP_SKETCH_LIB_H

#include <linux/types.h>
#include <linux/min_heap.h>
#include <linux/hash.h>
#include <linux/container_of.h>

/**********************************************************
 * ************SKETCH PRIMITIVE STRUCT DEFINE*************
 * *******************************************************/

struct sk_top_cache {
	u32 index ____cacheline_aligned;
	u32 count;
};

#define SK_BIT_SHIFT 5
typedef unsigned long __sk_bitmap;
typedef u32 __sk_elem;

struct sk_cache {
	/*first level of cache*/
	/* struct sk_top_cache 	top  ____cacheline_aligned; */

	/*second level of cache, bitmap, the size of second_bitmaps should be power of 2*/
	DECLARE_FLEX_ARRAY(__sk_bitmap, bitmaps) ____cacheline_aligned;
};

struct sk_countarray {
	DECLARE_FLEX_ARRAY(__sk_elem, data);
};

struct sk_aux {
	u32 row ____cacheline_aligned; /*row of count array*/
	u32 col;
	u32 col_mask; /*calculate index base on hash value and mask*/
	u32 bitmap_num;
	u32 bitmap_shift; /*calcualet bitmap index from count array index */
	u32 bitmap_mask;
	u32 row_cache_size;
	u32 row_array_size;
};

struct sketch_primitive_map {
	struct sk_aux aux;

	struct sk_cache __percpu *caches; /* percpu caches */

	struct sk_countarray __percpu *arrays; /* count arrays */
	u32 key_size;
};

/**********************************************************
 * ************SKETCH HEAP STRUCT DEFINE*************
 * *******************************************************/

static inline void sk_hash_init(struct hlist_head *ht, unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		INIT_HLIST_HEAD(&ht[i]);
}

#define sk_hash_min(val, bits) \
	(sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))

/**
 * hash_add - add an object to a hashtable
 * @hashtable: hashtable to add to
 * @node: the &struct hlist_node of the object to be added
 * @key: the key of the object to be added
 * @bits: the number of htab bits
 */

#define sk_hash_add(hashtable, node, key, bits) \
	hlist_add_head(node, &hashtable[sk_hash_min(key, bits)])

/**
 * hash_del - remove an object from a hashtable
 * @node: &struct hlist_node of the object to remove
 */
static inline void sk_hash_del(struct hlist_node *node)
{
	hlist_del_init(node);
}

/**
 * hash_for_each_safe - iterate over a hashtable safe against removal of
 * hash entry
 * @name: hashtable to iterate
 * @bkt: integer to use as bucket loop cursor
 * @tmp: a &struct hlist_node used for temporary storage
 * @obj: the type * to use as a loop cursor for each entry
 * @member: the name of the hlist_node within the struct
 * @size: hashtab size
 */
#define sk_hash_for_each_safe(name, bkt, tmp, obj, member, size)            \
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < (size); (bkt)++) \
		hlist_for_each_entry_safe(obj, tmp, &name[bkt], member)
/**
 * hash_for_each_possible - iterate over all possible objects hashing to the
 * same bucket
 * @name: hashtable to iterate
 * @obj: the type * to use as a loop cursor for each entry
 * @member: the name of the hlist_node within the struct
 * @key: the key of the objects to iterate overo
 * @bits: hashtab bitsize
 */
#define sk_hash_for_each_possible(name, obj, member, key, bits) \
	hlist_for_each_entry(obj, &name[sk_hash_min(key, (bits))], member)

enum SK_HEAP_MAP_RET_CODE {
	SK_HEAP_INSERT = 0,
	SK_HEAP_LESS_MIN,
	SK_HEAP_INCREASE,
	SK_HEAP_EVICT
};

struct __sk_hash_elem {
	struct hlist_node node;
	void *pos ____cacheline_aligned;
	DECLARE_FLEX_ARRAY(char, key);
};

struct __sk_heap_elem {
	struct hlist_node *node; /*ptr to hlist_node in hashtab*/
	u64 counter;
};

struct sketch_heap_hash {
	struct hlist_head __percpu *hashtab;
	struct min_heap __percpu *min_heap;
	u32 heap_size; /*k for topk*/
	u32 htab_bits;
	u32 hashelem_size;
	u32 key_size;
};

#define to_hash_elem(heap_elem) \
	container_of((heap_elem)->node, struct __sk_hash_elem, node);

static inline void sk_hash_free(struct __sk_hash_elem *hash_elem)
{
	if (hash_elem != NULL) {
		kfree(hash_elem);
	}
}

/**********************************************************
 * ************SKETCH RANDOM COUNTER STRUCT DEFINE*********
 * *******************************************************/

struct sketch_random_counter {
	struct rnd_state __percpu *state; /*per map rnd_state*/
	unsigned long __percpu *counter; /* random counter*/
	u32 prod_bits; /*possible bits for GEO probability 1, 0.5, 0.25, 0.125, 0.0625 ...*/
};

#endif
