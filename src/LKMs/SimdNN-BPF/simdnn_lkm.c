/* SimdNN纯内核模块实现
   1.功能和eBPF+kfunc一致。
   2.使用纯内核模块实现，作为simdnn模块的一部分。
   3.eBPF+kfunc的实现文件:
   用户态eBPF:src/c/SimdNN-BPF/simdnn_loader.c
   内核态eBPF:src/bpf_kern/SimdNN-BPF/simdnn.bpf.c
   kfunc:src/LKMs/SimdNN-BPF/simdnn_kfunc.c
   纯内核模块实现:src/LKMs/SimdNN-BPF/simdnn_lkm.c
*/

/* SimdNN 纯内核模块实现：功能等价 eBPF+kfunc
 * - Netfilter PRE_ROUTING 抓包
 * - per-flow 特征统计与归一化
 * - 调用 simdnn_analyze_and_infer() 做推理
 */
// simdnn_lkm.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/uaccess.h>
#include <linux/errno.h>

#include "common.h"      /* struct model / struct flow / flow_attribute */
#include "mlp_params.bpf.h"     /* N0..N3、mean/scale、FIX_POINT、权重 */

#define FLOW_HT_BITS   12     /* 4K 桶 */
#define INFER_MIN_PKTS 1      /* 触发推理阈值（示例） */

struct flow_node {
	struct hlist_node hnode;
	struct flow key;
	struct flow_attribute fa;
};

static DEFINE_HASHTABLE(flow_ht, FLOW_HT_BITS);
static spinlock_t bucket_locks[1 << FLOW_HT_BITS];
static struct nf_hook_ops nfops;

/* 模型常驻（推理结果写回 output_buffer） */
static struct model g_model;

int simdnn_analyze_and_infer(void *m, int model_size, int *attr, int attr_size);

/* ------------ 工具：hash/比较 ------------ */
static inline u32 flow_hash(const struct flow *k)
{
	return jhash2((u32 *)k, sizeof(*k) / sizeof(u32), 0);
}
static inline bool flow_equal(const struct flow *a, const struct flow *b)
{
	return a->saddr == b->saddr && a->daddr == b->daddr &&
	       a->sport == b->sport && a->dport == b->dport;
}

/* ------------ normalize ------------ */
static inline int sat_div_shift(int64_t num, int64_t den)
{
	int64_t q;
	if (den == 0)
		return 0;
	q = (num << FIX_POINT) / den;
	if (q > INT_MAX)  return INT_MAX;
	if (q < INT_MIN)  return INT_MIN;
	return (int)q;
}
static void normalize_attr_to_int6(const struct flow_attribute *fa, int out6[N0])
{
	out6[0] = sat_div_shift(fa->num_packet        - mean[0], scale[0]);
	out6[1] = sat_div_shift(fa->max_duration      - mean[1], scale[1]);
	out6[2] = sat_div_shift(fa->max_packet_length - mean[2], scale[2]);
	out6[3] = sat_div_shift(fa->min_packet_length - mean[3], scale[3]);
	out6[4] = sat_div_shift(fa->dst_port          - mean[4], scale[4]);
	out6[5] = sat_div_shift(fa->header_length     - mean[5], scale[5]);
}

/* ------------ 装配模型（把三层 FC 权重写入 g_model） ------------ */
static void build_model(struct model *m)
{
	memset(m, 0, sizeof(*m));

	/* fc1: N0 -> N1 */
	m->fc1.comm.type           = ENETSTL_FC_LAYER;
	m->fc1.comm.next_layer_off = (int)offsetof(struct model, relu1);
	m->fc1.parm.in_features    = N0;
	m->fc1.parm.out_features   = N1;
	for (int o = 0; o < N1; ++o)
		for (int i = 0; i < N0; ++i)
			m->fc1.weights[o][i] = layer_0_weight[o * N0 + i];

	/* relu1 */
	m->relu1.comm.type           = ENETSTL_RELU_LAYER;
	m->relu1.comm.next_layer_off = (int)offsetof(struct model, fc2);

	/* fc2: N1 -> N2 */
	m->fc2.comm.type           = ENETSTL_FC_LAYER;
	m->fc2.comm.next_layer_off = (int)offsetof(struct model, relu2);
	m->fc2.parm.in_features    = N1;
	m->fc2.parm.out_features   = N2;
	for (int o = 0; o < N2; ++o)
		for (int i = 0; i < N1; ++i)
			m->fc2.weights[o][i] = layer_1_weight[o * N1 + i];

	/* relu2 */
	m->relu2.comm.type           = ENETSTL_RELU_LAYER;
	m->relu2.comm.next_layer_off = (int)offsetof(struct model, fc_out);

	/* fc_out: N2 -> N3 */
	m->fc_out.comm.type           = ENETSTL_FC_LAYER;
	m->fc_out.comm.next_layer_off = (int)offsetof(struct model, output_buffer);
	m->fc_out.parm.in_features    = N2;
	m->fc_out.parm.out_features   = N3;
	for (int o = 0; o < N3; ++o)
		for (int i = 0; i < N2; ++i)
			m->fc_out.weights[o][i] = layer_2_weight[o * N2 + i];

	m->output_buffer.comm.type           = ENETSTL_RELU_LAYER; /* 终止层 */
	m->output_buffer.comm.next_layer_off = 0;
}

/* ------------ 解析报文 + 更新一次流特征（简化实现） ------------ */
static bool parse_and_update(struct sk_buff *skb,
			     struct flow *k, struct flow_attribute *fa)
{
	struct ethhdr *eth;
	struct iphdr  *iph;

	if (!skb) return false;
	if (!pskb_may_pull(skb, sizeof(*eth))) return false;

	eth = eth_hdr(skb);
	if (ntohs(eth->h_proto) != ETH_P_IP)
		return false;

	if (!pskb_may_pull(skb, sizeof(*eth) + sizeof(*iph)))
		return false;

	iph = ip_hdr(skb);
	if (iph->version != 4)
		return false;

	/* 4 元组部分 */
	memset(k, 0, sizeof(*k));
	k->saddr = iph->saddr;
	k->daddr = iph->daddr;

	/* 头长：L2 + L3 + L4 */
	{
		unsigned int l2 = ETH_HLEN;
		unsigned int l3 = iph->ihl * 4;
		unsigned int l4 = 0;

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *th;
			if (!pskb_may_pull(skb, sizeof(*eth) + l3 + sizeof(*th)))
				return false;
			th = (struct tcphdr *)((u8 *)iph + l3);
			k->sport = th->source;
			k->dport = th->dest;
			l4 = th->doff * 4;
			fa->dst_port = ntohs(th->dest);
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *uh;
			if (!pskb_may_pull(skb, sizeof(*eth) + l3 + sizeof(*uh)))
				return false;
			uh = (struct udphdr *)((u8 *)iph + l3);
			k->sport = uh->source;
			k->dport = uh->dest;
			l4 = sizeof(*uh);
			fa->dst_port = ntohs(uh->dest);
		} else {
			return false;
		}
		fa->header_length = l2 + l3 + l4;
	}

	/* 统计更新 */
	{
		u64 now  = ktime_get_ns();
		u32 plen = skb->len;

		fa->num_packet++;
		if (fa->num_packet == 1) {
			fa->min_packet_length    = plen;
			fa->max_packet_length    = plen;
			fa->detection_start_time = now;
		} else {
			if (plen < fa->min_packet_length)
				fa->min_packet_length = plen;
			if (plen > fa->max_packet_length)
				fa->max_packet_length = plen;
		}
		if (fa->last_packet_time) {
			u64 dt = now - fa->last_packet_time;
			if (dt > fa->max_duration)
				fa->max_duration = dt;
		}
		fa->last_packet_time = now;
	}
	return true;
}

/* ------------ 处理一个包：更新表项 → 条件满足则推理 ------------ */
static void handle_packet(struct sk_buff *skb)
{
	struct flow key;
	struct flow_node *node;
	u32 h, bkt;
	struct flow_attribute fa_once = {0};
	int attr6[N0];
	int ret;

	if (!parse_and_update(skb, &key, &fa_once))
		return;

	h   = flow_hash(&key);
	bkt = hash_min(h, FLOW_HT_BITS);

	spin_lock(&bucket_locks[bkt]);

	/* 查找或新建 */
	hlist_for_each_entry(node, &flow_ht[bkt], hnode) {
		if (flow_equal(&node->key, &key))
			goto found;
	}
	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (!node) {
		spin_unlock(&bucket_locks[bkt]);
		return;
	}
	node->key = key;
	hlist_add_head(&node->hnode, &flow_ht[bkt]);

found:
	/* 合并一次更新到总特征 */
	if (node->fa.num_packet == 0) {
		node->fa = fa_once;
	} else {
		node->fa.num_packet++;
		if (fa_once.min_packet_length < node->fa.min_packet_length)
			node->fa.min_packet_length = fa_once.min_packet_length;
		if (fa_once.max_packet_length > node->fa.max_packet_length)
			node->fa.max_packet_length = fa_once.max_packet_length;
		if (fa_once.max_duration > node->fa.max_duration)
			node->fa.max_duration = fa_once.max_duration;
		node->fa.dst_port       = fa_once.dst_port;
		node->fa.header_length  = fa_once.header_length;
		node->fa.last_packet_time = fa_once.last_packet_time;
	}

	/* 触发推理（示例：每包都推；实战可改为 >= INFER_MIN_PKTS） */
	if (node->fa.num_packet >= INFER_MIN_PKTS) {
		normalize_attr_to_int6(&node->fa, attr6);
		ret = simdnn_analyze_and_infer(&g_model, sizeof(g_model),
		                               attr6, sizeof(attr6));
		if (ret >= 0) {
			int best = 0;
			for (int i = 1; i < N3; ++i)
				if (g_model.output_buffer.buffer[i] > g_model.output_buffer.buffer[best])
					best = i;

			pr_debug("simdnn: %pI4:%u -> %pI4:%u  y0=%d y1=%d  pred=%d\n",
			         &key.saddr, ntohs(key.sport),
			         &key.daddr, ntohs(key.dport),
			         g_model.output_buffer.buffer[0],
			         (N3>1? g_model.output_buffer.buffer[1] : 0),
			         best);
		}
	}

	spin_unlock(&bucket_locks[bkt]);
}

/* ------------ Netfilter 钩子 ------------ */
static unsigned int nf_prerouting_hook(void *priv,
				       struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	handle_packet(skb);
	return NF_ACCEPT;
}

int simdnn_lkm_register(void)
{
	/* 构建模型（一次） */
	build_model(&g_model);

	/* 初始化桶锁 */
	for (u32 i = 0; i < (1u << FLOW_HT_BITS); ++i)
		spin_lock_init(&bucket_locks[i]);

	/* 注册 IPv4 PRE_ROUTING 钩子 */
	memset(&nfops, 0, sizeof(nfops));
	nfops.hook     = nf_prerouting_hook;
	nfops.pf       = PF_INET;
	nfops.hooknum  = NF_INET_PRE_ROUTING;
	nfops.priority = NF_IP_PRI_FIRST;

	if (nf_register_net_hook(&init_net, &nfops)) {
		pr_err("simdnn: nf_register_net_hook failed\n");
		return -EINVAL;
	}

	pr_info("simdnn: lkm registered (pure kernel path)\n");
	return 0;
}

void simdnn_lkm_unregister(void)
{
	struct flow_node *node;
	struct hlist_node *tmp;
	u32 b;

	nf_unregister_net_hook(&init_net, &nfops);

	/* 清表 */
	hash_for_each_safe(flow_ht, b, tmp, node, hnode) {
		hlist_del(&node->hnode);
		kfree(node);
	}
	pr_info("simdnn: lkm unregistered\n");
}

MODULE_LICENSE("GPL");
