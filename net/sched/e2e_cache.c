// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/workqueue.h>
#include <linux/jhash.h>
#include <linux/bitmap.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/rhashtable.h>

#include <net/e2e_cache_api.h>
#include <net/pkt_cls.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack.h>

/* Number of reclassify + single CT per classify */
#define E2E_CACHE_MAX_TRACE_ENTRIES (TCF_MAX_RECLASSIFY_LOOP * 2)

enum {
	E2E_CACHE_TRACE_CACHEABLE  = BIT(0),
};

enum {
	E2E_ENTRY_INSERTED  = BIT(0),
};

/* Number of reclassify + single CT per classify */
#define E2E_CACHE_MAX_TRACE_ENTRIES (TCF_MAX_RECLASSIFY_LOOP * 2)

struct e2e_cache_tuple {
	union {
		struct in_addr          src_v4;
		struct in6_addr         src_v6;
	};
	union {
		struct in_addr          dst_v4;
		struct in6_addr         dst_v6;
	};
	struct {
		__be16                  src_port;
		__be16                  dst_port;
	};

	u8                              l3proto;
	u8                              l4proto;
};

struct e2e_cache_trace {
	u32 flags;
	const struct tcf_proto_ops *ops;

	struct e2e_cache_trace_entry entries[E2E_CACHE_MAX_TRACE_ENTRIES];
	int num_entries;

	int num_tps;
	int num_conns;
	u32 hash;

	__be16 protocol;

	struct tcf_e2e_cache *tcf_e2e_cache;

	struct work_struct work;
};

#define E2E_TRACING_BM_SIZE (1 << 23)

struct e2e_cache_entry_stats {
	u64 pkts;
	u64 bytes;
};

struct e2e_cache_entry_node {
	enum e2e_cache_trace_type type;
	int pos;

	struct { /* tp entry */
		struct tcf_proto *tp;
		void *fh;

		struct rhlist_head tp_node;
		struct rhlist_head tp_fh_node;

		struct e2e_cache_entry_stats last_stats_sw;
		struct e2e_cache_entry_stats last_stats_hw;
	};

};

struct e2e_cache_entry {
	struct e2e_cache_entry_node nodes[E2E_CACHE_MAX_TRACE_ENTRIES];
	struct tcf_proto *tp;
	int num_entries;

	refcount_t ref;
	struct rcu_head rcu;
	struct work_struct work;

	struct tcf_e2e_cache *tcf_e2e_cache;

	void *merged_fh;

	u64 lastused;
	unsigned long last_query;
	struct e2e_cache_entry_stats entry_stats_hw;
	struct e2e_cache_entry_stats entry_stats_sw;

	unsigned long flags;
};

static DEFINE_PER_CPU(struct e2e_cache_trace *, packet_trace);
static DECLARE_BITMAP(e2e_tracing_bm, E2E_TRACING_BM_SIZE) = {0};
static struct kmem_cache *e2e_cache_mem;
static struct workqueue_struct *e2e_wq;
static const u32 prio = 1 << 16;

static struct tcf_proto *
e2e_cache_lookup_tp(struct tcf_block *block, const struct tcf_proto_ops *ops,
		    u32 prio)
{
	struct tcf_chain_info chain_info;
	struct tcf_chain *chain;
	struct tcf_proto *tp;

	chain = block->chain0.chain;
	mutex_lock(&chain->filter_chain_lock);
	tp = tcf_chain_tp_find(chain, &chain_info, ETH_P_ALL, prio, false);
	mutex_unlock(&chain->filter_chain_lock);
	if (IS_ERR_OR_NULL(tp))
		return tp;
	else if (tp->ops != ops)
		return ERR_PTR(-EINVAL);
	return tp;
}

static const struct rhashtable_params tp_rhl_params = {
	.key_len = FIELD_SIZEOF(struct e2e_cache_entry_node, tp),
	.key_offset = offsetof(struct e2e_cache_entry_node, tp),
	.head_offset = offsetof(struct e2e_cache_entry_node, tp_node),
	.automatic_shrinking = true,
	.min_size = 1,
};

static const struct rhashtable_params tp_fh_rhl_params = {
	.key_len = FIELD_SIZEOF(struct e2e_cache_entry_node, tp) +
		   FIELD_SIZEOF(struct e2e_cache_entry_node, fh),
	.key_offset = offsetof(struct e2e_cache_entry_node, tp),
	.head_offset = offsetof(struct e2e_cache_entry_node, tp_fh_node),
	.automatic_shrinking = true,
	.min_size = 1,
};

static void e2e_cache_entry_delete_work(struct work_struct *work);
static void e2e_cache_entry_update_hw_stats_work(struct work_struct *work);

static int
e2e_cache_entry_insert(struct tcf_e2e_cache *tcf_e2e_cache, struct e2e_cache_trace *trace,
		       struct e2e_cache_entry *merged_entry)
{
	struct e2e_cache_entry_node *node;
	int i, err;

	for (i = 0; i < trace->num_entries; i++) {
		struct e2e_cache_entry_node *node;

		node = &merged_entry->nodes[i];

		node->pos = i;
		node->type = trace->entries[i].type;
		if (trace->entries[i].type == E2E_CACHE_TRACE_TP) {
			node->tp = trace->entries[i].tp;
			node->fh = trace->entries[i].fh;

			err = rhltable_insert(&tcf_e2e_cache->tp_rhl, &node->tp_node,
					      tp_rhl_params);
			if (err)
				goto err_tp;
			refcount_inc(&merged_entry->ref);

			err = rhltable_insert(&tcf_e2e_cache->tp_fh_rhl, &node->tp_fh_node,
					      tp_fh_rhl_params);
			if (err)
				goto err_tp_fh;
			refcount_inc(&merged_entry->ref);
		} else if (trace->entries[i].type == E2E_CACHE_TRACE_CT) {
			//TODO: CT handling
		}

		merged_entry->num_entries++;
	}

	set_bit(E2E_ENTRY_INSERTED, &merged_entry->flags);

	return 0;

err_tp_fh:
	pr_debug("err_tp_fh\n");
	rhltable_remove(&tcf_e2e_cache->tp_rhl, &node->tp_node, tp_rhl_params);
	refcount_dec(&merged_entry->ref);
err_tp:
	pr_debug("err_tp\n");
	while (i-- > 0) {
		// Cleanup previous [(i-1) - 0] nodes
		node = &merged_entry->nodes[i];

		if (node->type == E2E_CACHE_TRACE_TP) {
			rhltable_remove(&tcf_e2e_cache->tp_rhl, &node->tp_node,
					tp_rhl_params);
			refcount_dec(&merged_entry->ref);
			rhltable_remove(&tcf_e2e_cache->tp_fh_rhl, &node->tp_fh_node,
					tp_fh_rhl_params);
			refcount_dec(&merged_entry->ref);
		}
	}

	return err;
}

static struct rhlist_head *
e2e_cache_entries_lookup(struct tcf_e2e_cache *tcf_e2e_cache,
			 const struct tcf_proto *tp, void *fh)
{
	struct {
		const struct tcf_proto *tp;
		void *fh;
	} tp_fh_key;

	if (!fh)
		return rhltable_lookup(&tcf_e2e_cache->tp_rhl, &tp, tp_rhl_params);

	tp_fh_key.tp = tp;
	tp_fh_key.fh = fh;

	return rhltable_lookup(&tcf_e2e_cache->tp_fh_rhl, &tp_fh_key, tp_fh_rhl_params);
}

static struct e2e_cache_entry *
e2e_cache_entry_from_entry_node(struct e2e_cache_entry_node *node)
{
	return container_of(node, struct e2e_cache_entry, nodes[node->pos]);
}

static void
e2e_cache_entry_remove(struct e2e_cache_entry *entry)
{
	struct tcf_e2e_cache *tcf_e2e_cache = entry->tcf_e2e_cache;
	int i;

	if (!test_and_clear_bit(E2E_ENTRY_INSERTED, &entry->flags))
		return;

	for (i = 0; i < entry->num_entries; i++) {
		struct e2e_cache_entry_node *node = &entry->nodes[i];

		if (node->type == E2E_CACHE_TRACE_TP) {
			rhltable_remove(&tcf_e2e_cache->tp_rhl, &node->tp_node,
					tp_rhl_params);
			refcount_dec(&entry->ref);

			rhltable_remove(&tcf_e2e_cache->tp_fh_rhl, &node->tp_fh_node,
					tp_fh_rhl_params);
			refcount_dec(&entry->ref);
		}
	}
}

static void
e2e_cache_entry_delete(struct e2e_cache_entry *entry)
{
	bool last;

	pr_debug("Deleting merged entry=0x%p\n", entry);

	entry->tp->ops->delete(entry->tp, entry->merged_fh, &last, true, NULL);

	tcf_proto_put(entry->tp, false, NULL);

	kfree_rcu(entry, rcu);
}

static bool
e2e_cache_entry_get(struct e2e_cache_entry *entry)
{
	return refcount_inc_not_zero(&entry->ref);
}

static void
e2e_cache_entry_put(struct e2e_cache_entry *entry)
{
	if (!refcount_dec_and_test(&entry->ref))
		return;

	INIT_WORK(&entry->work, &e2e_cache_entry_delete_work);
	queue_work(e2e_wq, &entry->work);
}

static void
e2e_cache_entry_put_sync(struct e2e_cache_entry *entry)
{
	if (!refcount_dec_and_test(&entry->ref))
		return;

	e2e_cache_entry_delete(entry);
}

typedef int (*e2e_cache_entries_walk_entry_fn)(const struct tcf_proto *tp, void *fh,
					       struct e2e_cache_entry *merged_entry,
					       struct e2e_cache_entry_node *node);

static int
e2e_cache_entry_unref(const struct tcf_proto *tp, void *fh,
		      struct e2e_cache_entry *merged_entry,
		      struct e2e_cache_entry_node *node)
{
	e2e_cache_entry_remove(merged_entry);
	return 0;
}

static void
e2e_cache_entries_walk(struct tcf_e2e_cache *tcf_e2e_cache,
		       const struct tcf_proto *tp, void *fh,
		       e2e_cache_entries_walk_entry_fn walk_fn)
{
	struct e2e_cache_entry_node *node;
	struct rhlist_head *list, *pos;
	int err;

	if (!walk_fn)
		return;

	rcu_read_lock();

	list = e2e_cache_entries_lookup(tcf_e2e_cache, tp, fh);
	rhl_for_each_rcu(pos, list) {
		struct e2e_cache_entry *merged_entry;

		// Get entry's node
		if (!fh)
			rht_entry(node, pos, tp_node);
		else
			rht_entry(node, pos, tp_fh_node);

		if (rht_is_a_nulls(&pos->rhead)) {
			pr_debug("err\n");
			break;
		}

		// Get actual entry
		merged_entry = e2e_cache_entry_from_entry_node(node);
		if (!e2e_cache_entry_get(merged_entry)) {
			pr_debug("merged_entry get err\n");
			continue;
		}

		err = walk_fn(tp, fh, merged_entry, node);
		if (err)
			pr_debug("walk fn failed err=%d\n", err);

		e2e_cache_entry_put(merged_entry);
	}

	rcu_read_unlock();
}

static bool
e2e_cache_extract_ipv4(struct sk_buff *skb, struct e2e_cache_tuple *tuple)
{
	struct iphdr *iph;

	if (!pskb_network_may_pull(skb, sizeof(*iph)))
		return false;

	iph = ip_hdr(skb);
	if (ip_is_fragment(iph))
		return false;

	tuple->l3proto = AF_INET;
	tuple->l4proto = iph->protocol;
	tuple->src_v4.s_addr = iph->saddr;
	tuple->dst_v4.s_addr = iph->daddr;

	if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph;

		if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(*udph)))
			return false;

		udph = udp_hdr(skb);
		tuple->src_port = udph->source;
		tuple->dst_port = udph->dest;
	} else if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph;

		if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(*tcph)))
			return false;

		tcph = tcp_hdr(skb);
		tuple->src_port = tcph->source;
		tuple->dst_port = tcph->dest;
	} else {
		return false;
	}

	return true;
}

static bool
e2e_cache_extract_ipv6(struct sk_buff *skb, struct e2e_cache_tuple *tuple)
{
	unsigned int offset = 0;
	unsigned short fragoff;
	struct ipv6hdr *ip6h;
	int nexthdr;

	if (!pskb_network_may_pull(skb, sizeof(*ip6h)))
		return false;

	ip6h = ipv6_hdr(skb);
	tuple->l3proto = AF_INET6;
	tuple->src_v6 = ip6h->saddr;
	tuple->dst_v6 = ip6h->daddr;

	nexthdr = ipv6_find_hdr(skb, &offset, -1, &fragoff, NULL);
	if (fragoff)
		return false;
	tuple->l4proto = nexthdr;

	if (nexthdr == IPPROTO_UDP) {
		struct udphdr *udph;

		if (!pskb_may_pull(skb, offset + sizeof(*udph)))
			return false;

		udph = udp_hdr(skb);
		tuple->src_port = udph->source;
		tuple->dst_port = udph->dest;
	} else if (nexthdr == IPPROTO_TCP) {
		struct tcphdr *tcph;

		if (!pskb_may_pull(skb, offset + sizeof(*tcph)))
			return false;

		tcph = tcp_hdr(skb);
		tuple->src_port = tcph->source;
		tuple->dst_port = tcph->dest;
	} else {
		return false;
	}

	return true;
}

static bool
e2e_cache_extract_tuple(struct sk_buff *skb, struct e2e_cache_tuple *tuple)
{
	__be16 proto = skb_protocol(skb, true);

	if (proto == htons(ETH_P_IP))
		return e2e_cache_extract_ipv4(skb, tuple);
	else if (proto == htons(ETH_P_IPV6))
		return e2e_cache_extract_ipv6(skb, tuple);
	else
		return false;
}

static bool
e2e_cache_mark_tracing(struct e2e_cache_tuple *tuple, u32 *hash)
{
	*hash = jhash(tuple, sizeof(*tuple), 0) % E2E_TRACING_BM_SIZE;
	return !test_and_set_bit(*hash, e2e_tracing_bm);
}

static void
e2e_cache_unmark_tracing(u32 hash)
{
	clear_bit(hash, e2e_tracing_bm);
}

static void e2e_cache_trace_release(struct e2e_cache_trace *trace)
{
	int i;

	if (trace->tcf_e2e_cache)
		e2e_cache_put(trace->tcf_e2e_cache);

	for (i = 0; i < trace->num_entries; i++) {
		if (trace->entries[i].type == E2E_CACHE_TRACE_TP) {
			struct tcf_proto *tp = trace->entries[i].tp;
			void *fh = trace->entries[i].fh;

			if (fh)
				tp->ops->put(tp, fh);
			tcf_proto_put(tp, false, NULL);
		}
	}

	e2e_cache_unmark_tracing(trace->hash);
	kmem_cache_free(e2e_cache_mem, trace);
}

static void e2e_cache_trace_process_work(struct work_struct *work)
{
	struct e2e_cache_trace *trace = container_of(work,
						     struct e2e_cache_trace,
						     work);
	struct tcf_e2e_cache *tcf_e2e_cache = trace->tcf_e2e_cache;
	struct e2e_cache_trace_data trace_data;
	struct e2e_cache_entry *merged_entry;
	struct tcf_proto *tp;
	void *merged_fh;
	int err;

	pr_debug("process work\n");

	tp = e2e_cache_lookup_tp(tcf_e2e_cache->block, trace->ops, prio);
	if (IS_ERR_OR_NULL(tp)) {
		pr_err("tp not found\n");
		goto err_out_tp;
	}

	/* call the classifier's merge */
	trace_data.entries = trace->entries;
	trace_data.num_entries = trace->num_entries;
	trace_data.protocol = trace->protocol;

	err = trace->ops->merge(tp, &trace_data, &merged_fh);
	if (err) {
		pr_debug("merge failed, err %d\n", err);
		goto err_out_merge;
	}

	merged_entry = kzalloc(sizeof(*merged_entry), GFP_KERNEL);
	if (!merged_entry)
		goto err_out_alloc;

	tcf_proto_get_not_zero(tp);
	merged_entry->tp = tp;

	refcount_set(&merged_entry->ref, 1);
	merged_entry->tcf_e2e_cache = tcf_e2e_cache;
	merged_entry->merged_fh = merged_fh;
	if (e2e_cache_entry_insert(tcf_e2e_cache, trace, merged_entry))
		goto err_out_insert;

	tcf_proto_put(tp, false, NULL);
	e2e_cache_trace_release(trace);

	return;

err_out_insert:
	e2e_cache_entry_delete(merged_entry);
err_out_alloc:
err_out_merge:
	tcf_proto_put(tp, false, NULL);
err_out_tp:
	e2e_cache_trace_release(trace);
}

static void e2e_cache_trace_release_work(struct work_struct *work)
{
	struct e2e_cache_trace *trace = container_of(work,
						     struct e2e_cache_trace,
						     work);

	pr_debug("release work\n");
	e2e_cache_trace_release(trace);
}
static void
e2e_cache_trace_begin_impl(struct tcf_e2e_cache *tcf_e2e_cache, struct sk_buff *skb)
{
	struct e2e_cache_trace **trace = this_cpu_ptr(&packet_trace);
	struct e2e_cache_tuple tuple;
	u32 hash;

	memset(&tuple, 0, sizeof(tuple));

	if (!e2e_cache_extract_tuple(skb, &tuple)) {
		pr_debug("extract tuple failed\n");
		return;
	}

	if (!e2e_cache_mark_tracing(&tuple, &hash)) {
		pr_debug("tuple already being traced\n");
		return;
	}

	*trace = kmem_cache_alloc(e2e_cache_mem, GFP_ATOMIC);
	if (!*trace) {
		e2e_cache_unmark_tracing(hash);
		return;
	}

	pr_debug("l3=%hhu l4=%hhu %pI4:%hu to %pI4:%hu (%u)\n",
		 tuple.l3proto, tuple.l4proto,
		 &tuple.src_v4, ntohs(tuple.src_port), &tuple.dst_v4, ntohs(tuple.dst_port),
		 hash);
	memset(*trace, 0, sizeof(**trace));

	(*trace)->flags = E2E_CACHE_TRACE_CACHEABLE;
	(*trace)->tcf_e2e_cache = tcf_e2e_cache;
	(*trace)->hash = hash;
	(*trace)->tcf_e2e_cache = tcf_e2e_cache;
}

static void
e2e_cache_trace_tp_impl(struct sk_buff *skb,
			const struct tcf_proto *const_tp,
			int classify_ret,
			struct tcf_result *res)
{
	struct e2e_cache_trace *trace = *this_cpu_ptr(&packet_trace);
	struct tcf_proto *tp = (struct tcf_proto *)const_tp;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	if (!trace || !(trace->flags & E2E_CACHE_TRACE_CACHEABLE))
		return;

	pr_debug("trace=0x%p flags=%d\n", trace, trace->flags);
	if (trace->num_entries >= E2E_CACHE_MAX_TRACE_ENTRIES)
		goto not_cacheable;

	/* only filters with goto chain actions may be cached */
	if (!TC_ACT_EXT_CMP(classify_ret, TC_ACT_GOTO_CHAIN) &&
	    classify_ret != TC_ACT_CONSUMED)
		goto not_cacheable;

	/* trace only if we have a fh */
	if (!res->fh)
		goto not_cacheable;

	/* trace only classifiers of the same kind */
	if (!trace->ops) {
		trace->ops = tp->ops;
		/* trace only classifier supporting cache related ops */
		if (!tp->ops->merge || !tp->ops->take || !tp->ops->put)
			goto not_cacheable;
		trace->protocol = tp->protocol;
	} else if (trace->ops != tp->ops) {
		pr_debug("trace=0x%p diff ops: 0x%p 0x%p\n", trace, trace->ops, tp->ops);
		goto not_cacheable;
	}

	if (classify_ret != TC_ACT_CONSUMED) {
		/* If ct was executed then make sure to trace only established connections */
		ct = nf_ct_get(skb, &ctinfo);
		if (ct &&
		    (ctinfo != IP_CT_UNTRACKED &&
		     ctinfo != IP_CT_ESTABLISHED && ctinfo != IP_CT_ESTABLISHED_REPLY)) {
			pr_debug("trace=0x%p ct_state=%d\n", trace, ctinfo);
			goto not_cacheable;
		}

		/* Don't trace tcp connections teardown sequence */
		if (ct && nf_ct_protonum(ct) == IPPROTO_TCP &&
		    ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) {
			pr_debug("trace=0x%p tcp_state=%d\n", trace, ct->proto.tcp.state);
			goto not_cacheable;
		}
	}

	if (!tcf_proto_get_not_zero(tp)) {
		pr_debug("trace=0x%p can't take tp\n", trace);
		goto not_cacheable;
	}

	trace->entries[trace->num_entries].type = E2E_CACHE_TRACE_TP;
	trace->entries[trace->num_entries].tp = (struct tcf_proto *)tp;
	if (tp->ops->take(tp, res->fh)) {
		trace->entries[trace->num_entries].fh = res->fh;
	} else {
		pr_debug("trace=0x%p can't take fh\n", trace);
		trace->flags &= ~E2E_CACHE_TRACE_CACHEABLE;
	}

	trace->num_entries++;
	trace->num_tps++;
	return;

not_cacheable:
	pr_debug("trace not cacheable\n");
	trace->flags &= ~E2E_CACHE_TRACE_CACHEABLE;
}

static void
e2e_cache_trace_end_impl(struct sk_buff *skb, int classify_result)
{
	struct e2e_cache_trace **pcputrace = this_cpu_ptr(&packet_trace);
	struct e2e_cache_trace *trace = *pcputrace;

	if (!trace)
		return;

	*pcputrace = NULL;
	pr_debug("trace=0x%p flags=%d\n", trace, trace->flags);

	if (!(trace->flags & E2E_CACHE_TRACE_CACHEABLE))
		goto trace_failed;

	if (classify_result != TC_ACT_CONSUMED || trace->num_tps < 2)
		goto trace_failed;

	if (!e2e_cache_get(trace->tcf_e2e_cache)) {
		trace->flags &= ~E2E_CACHE_TRACE_CACHEABLE;
		goto trace_failed;
	}

	pr_debug("trace=0x%p processing trace of %d chains %d connections\n"
		 , trace
		 , trace->num_tps
		 , trace->num_conns);

	INIT_WORK(&trace->work, e2e_cache_trace_process_work);
	queue_work(e2e_wq, &trace->work);
	return;

trace_failed:
	pr_debug("cleaning up trace of %d chains\n", trace->num_tps);
	trace->tcf_e2e_cache = NULL;
	if (trace->num_entries) {
		/* Releasing tp or filter instance is potentially sleeping and
		 * must be done on workqueue.
		 */
		INIT_WORK(&trace->work, e2e_cache_trace_release_work);
		queue_work(e2e_wq, &trace->work);
	} else {
		e2e_cache_trace_release(trace);
	}
}

static void e2e_cache_entry_delete_work(struct work_struct *work)
{
	struct e2e_cache_entry *entry = container_of(work,
						     struct e2e_cache_entry,
						     work);

	e2e_cache_entry_delete(entry);
}

struct e2e_cache_entry_update_work {
	struct work_struct work;
	struct e2e_cache_entry *entry;
};

static void e2e_cache_entry_update_hw_stats_work(struct work_struct *work)
{
	struct e2e_cache_entry_update_work *update_work;
	struct e2e_cache_entry *entry;
	struct flow_stats flow_stats;

	update_work = container_of(work, struct e2e_cache_entry_update_work, work);
	entry = update_work->entry;

	entry->tp->ops->get_hw_stats(entry->tp, entry->merged_fh, &flow_stats);

	e2e_cache_entry_put(entry);
	e2e_cache_put(entry->tcf_e2e_cache);

	kfree(work);
}

static void
e2e_cache_entry_update(struct tcf_e2e_cache *tcf_e2e_cache, struct e2e_cache_entry *entry)
{
	struct gnet_stats_basic_packed bstats = {0}, bstats_hw = {0};
	struct e2e_cache_entry_update_work *update_work;
	struct tcf_exts *exts;

	if (!time_after(jiffies, entry->last_query + jiffies_to_msecs(1000)))
		return;

	update_work = kzalloc(sizeof(*update_work), GFP_ATOMIC);
	if (!update_work)
		return;

	if (!e2e_cache_get(entry->tcf_e2e_cache)) {
		kfree(update_work);
		return;
	}

	entry->last_query = jiffies;

	// update the hw stats - cannot be called in RCU context
	// will be available for the next round
	e2e_cache_entry_get(entry);
	update_work->entry = entry;
	INIT_WORK(&update_work->work, &e2e_cache_entry_update_hw_stats_work);
	queue_work(e2e_wq, &update_work->work);

	// calc sw stats diff
	exts = entry->tp->ops->get_exts(entry->tp, entry->merged_fh);
	__gnet_stats_copy_basic(NULL, &bstats, exts->actions[0]->cpu_bstats, &exts->actions[0]->tcfa_bstats);
	__gnet_stats_copy_basic(NULL, &bstats_hw, exts->actions[0]->cpu_bstats_hw, &exts->actions[0]->tcfa_bstats_hw);

	entry->entry_stats_sw.pkts = bstats.packets - bstats_hw.packets;
	entry->entry_stats_sw.bytes = bstats.bytes - bstats_hw.bytes;
	entry->entry_stats_hw.pkts = bstats_hw.packets;
	entry->entry_stats_hw.bytes = bstats_hw.bytes;
	entry->lastused = max_t(u64, entry->lastused, exts->actions[0]->tcfa_tm.lastuse);
}

static int
e2e_cache_stats_update_walk(const struct tcf_proto *tp, void *fh,
			    struct e2e_cache_entry *entry, struct e2e_cache_entry_node *node)
{
	struct tcf_exts *exts;

	e2e_cache_entry_update(entry->tcf_e2e_cache, entry);

	// Report diff
	exts = tp->ops->get_exts(tp, fh);
	tcf_exts_stats_update(exts,
			      entry->entry_stats_hw.bytes - node->last_stats_hw.bytes,
			      entry->entry_stats_hw.pkts - node->last_stats_hw.pkts,
			      entry->lastused);
	tcf_exts_stats_update_sw(exts,
				 entry->entry_stats_sw.bytes - node->last_stats_sw.bytes,
				 entry->entry_stats_sw.pkts - node->last_stats_sw.pkts,
				 entry->lastused);

	// Save for next diff
	node->last_stats_hw.bytes = entry->entry_stats_hw.bytes;
	node->last_stats_hw.pkts = entry->entry_stats_hw.pkts;
	node->last_stats_sw.bytes = entry->entry_stats_sw.bytes;
	node->last_stats_sw.pkts = entry->entry_stats_sw.pkts;

	return 0;
}

static void
e2e_cache_trace_ct_impl(struct nf_flowtable *nf_ft, struct flow_offload *flow, int dir)
{
	unsigned long cookie = (unsigned long) &flow->tuplehash[!dir].tuple;
	struct e2e_cache_trace *trace = *this_cpu_ptr(&packet_trace);

	if (!trace || !(trace->flags & E2E_CACHE_TRACE_CACHEABLE))
		return;

	/* This can happen if one filter has several CT actions */
	if (trace->num_entries == E2E_CACHE_MAX_TRACE_ENTRIES) {
		pr_debug("trace=0x%p\n", trace);
		trace->flags &= ~E2E_CACHE_TRACE_CACHEABLE;
		return;
	}

	trace->entries[trace->num_entries].type = E2E_CACHE_TRACE_CT;
	trace->entries[trace->num_entries].nf_ft = nf_ft;
	trace->entries[trace->num_entries].flow = flow;
	trace->entries[trace->num_entries].dir = dir;
	trace->entries[trace->num_entries].cookie = cookie;
	trace->num_entries++;
	trace->num_conns++;
	pr_debug("trace=0x%p flow=0x%p dir=%d num_conns=%d\n", trace
						             , flow, dir, trace->num_conns);
}

static void
e2e_cache_filter_delete_impl(struct tcf_e2e_cache *tcf_e2e_cache,
			     const struct tcf_proto *tp,
			     void *fh)
{
	e2e_cache_entries_walk(tcf_e2e_cache, tp, fh, &e2e_cache_entry_unref);
}

static void
e2e_cache_tp_destroy_impl(struct tcf_e2e_cache *tcf_e2e_cache,
			  const struct tcf_proto *tp)
{
	e2e_cache_filter_delete_impl(tcf_e2e_cache, tp, NULL);
}

static void
e2e_cache_filter_update_stats_impl(struct tcf_e2e_cache *tcf_e2e_cache,
				   const struct tcf_proto *tp,
				   void *fh)
{
	e2e_cache_entries_walk(tcf_e2e_cache, tp, fh, &e2e_cache_stats_update_walk);
}

static struct tcf_e2e_cache *
e2e_cache_create_impl(struct Qdisc *q, enum flow_block_binder_type binder_type)
{
	struct tcf_block_ext_info ei = {
		.chain_head_change_priv = q,
		.block_index = TCF_BLOCK_E2E_CACHE,
	};
	struct tcf_proto *tp, *tp_new;
	struct tcf_e2e_cache *e2e_cache;
	struct tcf_block *block;
	struct tcf_chain *chain;
	int err;

	if (binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		ei.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS_E2E;
	else
		return ERR_PTR(-EOPNOTSUPP);

	e2e_cache = kzalloc(sizeof(*e2e_cache), GFP_KERNEL);
	if (!e2e_cache)
		return ERR_PTR(-ENOMEM);

	err = rhltable_init(&e2e_cache->tp_rhl, &tp_rhl_params);
	if (err)
		goto err_tp_rhl;
	err = rhltable_init(&e2e_cache->tp_fh_rhl, &tp_fh_rhl_params);
	if (err)
		goto err_tp_fh_rhl;

	err = tcf_block_get_ext(&block, q, &ei, false, NULL);
	if (err)
		goto err_block;

	mutex_lock(&block->lock);
	chain = tcf_chain_create(block, 0, true);
	mutex_unlock(&block->lock);
	if (!chain) {
		err = -ENOMEM;
		goto err_chain;
	}

err_eagain:
	tp_new = tcf_proto_create("flower", ETH_P_ALL, prio, chain, true, NULL);
	if (IS_ERR(tp_new)) {
		/* first user, module was loaded */
		if (PTR_ERR(tp_new) == -EAGAIN)
			goto err_eagain;
		err = PTR_ERR(tp_new);
		goto err_tp;
	}

	tp = tcf_chain_tp_insert_unique(chain, tp_new, ETH_P_ALL, prio, true);
	if (IS_ERR(tp)) {
		err = PTR_ERR(tp);
		goto err_tp;
	}
	/* insert function acquired new reference */
	tcf_proto_put(tp, true, NULL);

	/* persistent chain that is not deleted with last tp */
	mutex_lock(&chain->block->lock);
	tcf_chain_hold(chain);
	chain->explicitly_created = true;
	mutex_unlock(&chain->block->lock);

	__module_get(THIS_MODULE);
	e2e_cache->block = block;
	tcf_block_hold(e2e_cache->block);
	refcount_set(&e2e_cache->refcnt, 1);
	pr_debug("chain=0x%p tp=0x%p\n", chain, tp);

	return e2e_cache;

err_tp:
	tcf_chain_put(chain);
err_chain:
	tcf_block_put_ext(block, q, &ei);
err_block:
	rhltable_destroy(&e2e_cache->tp_fh_rhl);
err_tp_fh_rhl:
	rhltable_destroy(&e2e_cache->tp_rhl);
err_tp_rhl:
	kfree(e2e_cache);
	return ERR_PTR(err);
}

static void
e2e_cache_detach_impl(struct tcf_e2e_cache *tcf_e2e_cache, struct Qdisc *q,
		      enum flow_block_binder_type binder_type)
{
	struct tcf_block_ext_info ei = {
		.chain_head_change_priv = q,
		.block_index = TCF_BLOCK_E2E_CACHE,
	};

	if (binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		ei.binder_type = FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS_E2E;
	else
		WARN_ON(1);

	tcf_block_put_ext(tcf_e2e_cache->block, q, &ei);
	pr_debug("Cache detached\n");
}

static void
e2e_cache_tp_fh_rhl_free_fn(void *ptr, void *arg)
{
	struct e2e_cache_entry_node *node = ptr;
	struct e2e_cache_entry *entry;

	entry = e2e_cache_entry_from_entry_node(node);
	e2e_cache_entry_put_sync(entry);
}

static void
e2e_cache_destroy_impl(struct tcf_e2e_cache *tcf_e2e_cache)
{
	rhltable_free_and_destroy(&tcf_e2e_cache->tp_rhl, e2e_cache_tp_fh_rhl_free_fn, NULL);
	rhltable_free_and_destroy(&tcf_e2e_cache->tp_fh_rhl, e2e_cache_tp_fh_rhl_free_fn, NULL);

	tcf_block_put(tcf_e2e_cache->block);
	module_put(THIS_MODULE);
	kfree_rcu(tcf_e2e_cache, rcu);
	pr_debug("Cache destroyed\n");
}

static void
e2e_cache_indr_cmd_impl(struct tcf_e2e_cache *tcf_e2e_cache,
			struct net_device *dev,
			flow_indr_block_bind_cb_t *cb, void *cb_priv,
			enum flow_block_command command,
			enum flow_block_binder_type binder_type)
{
	struct tcf_block *block = tcf_e2e_cache->block;

	if (binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		tc_indr_block_cmd(dev, block, cb, cb_priv, command,
				  FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS_E2E);
	else
		WARN_ON(1);
}

static int
e2e_cache_classify_impl(struct tcf_e2e_cache *tcf_e2e_cache,
			struct sk_buff *skb,
			struct tcf_result *res)
{
	struct tcf_chain *cache_chain;
	struct tcf_proto *tp;

	if (!tcf_e2e_cache)
		return -ENOENT;

	cache_chain = tcf_e2e_cache->block->chain0.chain;
	for (tp = rcu_dereference_bh(cache_chain->filter_chain);
	     tp; tp = rcu_dereference_bh(tp->next)) {
		int err = tp->classify(skb, tp, res);

		if (err >= 0) {
			pr_debug("Cache classify hit\n");
			return err;
		}
	}

	pr_debug("Cache classify miss\n");
	return -1;
}

static int e2e_cache_dump_impl(struct tcf_e2e_cache *tcf_e2e_cache,
			       struct sk_buff *skb,
			       struct netlink_callback *cb, long index_start,
			       long *index, bool terse_dump)
{
	if (!tcf_chain_dump(tcf_e2e_cache->block->chain0.chain, NULL, 0, skb,
			    cb, index_start, index, terse_dump))
		return -EMSGSIZE;
	return 0;
}

static struct e2e_cache_ops e2e_cache_ops = {
	.create		= e2e_cache_create_impl,
	.detach		= e2e_cache_detach_impl,
	.destroy	= e2e_cache_destroy_impl,
	.trace_begin	= e2e_cache_trace_begin_impl,
	.trace_tp	= e2e_cache_trace_tp_impl,
	.trace_end	= e2e_cache_trace_end_impl,
	.trace_ct	= e2e_cache_trace_ct_impl,
	.tp_destroy	= e2e_cache_tp_destroy_impl,
	.filter_delete	= e2e_cache_filter_delete_impl,
	.filter_update_stats	= e2e_cache_filter_update_stats_impl,
	.classify	= e2e_cache_classify_impl,
	.dump		= e2e_cache_dump_impl,
	.indr_cmd	= e2e_cache_indr_cmd_impl,
};

static int
__init e2e_cache_init(void)
{
	e2e_cache_mem = KMEM_CACHE(e2e_cache_trace, SLAB_HWCACHE_ALIGN);
	if (!e2e_cache_mem)
		return -ENOMEM;

	e2e_wq = alloc_workqueue("tc_e2e_workqueue", WQ_UNBOUND, 0);
	if(!e2e_wq) {
		kmem_cache_destroy(e2e_cache_mem);
		return -ENOMEM;
	}

	e2e_cache_register_ops(&e2e_cache_ops);
	return 0;
}

static void
__exit e2e_cache_exit(void)
{
	e2e_cache_unregister_ops();
	destroy_workqueue(e2e_wq);
	kmem_cache_destroy(e2e_cache_mem);

}

module_init(e2e_cache_init);
module_exit(e2e_cache_exit);

MODULE_AUTHOR("Oz Shlomo <ozsh@nvidia.com>");
MODULE_AUTHOR("Paul Blakey <paulb@nvidia.com>");
MODULE_AUTHOR("Vlad Buslov <vladbu@nvidia.com>");
MODULE_AUTHOR("Roi Dayan <roid@nvidia.com>");
MODULE_DESCRIPTION("E2E cache");
MODULE_LICENSE("GPL");
