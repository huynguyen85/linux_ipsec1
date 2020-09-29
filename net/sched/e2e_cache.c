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

/* Number of reclassify + single CT per classify */
#define E2E_CACHE_MAX_TRACE_ENTRIES (TCF_MAX_RECLASSIFY_LOOP * 2)

enum e2e_cache_trace_type {
	E2E_CACHE_TRACE_TP,
	E2E_CACHE_TRACE_CT,
};

struct e2e_cache_trace_entry {
	enum e2e_cache_trace_type type;

	union {
		struct { /* tp entry */
			struct tcf_proto *tp;
			void *fh;
		};

		struct { /* ct entry */
			struct flow_offload *flow;
			int dir;
		};
	};
};

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

struct e2e_cache_entry {
	struct e2e_cache_trace_entry entries[E2E_CACHE_MAX_TRACE_ENTRIES];
	int num_entries;

	void *merged_fh;
};

struct tcf_e2e_cache {
	struct tcf_chain *tcf_e2e_chain;
	struct tcf_proto *tp;
	struct e2e_cache_entry *entry;
};

static DEFINE_PER_CPU(struct e2e_cache_trace *, packet_trace);
static DECLARE_BITMAP(e2e_tracing_bm, E2E_TRACING_BM_SIZE) = {0};
static struct kmem_cache *e2e_cache_mem;
static struct workqueue_struct *e2e_wq;

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

static void
e2e_cache_destroy_tp(struct tcf_e2e_cache *tcf_e2e_cache)
{
	tcf_chain_tp_delete_empty(tcf_e2e_cache->tcf_e2e_chain, tcf_e2e_cache->tp);
	tcf_proto_put(tcf_e2e_cache->tp, true, NULL);
	tcf_e2e_cache->tp = NULL;
}

static void e2e_cache_trace_release(struct e2e_cache_trace *trace)
{
	int i;

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
	struct e2e_cache_entry *merged_entry;
	bool tp_created = false;

	pr_debug("process work\n");

	if (!tcf_e2e_cache->tp) {
		struct tcf_proto *tp;

		tp = tcf_proto_create_and_insert(trace->ops->kind, ETH_P_ALL , 1 << 16,
						 tcf_e2e_cache->tcf_e2e_chain);
		if (IS_ERR(tp))
			goto err_out;

		pr_debug("created %s tp for proto 0x%x\n", trace->ops->kind
							 , trace->protocol);
		tcf_e2e_cache->tp = tp;
		tp_created = true;
	}

	/* Only room for one tp kind for now */
	if (tcf_e2e_cache->tp->ops != trace->ops)
		goto err_out;

	merged_entry = kzalloc(sizeof(*merged_entry), GFP_KERNEL);
	if (!merged_entry)
		goto err_out;

	memcpy(&merged_entry->entries, &trace->entries, sizeof(trace->entries));
	merged_entry->num_entries = trace->num_entries;

	//tp->merge() here and save merged_fh in entry
	tcf_e2e_cache->entry = merged_entry;

	return;

err_out:
	if (tp_created)
		tcf_proto_put(tcf_e2e_cache->tp, true, NULL);
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
		if (!tp->ops->take || !tp->ops->put)
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

	pr_debug("trace=0x%p processing trace of %d chains %d connections\n"
		 , trace
		 , trace->num_tps
		 , trace->num_conns);

	INIT_WORK(&trace->work, e2e_cache_trace_process_work);
	queue_work(e2e_wq, &trace->work);
	return;

trace_failed:
	pr_debug("cleaning up trace of %d chains\n", trace->num_tps);
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

static void
e2e_cache_entry_delete(struct tcf_e2e_cache *tcf_e2e_cache, struct e2e_cache_entry *entry)
{
	/* delete fh using entry->tp->ops->delete(...., &last), and if last delete tp */
	/* for now we only have one entry */

	kfree(tcf_e2e_cache->entry);
	tcf_e2e_cache->entry = NULL;

	e2e_cache_destroy_tp(tcf_e2e_cache);
}

static void
e2e_cache_trace_ct_impl(struct flow_offload *flow, int dir)
{
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
	trace->entries[trace->num_entries].flow = flow;
	trace->entries[trace->num_entries].dir = dir;
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
	/* TODO: Check all trace filters tp and fhs */
	if (!tcf_e2e_cache->entry || tcf_e2e_cache->entry->entries[0].tp != tp ||
	    tcf_e2e_cache->entry->entries[0].fh != fh)
		return;

	e2e_cache_entry_delete(tcf_e2e_cache, tcf_e2e_cache->entry);
}

static void
e2e_cache_tp_destroy_impl(struct tcf_e2e_cache *tcf_e2e_cache,
			  const struct tcf_proto *tp)
{
	/* TODO: Check all trace filters tps */
	if (!tcf_e2e_cache->entry || tcf_e2e_cache->entry->entries[0].tp != tp)
		return;

	e2e_cache_entry_delete(tcf_e2e_cache, tcf_e2e_cache->entry);
}

static struct tcf_e2e_cache *
e2e_cache_create_impl(struct tcf_chain *tcf_e2e_chain)
{
	struct tcf_e2e_cache *tcf_e2e_cache;

	tcf_e2e_cache = kzalloc(sizeof(*tcf_e2e_cache), GFP_KERNEL);
	if (!tcf_e2e_cache)
		return ERR_PTR(-ENOMEM);

	__module_get(THIS_MODULE);

	tcf_e2e_cache->tcf_e2e_chain = tcf_e2e_chain;
	pr_debug("chain=0x%p\n", tcf_e2e_chain);

	return tcf_e2e_cache;
}

static void
e2e_cache_destroy_impl(struct tcf_e2e_cache *tcf_e2e_cache)
{
	if (tcf_e2e_cache->entry)
		e2e_cache_entry_delete(tcf_e2e_cache, tcf_e2e_cache->entry);

	module_put(THIS_MODULE);
	kfree(tcf_e2e_cache);
	pr_debug("Cache destroyed\n");
}

static struct e2e_cache_ops e2e_cache_ops = {
	.create		= e2e_cache_create_impl,
	.destroy	= e2e_cache_destroy_impl,
	.trace_begin	= e2e_cache_trace_begin_impl,
	.trace_tp	= e2e_cache_trace_tp_impl,
	.trace_end	= e2e_cache_trace_end_impl,
	.trace_ct	= e2e_cache_trace_ct_impl,
	.tp_destroy	= e2e_cache_tp_destroy_impl,
	.filter_delete	= e2e_cache_filter_delete_impl,
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
