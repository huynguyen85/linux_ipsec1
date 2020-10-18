// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/percpu.h>

#include <net/e2e_cache_api.h>
#include <net/pkt_cls.h>

#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack.h>

struct tcf_e2e_cache {
	struct tcf_chain *tcf_e2e_chain;
};

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
			const struct tcf_proto *tp;
			void *fh;
		};

		struct { /* ct entry */
			struct flow_offload *flow;
			int dir;
		};
	};
};

struct e2e_cache_trace {
	u32 flags;
	const struct tcf_proto_ops *ops;

	struct e2e_cache_trace_entry entries[E2E_CACHE_MAX_TRACE_ENTRIES];
	int num_entries;

	int num_tps;
	int num_conns;
};
static DEFINE_PER_CPU(struct e2e_cache_trace, packet_trace);

static void
e2e_cache_trace_begin_impl(struct sk_buff *skb)
{
	struct e2e_cache_trace *trace = this_cpu_ptr(&packet_trace);

	pr_debug("trace=0x%p\n", trace);
	memset(trace, 0, sizeof(*trace));

	trace->flags = E2E_CACHE_TRACE_CACHEABLE;
}

static void
e2e_cache_trace_tp_impl(struct sk_buff *skb,
			const struct tcf_proto *tp,
			int classify_ret,
			struct tcf_result *res)
{
	struct e2e_cache_trace *trace = this_cpu_ptr(&packet_trace);
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	pr_debug("trace=0x%p\n", trace);
	if (!(trace->flags & E2E_CACHE_TRACE_CACHEABLE))
		return;

	if (trace->num_entries >= E2E_CACHE_MAX_TRACE_ENTRIES)
		goto not_cacheable;

	/* only filters with goto chain actions may be cached */
	if (!TC_ACT_EXT_CMP(classify_ret, TC_ACT_GOTO_CHAIN) &&
	    classify_ret != TC_ACT_CONSUMED)
		goto not_cacheable;

	/* trace only classifiers of the same kind */
	if (!trace->ops) {
		trace->ops = tp->ops;
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

	trace->entries[trace->num_entries].type = E2E_CACHE_TRACE_TP;
	trace->entries[trace->num_entries].tp = (struct tcf_proto *)tp;
	trace->entries[trace->num_entries].fh = res->fh;
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
	struct e2e_cache_trace *trace = this_cpu_ptr(&packet_trace);

	pr_debug("trace=0x%p flags=%d\n", trace, trace->flags);

	if (!(trace->flags & E2E_CACHE_TRACE_CACHEABLE))
		return;

	if (classify_result != TC_ACT_CONSUMED || trace->num_tps < 2)
		return;

	pr_debug("trace=0x%p processing trace of %d chains %d connections\n"
		 , trace
		 , trace->num_tps
		 , trace->num_conns);
}

static void
e2e_cache_trace_ct_impl(struct flow_offload *flow, int dir)
{
	struct e2e_cache_trace *trace = this_cpu_ptr(&packet_trace);

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
};

static int
__init e2e_cache_init(void)
{
	e2e_cache_register_ops(&e2e_cache_ops);
	return 0;
}

static void
__exit e2e_cache_exit(void)
{
	e2e_cache_unregister_ops();
}

module_init(e2e_cache_init);
module_exit(e2e_cache_exit);

MODULE_AUTHOR("Oz Shlomo <ozsh@nvidia.com>");
MODULE_AUTHOR("Paul Blakey <paulb@nvidia.com>");
MODULE_AUTHOR("Vlad Buslov <vladbu@nvidia.com>");
MODULE_AUTHOR("Roi Dayan <roid@nvidia.com>");
MODULE_DESCRIPTION("E2E cache");
MODULE_LICENSE("GPL");
