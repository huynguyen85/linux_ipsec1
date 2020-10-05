// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/module.h>
#include <net/e2e_cache_api.h>

static struct e2e_cache_ops *ops;

void e2e_cache_register_ops(struct e2e_cache_ops *e2e_cache_ops)
{
	ops = e2e_cache_ops;
}
EXPORT_SYMBOL(e2e_cache_register_ops);

void e2e_cache_unregister_ops(void)
{
	ops = NULL;
}
EXPORT_SYMBOL(e2e_cache_unregister_ops);

struct tcf_e2e_cache *e2e_cache_create(struct tcf_chain *tcf_e2e_chain)
{
	request_module("e2e-cache");

	if (!ops)
		return NULL;

	return ops->create(tcf_e2e_chain);
}

void e2e_cache_destroy(struct tcf_e2e_cache *tcf_e2e_cache)
{
	if (!ops)
		return;

	return ops->destroy(tcf_e2e_cache);
}

void e2e_cache_trace_begin(struct tcf_e2e_cache *tcf_e2e_cache, struct sk_buff *skb)
{
	if (!ops)
		return;

	return ops->trace_begin(tcf_e2e_cache, skb);
}

void e2e_cache_trace_end(struct sk_buff *skb, int classify_result)
{
	if (!ops)
		return;

	return ops->trace_end(skb, classify_result);
}

void e2e_cache_trace_tp(struct sk_buff *skb, const struct tcf_proto *tp,
			int classify_ret, struct tcf_result *res)
{
	if (!ops)
		return;

	return ops->trace_tp(skb, tp, classify_ret, res);
}

void e2e_cache_filter_delete(struct tcf_e2e_cache *tcf_e2e_cache, struct tcf_proto *tp, void *fh)
{
	if (!ops)
		return;

	return ops->filter_delete(tcf_e2e_cache, tp, fh);
}

void e2e_cache_filter_update_stats(struct tcf_e2e_cache *tcf_e2e_cache, struct tcf_proto *tp,
				   void *fh)
{
	if (!ops)
		return;

	return ops->filter_update_stats(tcf_e2e_cache, tp, fh);
}

void e2e_cache_tp_destroy(struct tcf_e2e_cache *tcf_e2e_cache, struct tcf_proto *tp)
{
	if (!ops)
		return;

	return ops->tp_destroy(tcf_e2e_cache, tp);
}

void e2e_cache_trace_ct(struct flow_offload *flow, int dir)
{
	if (!ops)
		return;

	return ops->trace_ct(flow, dir);
}
EXPORT_SYMBOL(e2e_cache_trace_ct);
