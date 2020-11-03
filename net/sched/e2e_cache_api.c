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

struct tcf_e2e_cache *e2e_cache_create(struct Qdisc *q,
				       enum flow_block_binder_type binder_type)
{
	request_module("e2e-cache");

	if (!ops)
		return NULL;

	return ops->create(q, binder_type);
}

void e2e_cache_destroy(struct tcf_e2e_cache *tcf_e2e_cache, struct Qdisc *q,
		       enum flow_block_binder_type binder_type)
{
	if (!ops)
		return;

	return ops->destroy(tcf_e2e_cache, q, binder_type);
}

void e2e_cache_indr_cmd(struct tcf_e2e_cache *tcf_e2e_cache,
			struct net_device *dev,
			flow_indr_block_bind_cb_t *cb, void *cb_priv,
			enum flow_block_command command,
			enum flow_block_binder_type binder_type)
{
	if (!ops)
		return;

	return ops->indr_cmd(tcf_e2e_cache, dev, cb, cb_priv, command,
			     binder_type);
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

int e2e_cache_classify(struct tcf_e2e_cache *tcf_e2e_cache,
		       struct sk_buff *skb,
		       struct tcf_result *res)
{
	if (!ops)
		return -1;

	return ops->classify(tcf_e2e_cache, skb, res);
}
EXPORT_SYMBOL(e2e_cache_classify);

int e2e_cache_dump(struct tcf_e2e_cache *tcf_e2e_cache, struct sk_buff *skb,
		   struct netlink_callback *cb, long index_start, long *index,
		   bool terse_dump)
{
	if (!ops)
		return -1;

	return ops->dump(tcf_e2e_cache, skb, cb, index_start, index,
			 terse_dump);
}
EXPORT_SYMBOL(e2e_cache_dump);
