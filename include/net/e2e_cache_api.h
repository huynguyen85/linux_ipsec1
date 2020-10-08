/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NET_E2E_CACHE_API_H
#define __NET_E2E_CACHE_API_H

#include <net/netfilter/nf_flow_table.h>
#include <net/sch_generic.h>

struct tcf_e2e_cache;

struct e2e_cache_ops {
	struct tcf_e2e_cache*	(*create)(struct tcf_chain *tcf_e2e_chain);
	void			(*destroy)(struct tcf_e2e_cache *tcf_e2e_cache);
	void			(*trace_begin)(struct tcf_e2e_cache *tcf_e2e_cache,
					       struct sk_buff *skb);
	void			(*trace_end)(struct sk_buff *skb, int classify_result);
	void			(*trace_tp)(struct sk_buff *skb, const struct tcf_proto *tp,
					    int classify_ret, struct tcf_result *res);
	void			(*trace_ct)(struct flow_offload *flow, int dir);
	void			(*filter_delete)(struct tcf_e2e_cache *tcf_e2e_cache,
						 const struct tcf_proto *tp, void *fh);
	void			(*tp_destroy)(struct tcf_e2e_cache *tcf_e2e_cache,
					      const struct tcf_proto *tp);
};

void e2e_cache_register_ops(struct e2e_cache_ops *e2e_cache_ops);
void e2e_cache_unregister_ops(void);

struct tcf_e2e_cache *e2e_cache_create(struct tcf_chain *tcf_e2e_chain);
void e2e_cache_destroy(struct tcf_e2e_cache *tcf_e2e_cache);

void e2e_cache_trace_begin(struct tcf_e2e_cache *tcf_e2e_cache, struct sk_buff *skb);
void e2e_cache_trace_end(struct sk_buff *skb, int classify_result);

void e2e_cache_trace_tp(struct sk_buff *skb, const struct tcf_proto *tp,
			int classify_ret, struct tcf_result *res);
void e2e_cache_trace_ct(struct flow_offload *flow, int dir);

void e2e_cache_filter_delete(struct tcf_e2e_cache *tcf_e2e_cache, struct tcf_proto *tp, void *fh);
void e2e_cache_tp_destroy(struct tcf_e2e_cache *tcf_e2e_cache, struct tcf_proto *tp);

#endif /* __NET_E2E_CACHE_API_H */
