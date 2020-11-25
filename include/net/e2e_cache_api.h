/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NET_E2E_CACHE_API_H
#define __NET_E2E_CACHE_API_H

#include <net/netfilter/nf_flow_table.h>
#include <net/sch_generic.h>
#include <linux/netlink.h>
#include <linux/refcount.h>

struct e2e_cache_entry;

enum e2e_cache_trace_type {
	E2E_CACHE_TRACE_TP,
	E2E_CACHE_TRACE_CT,
};

struct tcf_e2e_cache {
	refcount_t refcnt;
	struct tcf_block *block;
	struct rhltable tp_rhl;
	struct rhltable tp_fh_rhl;
	struct rhltable ct_rhl;
	struct list_head fts;
	struct list_head list;
	struct rcu_head rcu;
	atomic_t entries;
};

struct e2e_cache_trace_entry {
	enum e2e_cache_trace_type type;

	union {
		struct { /* tp entry */
			struct tcf_proto *tp;
			void *fh;
		};

		struct { /* ct entry */
			struct nf_flowtable *nf_ft;
			struct flow_offload *flow;
			int dir;
			unsigned long cookie;
		};
	};
};

struct e2e_cache_trace_data {
	struct e2e_cache_trace_entry 	*entries;
	int 				num_entries;
	__be16				protocol;
};

struct e2e_cache_ops {
	struct tcf_e2e_cache*	(*create)(struct Qdisc *q,
					  enum flow_block_binder_type bt);
	void			(*detach)(struct tcf_e2e_cache *tcf_e2e_cache,
					  struct Qdisc *q,
					  enum flow_block_binder_type bt);
	void			(*destroy)(struct tcf_e2e_cache *tcf_e2e_cache);
	void			(*trace_begin)(struct tcf_e2e_cache *tcf_e2e_cache,
					       struct sk_buff *skb);
	void			(*trace_end)(struct sk_buff *skb, int classify_result);
	void			(*trace_tp)(struct sk_buff *skb, const struct tcf_proto *tp,
					    int classify_ret, struct tcf_result *res);
	void			(*trace_ct)(struct nf_flowtable *nf_ft, struct flow_offload *flow,
					    int dir);
	void			(*trace_ft_delete)(struct nf_flowtable *nf_ft);
	void			(*filter_delete)(struct tcf_e2e_cache *tcf_e2e_cache,
						 const struct tcf_proto *tp, void *fh);
	void			(*filter_update_stats)(struct tcf_e2e_cache *tcf_e2e_cache,
					               const struct tcf_proto *tp, void *fh);
	void			(*tp_destroy)(struct tcf_e2e_cache *tcf_e2e_cache,
					      const struct tcf_proto *tp);
	int			(*classify)(struct tcf_e2e_cache *tcf_e2e_cache,
					    struct sk_buff *skb,
					    struct tcf_result *res);
	int			(*dump)(struct tcf_e2e_cache *tcf_e2e_cache,
					struct sk_buff *skb,
					struct netlink_callback *cb,
					long index_start, long *index,
					bool terse_dump);
	void			(*indr_cmd)(struct tcf_e2e_cache *tcf_e2e_cache,
					    struct net_device *dev,
					    flow_indr_block_bind_cb_t *cb,
					    void *cb_priv,
					    enum flow_block_command command,
					    enum flow_block_binder_type bt);
};

void e2e_cache_register_ops(struct e2e_cache_ops *e2e_cache_ops);
void e2e_cache_unregister_ops(void);

struct tcf_e2e_cache *
e2e_cache_deref_rcu(struct tcf_e2e_cache __rcu **tcf_e2e_cache);
struct tcf_e2e_cache *
e2e_cache_deref_protected(struct tcf_e2e_cache __rcu **tcf_e2e_cache);
bool e2e_cache_get(struct tcf_e2e_cache *tcf_e2e_cache);
void e2e_cache_put(struct tcf_e2e_cache *tcf_e2e_cache);
struct tcf_e2e_cache *
e2e_cache_deref_get(struct tcf_e2e_cache __rcu **tcf_e2e_cache);

int e2e_cache_create(struct tcf_e2e_cache __rcu **tcf_e2e_cache,
		     struct Qdisc *q,
		     enum flow_block_binder_type binder_type);
void e2e_cache_detach(struct tcf_e2e_cache __rcu **tcf_e2e_cache,
		      struct Qdisc *q,
		      enum flow_block_binder_type binder_type);
void e2e_cache_indr_cmd(struct tcf_e2e_cache *tcf_e2e_cache,
			struct net_device *dev,
			flow_indr_block_bind_cb_t *cb, void *cb_priv,
			enum flow_block_command command,
			enum flow_block_binder_type binder_type);

void e2e_cache_trace_begin(struct tcf_e2e_cache *tcf_e2e_cache, struct sk_buff *skb);
void e2e_cache_trace_end(struct sk_buff *skb, int classify_result);

void e2e_cache_trace_tp(struct sk_buff *skb, const struct tcf_proto *tp,
			int classify_ret, struct tcf_result *res);
void e2e_cache_trace_ct(struct nf_flowtable *nf_ft, struct flow_offload *flow, int dir);
void e2e_cache_trace_ft_delete(struct nf_flowtable *nf_ft);
int e2e_cache_classify(struct tcf_e2e_cache *tcf_e2e_cache,
		       struct sk_buff *skb,
		       struct tcf_result *res);

void e2e_cache_filter_delete(struct tcf_e2e_cache *tcf_e2e_cache, struct tcf_proto *tp, void *fh);
void e2e_cache_filter_update_stats(struct tcf_e2e_cache *tcf_e2e_cache, struct tcf_proto *tp,
				   void *fh);
void e2e_cache_tp_destroy(struct tcf_e2e_cache *tcf_e2e_cache, struct tcf_proto *tp);

int e2e_cache_dump(struct tcf_e2e_cache *tcf_e2e_cache, struct sk_buff *skb,
		   struct netlink_callback *cb, long index_start, long *index,
		   bool terse_dump);

#endif /* __NET_E2E_CACHE_API_H */
