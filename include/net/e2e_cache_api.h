/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NET_E2E_CACHE_API_H
#define __NET_E2E_CACHE_API_H

struct tcf_e2e_cache;

struct e2e_cache_ops {
	struct tcf_e2e_cache*	(*create)(void);
	void			(*destroy)(struct tcf_e2e_cache *e2e_cache);
};

void e2e_cache_register_ops(struct e2e_cache_ops *e2e_cache_ops);
void e2e_cache_unregister_ops(void);

struct tcf_e2e_cache *e2e_cache_create(void);
void e2e_cache_destroy(struct tcf_e2e_cache *tcf_e2e_cache);

#endif /* __NET_E2E_CACHE_API_H */
