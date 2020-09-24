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

struct tcf_e2e_cache *e2e_cache_create()
{
	request_module("e2e-cache");

	if (!ops)
		return NULL;

	return ops->create();
}

void e2e_cache_destroy(struct tcf_e2e_cache *tcf_e2e_cache)
{
	if (!ops)
		return;

	return ops->destroy(tcf_e2e_cache);
}
