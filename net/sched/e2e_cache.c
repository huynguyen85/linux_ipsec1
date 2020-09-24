// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include <net/e2e_cache_api.h>

struct tcf_e2e_cache {
	struct tcf_chain *tcf_e2e_chain;
};

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
