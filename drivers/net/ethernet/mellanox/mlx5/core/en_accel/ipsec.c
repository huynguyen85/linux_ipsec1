/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <crypto/internal/geniv.h>
#include <crypto/aead.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/module.h>

#include "en.h"
#include "en_accel/ipsec.h"
#include "en_accel/ipsec_rxtx.h"
#include "en_accel/ipsec_steering.h"
#include "en/aso.h"

#define DEBUG_FL(format,...) printk("%s:%d - "format"\n",__func__,__LINE__,##__VA_ARGS__)

#define NO_TRAFFIC_RETRY 5
#define RETRY_SECOND (10 * HZ)

struct mlx5e_ipsec_async_work {
	struct delayed_work dwork;
	struct mlx5e_priv *priv;         
	u32 obj_id;
	u8 retry;
};

static void _mlx5e_ipsec_async_event(struct work_struct *work);

static struct mlx5e_ipsec_sa_entry *to_ipsec_sa_entry(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa;

	if (!x)
		return NULL;

	sa = (struct mlx5e_ipsec_sa_entry *)x->xso.offload_handle;
	if (!sa)
		return NULL;

	WARN_ON(sa->x != x);
	return sa;
}

struct xfrm_state *mlx5e_ipsec_sadb_rx_lookup(struct mlx5e_ipsec *ipsec,
					      unsigned int handle)
{
	struct mlx5e_ipsec_sa_entry *sa_entry;
	struct xfrm_state *ret = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->sadb_rx, sa_entry, hlist, handle)
		if (sa_entry->handle == handle) {
			ret = sa_entry->x;
			xfrm_state_hold(ret);
			break;
		}
	rcu_read_unlock();

	return ret;
}

static int  mlx5e_ipsec_sadb_rx_add(struct mlx5e_ipsec_sa_entry *sa_entry,
				    unsigned int handle)
{
	struct mlx5e_ipsec *ipsec = sa_entry->ipsec;
	struct mlx5e_ipsec_sa_entry *_sa_entry;
	unsigned long flags;

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->sadb_rx, _sa_entry, hlist, handle)
		if (_sa_entry->handle == handle) {
			rcu_read_unlock();
			return  -EEXIST;
		}
	rcu_read_unlock();

	spin_lock_irqsave(&ipsec->sadb_rx_lock, flags);
	sa_entry->handle = handle;
	hash_add_rcu(ipsec->sadb_rx, &sa_entry->hlist, sa_entry->handle);
	spin_unlock_irqrestore(&ipsec->sadb_rx_lock, flags);

	return 0;
}

static void mlx5e_ipsec_sadb_rx_del(struct mlx5e_ipsec_sa_entry *sa_entry)
{
	struct mlx5e_ipsec *ipsec = sa_entry->ipsec;
	unsigned long flags;

	spin_lock_irqsave(&ipsec->sadb_rx_lock, flags);
	hash_del_rcu(&sa_entry->hlist);
	spin_unlock_irqrestore(&ipsec->sadb_rx_lock, flags);
}

struct xfrm_state *mlx5e_ipsec_sadb_tx_lookup(struct mlx5e_ipsec *ipsec,
					      unsigned int handle)
{
	struct mlx5e_ipsec_sa_entry *sa_entry;
	struct xfrm_state *ret = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->sadb_tx, sa_entry, hlist, handle)
		if (sa_entry->handle == handle) {
			ret = sa_entry->x;
			xfrm_state_hold(ret);
			break;
		}
	rcu_read_unlock();

	return ret;
}

static int  mlx5e_ipsec_sadb_tx_add(struct mlx5e_ipsec_sa_entry *sa_entry,
				    unsigned int handle)
{
	struct mlx5e_ipsec *ipsec = sa_entry->ipsec;
	struct mlx5e_ipsec_sa_entry *_sa_entry;
	unsigned long flags;

	rcu_read_lock();
	hash_for_each_possible_rcu(ipsec->sadb_tx, _sa_entry, hlist, handle)
		if (_sa_entry->handle == handle) {
			rcu_read_unlock();
			return  -EEXIST;
		}
	rcu_read_unlock();

	spin_lock_irqsave(&ipsec->sadb_tx_lock, flags);
	sa_entry->handle = handle;
	hash_add_rcu(ipsec->sadb_tx, &sa_entry->hlist, sa_entry->handle);
	spin_unlock_irqrestore(&ipsec->sadb_tx_lock, flags);

	return 0;
}

static void mlx5e_ipsec_sadb_tx_del(struct mlx5e_ipsec_sa_entry *sa_entry)
{
	struct mlx5e_ipsec *ipsec = sa_entry->ipsec;
	unsigned long flags;

	spin_lock_irqsave(&ipsec->sadb_tx_lock, flags);
	hash_del_rcu(&sa_entry->hlist);
	spin_unlock_irqrestore(&ipsec->sadb_tx_lock, flags);
}

static bool mlx5e_ipsec_update_esn_state(struct mlx5e_ipsec_sa_entry *sa_entry)
{
	struct xfrm_replay_state_esn *replay_esn;
	u32 seq_bottom;
	u8 overlap;
	u32 *esn;

	if (!(sa_entry->x->props.flags & XFRM_STATE_ESN)) {
		sa_entry->esn_state.trigger = 0;
		return false;
	}

	replay_esn = sa_entry->x->replay_esn;
	seq_bottom = replay_esn->seq - replay_esn->replay_window + 1;
	overlap = sa_entry->esn_state.overlap;

	sa_entry->esn_state.esn = xfrm_replay_seqhi(sa_entry->x,
						    htonl(seq_bottom));
	esn = &sa_entry->esn_state.esn;

	sa_entry->esn_state.trigger = 1;
	if (unlikely(overlap && seq_bottom < MLX5E_IPSEC_ESN_SCOPE_MID)) {
		++(*esn);
		sa_entry->esn_state.overlap = 0;
		return true;
	} else if (unlikely(!overlap &&
			    (seq_bottom >= MLX5E_IPSEC_ESN_SCOPE_MID))) {
		sa_entry->esn_state.overlap = 1;
		return true;
	}

	return false;
}

static void
initialize_lifetime_limit(struct mlx5e_ipsec_sa_entry *sa_entry,
			  struct mlx5_accel_esp_xfrm_attrs *attrs)
{
	u64 soft_limit, hard_limit, hard_limit_modulo;
	struct xfrm_state *x = sa_entry->x;
	struct net_device *netdev;
	struct mlx5e_priv *priv;

	netdev = x->xso.dev;
	priv = netdev_priv(netdev);

	if (MLX5_CAP_GEN(priv->mdev, fpga))
		return;

	printk("initialize_lifetime_limit 001\n");
	printk("x->lft.soft_packet_limit=%d\n", x->lft.soft_packet_limit);
	printk("x->lft.hard_packet_limit=%d\n", x->lft.hard_packet_limit);

	hard_limit = x->lft.hard_packet_limit;
	soft_limit = (x->lft.soft_packet_limit == IPSEC_NO_LIMIT) ? 0 : x->lft.soft_packet_limit;
	if (!(x->xso.flags & XFRM_OFFLOAD_FULL) ||
	    (hard_limit <= soft_limit) ||
	    (hard_limit == IPSEC_NO_LIMIT)) {
		attrs->soft_packet_limit = IPSEC_NO_LIMIT;
		attrs->hard_packet_limit = IPSEC_NO_LIMIT;
		return;
	}

	/* Save soft and hard limit for async event */
	sa_entry->lft.real_soft_pkt_limit = soft_limit;
	sa_entry->lft.real_hard_pkt_limit = hard_limit;

	if (hard_limit >= IPSEC_HW_LIMIT) {

		hard_limit_modulo = hard_limit & (IPSEC_SW_LIMIT - 1);

		if (soft_limit >= IPSEC_HW_LIMIT) {
			hard_limit = IPSEC_SW_LIMIT + hard_limit_modulo;
			soft_limit = IPSEC_SW_LIMIT;
		} else {
			hard_limit = IPSEC_SW_LIMIT + hard_limit_modulo;
		}

		if (hard_limit == soft_limit)
			hard_limit ++;
	}
	
	attrs->hard_packet_limit = hard_limit;
	attrs->soft_packet_limit = soft_limit;
	sa_entry->lft.last_cnt = hard_limit;

	printk("attrs->hard_packet_limit =%d\n", attrs->hard_packet_limit);
	printk("attrs->soft_packet_limit =%d\n", attrs->soft_packet_limit);
	printk("sa_entry->lft.real_soft_pkt_limit =%d\n", sa_entry->lft.real_soft_pkt_limit);
	printk("sa_entry->lft.real_hard_pkt_limit =%d\n", sa_entry->lft.real_hard_pkt_limit);
	printk("sa_entry->lft.last_cnt =%d\n", sa_entry->lft.last_cnt);
	printk("initialize_lifetime_limit 009\n");
}				

static void
mlx5e_ipsec_build_accel_xfrm_attrs(struct mlx5e_ipsec_sa_entry *sa_entry,
				   struct mlx5_accel_esp_xfrm_attrs *attrs)
{
	struct xfrm_state *x = sa_entry->x;
	struct aes_gcm_keymat *aes_gcm = &attrs->keymat.aes_gcm;
	struct aead_geniv_ctx *geniv_ctx;
	struct crypto_aead *aead;
	unsigned int crypto_data_len, key_len;
	int ivsize;

	memset(attrs, 0, sizeof(*attrs));

	/* key */
	crypto_data_len = (x->aead->alg_key_len + 7) / 8;
	key_len = crypto_data_len - 4; /* 4 bytes salt at end */

	memcpy(aes_gcm->aes_key, x->aead->alg_key, key_len);
	aes_gcm->key_len = key_len * 8;

	/* salt and seq_iv */
	aead = x->data;
	geniv_ctx = crypto_aead_ctx(aead);
	ivsize = crypto_aead_ivsize(aead);
	memcpy(&aes_gcm->seq_iv, &geniv_ctx->salt, ivsize);
	memcpy(&aes_gcm->salt, x->aead->alg_key + key_len,
	       sizeof(aes_gcm->salt));

	/* iv len */
	aes_gcm->icv_len = x->aead->alg_icv_len;

	/* esn */
	if (sa_entry->esn_state.trigger) {
		attrs->flags |= MLX5_ACCEL_ESP_FLAGS_ESN_TRIGGERED;
		attrs->esn = sa_entry->esn_state.esn;
		if (sa_entry->esn_state.overlap)
			attrs->flags |= MLX5_ACCEL_ESP_FLAGS_ESN_STATE_OVERLAP;
	}

	/* rx handle */
	attrs->sa_handle = sa_entry->handle;

	/* algo type */
	attrs->keymat_type = MLX5_ACCEL_ESP_KEYMAT_AES_GCM;

	/* action */
	attrs->action = (!(x->xso.flags & XFRM_OFFLOAD_INBOUND)) ?
			MLX5_ACCEL_ESP_ACTION_ENCRYPT :
			MLX5_ACCEL_ESP_ACTION_DECRYPT;
	/* flags */
	attrs->flags |= (x->props.mode == XFRM_MODE_TRANSPORT) ?
			MLX5_ACCEL_ESP_FLAGS_TRANSPORT :
			MLX5_ACCEL_ESP_FLAGS_TUNNEL;

	/* full offload */
	//attrs->flags |= (x->xso.flags & XFRM_OFFLOAD_FULL) ? MLX5_ACCEL_ESP_FLAGS_FULL_OFFLOAD : 0;
	attrs->flags |= MLX5_ACCEL_ESP_FLAGS_FULL_OFFLOAD;

	/* spi */
	attrs->spi = x->id.spi;

	/* source , destination ips */
	memcpy(&attrs->saddr, x->props.saddr.a6, sizeof(attrs->saddr));
	memcpy(&attrs->daddr, x->id.daddr.a6, sizeof(attrs->daddr));
	attrs->is_ipv6 = (x->props.family != AF_INET);

	/* netdev priv */
	attrs->priv = netdev_priv(x->xso.dev);

	/* lifetime limit for full offload */
	initialize_lifetime_limit(sa_entry, attrs);
}

static inline int mlx5e_xfrm_validate_state(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct mlx5e_priv *priv;

	priv = netdev_priv(netdev);

	if (x->props.aalgo != SADB_AALG_NONE) {
		netdev_info(netdev, "Cannot offload authenticated xfrm states\n");
		return -EINVAL;
	}
	if (x->props.ealgo != SADB_X_EALG_AES_GCM_ICV16) {
		netdev_info(netdev, "Only AES-GCM-ICV16 xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.calgo != SADB_X_CALG_NONE) {
		netdev_info(netdev, "Cannot offload compressed xfrm states\n");
		return -EINVAL;
	}
	if (x->props.flags & XFRM_STATE_ESN &&
	    !(mlx5_accel_ipsec_device_caps(priv->mdev) &
	    MLX5_ACCEL_IPSEC_CAP_ESN)) {
		netdev_info(netdev, "Cannot offload ESN xfrm states\n");
		return -EINVAL;
	}
	if (x->props.family != AF_INET &&
	    x->props.family != AF_INET6) {
		netdev_info(netdev, "Only IPv4/6 xfrm states may be offloaded\n");
		return -EINVAL;
	}
	if (x->props.mode != XFRM_MODE_TRANSPORT &&
	    x->props.mode != XFRM_MODE_TUNNEL) {
		dev_info(&netdev->dev, "Only transport and tunnel xfrm states may be offloaded\n");
		return -EINVAL;
	}
	if (x->id.proto != IPPROTO_ESP) {
		netdev_info(netdev, "Only ESP xfrm state may be offloaded\n");
		return -EINVAL;
	}
	if (x->encap) {
		netdev_info(netdev, "Encapsulated xfrm state may not be offloaded\n");
		return -EINVAL;
	}
	if (!x->aead) {
		netdev_info(netdev, "Cannot offload xfrm states without aead\n");
		return -EINVAL;
	}
	if (x->aead->alg_icv_len != 128) {
		netdev_info(netdev, "Cannot offload xfrm states with AEAD ICV length other than 128bit\n");
		return -EINVAL;
	}
	if ((x->aead->alg_key_len != 128 + 32) &&
	    (x->aead->alg_key_len != 256 + 32)) {
		netdev_info(netdev, "Cannot offload xfrm states with AEAD key length other than 128/256 bit\n");
		return -EINVAL;
	}
	if (x->tfcpad) {
		netdev_info(netdev, "Cannot offload xfrm states with tfc padding\n");
		return -EINVAL;
	}
	if (!x->geniv) {
		netdev_info(netdev, "Cannot offload xfrm states without geniv\n");
		return -EINVAL;
	}
	if (strcmp(x->geniv, "seqiv")) {
		netdev_info(netdev, "Cannot offload xfrm states with geniv other than seqiv\n");
		return -EINVAL;
	}
	if (x->props.family == AF_INET6 &&
	    !(mlx5_accel_ipsec_device_caps(priv->mdev) &
	     MLX5_ACCEL_IPSEC_CAP_IPV6)) {
		netdev_info(netdev, "IPv6 xfrm state offload is not supported by this device\n");
		return -EINVAL;
	}


	if ((x->xso.flags & XFRM_OFFLOAD_FULL) &&
	    ((x->lft.hard_byte_limit != XFRM_INF) ||
	     (x->lft.soft_byte_limit != XFRM_INF) ||
	     x->lft.hard_add_expires_seconds ||
	     x->lft.soft_add_expires_seconds ||
	     x->lft.hard_use_expires_seconds ||
	     x->lft.soft_use_expires_seconds)) {
		netdev_info(netdev, "full offload state does not support:\n\
					x->lft.hard_add_expires_seconds=%llu,\n\
					x->lft.soft_add_expires_seconds=%llu,\n\
					x->lft.hard_use_expires_seconds=%llu,\n\
					x->lft.soft_use_expires_seconds=%llu,\n\
					x->lft.hard_byte_limit=0x%llx,\n\
					x->lft.soft_byte_limit=0x%llx,\n",
					x->lft.hard_add_expires_seconds,
					x->lft.soft_add_expires_seconds,
					x->lft.hard_use_expires_seconds,
					x->lft.soft_use_expires_seconds,
					x->lft.hard_byte_limit,
					x->lft.soft_byte_limit);
		return -EINVAL;
	}

	return 0;
}

static int mlx5e_xfrm_add_state(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa_entry = NULL;
	struct net_device *netdev = x->xso.dev;
	struct mlx5_accel_esp_xfrm_attrs attrs;
	struct mlx5e_priv *priv;
	unsigned int sa_handle;
	int err;

	DEBUG_FL("Enter\n");
	priv = netdev_priv(netdev);

	err = mlx5e_xfrm_validate_state(x);
	if (err)
		return err;

	sa_entry = kzalloc(sizeof(*sa_entry), GFP_KERNEL);
	if (!sa_entry) {
		err = -ENOMEM;
		goto out;
	}

	sa_entry->x = x;
	sa_entry->ipsec = priv->ipsec;

	/* check esn */
	mlx5e_ipsec_update_esn_state(sa_entry);

	/* create xfrm */
	mlx5e_ipsec_build_accel_xfrm_attrs(sa_entry, &attrs);
	sa_entry->xfrm =
		mlx5_accel_esp_create_xfrm(priv->mdev, &attrs,
					   MLX5_ACCEL_XFRM_FLAG_REQUIRE_METADATA);
	if (IS_ERR(sa_entry->xfrm)) {
		err = PTR_ERR(sa_entry->xfrm);
		goto err_sa_entry;
	}

	/* create hw context */
	sa_entry->hw_context =
			mlx5_accel_esp_create_hw_context(priv->mdev,
							 sa_entry->xfrm,
							 &sa_handle);
	if (IS_ERR(sa_entry->hw_context)) {
		err = PTR_ERR(sa_entry->hw_context);
		goto err_xfrm;
	}

	mlx5e_aso_send_ipsec_aso(priv, sa_handle, NULL, NULL, NULL);

	err = mlx5e_xfrm_add_rule(priv, sa_entry);
	if (err)
		goto err_hw_ctx;

	/* Add the SA to handle processed incoming packets before the add SA
	 * completion was received
	 * this is oki because the stack
	 * xfrm_add_sa -> xfrm_state_construct -> xfrm_dev_state_add (net/xfrm/xfrm_device.c)
	 *            |->x->km.state = XFRM_STATE_VALID (only post device success this will make all packetd to be dropped on Tx/Rx
	 *            | this is true for all new sa's (see xfrm_input for dropping packet))
	 */
	if (x->xso.flags & XFRM_OFFLOAD_INBOUND) {
		err = mlx5e_ipsec_sadb_rx_add(sa_entry, sa_handle);
		if (err)
			goto err_add_rule;
	} else {
		err = mlx5e_ipsec_sadb_tx_add(sa_entry, sa_handle);
		if (err)
			goto err_add_rule;
		sa_entry->set_iv_op = (x->props.flags & XFRM_STATE_ESN) ?
				mlx5e_ipsec_set_iv_esn : mlx5e_ipsec_set_iv;
	}

	x->xso.offload_handle = (unsigned long)sa_entry;
	DEBUG_FL("Out Success priv->ipsec=%p\n", priv->ipsec);

	goto out;

err_add_rule:
	mlx5e_xfrm_del_rule(priv, sa_entry);
err_hw_ctx:
	mlx5_accel_esp_free_hw_context(sa_entry->xfrm, sa_entry->hw_context);
err_xfrm:
	mlx5_accel_esp_destroy_xfrm(sa_entry->xfrm);
err_sa_entry:
	kfree(sa_entry);

out:
	return err;
}

static void mlx5e_xfrm_del_state(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa_entry = to_ipsec_sa_entry(x);

	if (!sa_entry)
		return;

	if (x->xso.flags & XFRM_OFFLOAD_INBOUND)
		mlx5e_ipsec_sadb_rx_del(sa_entry);
	else
		mlx5e_ipsec_sadb_tx_del(sa_entry);
}

static void mlx5e_xfrm_free_state(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa_entry = to_ipsec_sa_entry(x);
	struct mlx5e_priv *priv = netdev_priv(x->xso.dev);

	if (!sa_entry)
		return;

	if (sa_entry->hw_context) {
		flush_workqueue(sa_entry->ipsec->wq);
		mlx5e_xfrm_del_rule(priv, sa_entry);
		mlx5_accel_esp_free_hw_context(sa_entry->xfrm, sa_entry->hw_context);
		mlx5_accel_esp_destroy_xfrm(sa_entry->xfrm);
	}

	kfree(sa_entry);
}

int mlx5e_ipsec_init(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec *ipsec = NULL;
	int err;

	if (!MLX5_IPSEC_DEV(priv->mdev)) {
		netdev_dbg(priv->netdev, "Not an IPSec offload device\n");
		return 0;
	}

	ipsec = kzalloc(sizeof(*ipsec), GFP_KERNEL);
	if (!ipsec)
		return -ENOMEM;

	hash_init(ipsec->sadb_rx);
	spin_lock_init(&ipsec->sadb_rx_lock);
	hash_init(ipsec->sadb_tx);
	spin_lock_init(&ipsec->sadb_tx_lock);
	ida_init(&ipsec->halloc);
	ipsec->en_priv = priv;
	ipsec->en_priv->ipsec = ipsec;
	ipsec->no_trailer = !!(mlx5_accel_ipsec_device_caps(priv->mdev) &
			       MLX5_ACCEL_IPSEC_CAP_RX_NO_TRAILER);

	err = mlx5e_aso_reg_mr(priv);
	if (err)
		goto out;

	ipsec->wq = alloc_ordered_workqueue("mlx5e_ipsec: %s", 0,
					    priv->netdev->name);
	if (!ipsec->wq) {
		err = -ENOMEM;
		goto out_mr;
	}

	DEBUG_FL("IPSec attached to netdevice\n");
	return 0;

out_mr:
	mlx5e_aso_dereg_mr(priv);

out:
	kfree(ipsec);
	return err;
}

void mlx5e_ipsec_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec *ipsec = priv->ipsec;

	if (!ipsec)
		return;

	destroy_workqueue(ipsec->wq);
	mlx5e_aso_dereg_mr(priv);

	ida_destroy(&ipsec->halloc);
	kfree(ipsec);
	priv->ipsec = NULL;
}

static bool mlx5e_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x)
{
	if (x->props.family == AF_INET) {
		/* Offload with IPv4 options is not supported yet */
		if (ip_hdr(skb)->ihl > 5)
			return false;
	} else {
		/* Offload with IPv6 extension headers is not support yet */
		if (ipv6_ext_hdr(ipv6_hdr(skb)->nexthdr))
			return false;
	}

	return true;
}

struct mlx5e_ipsec_modify_state_work {
	struct work_struct		work;
	struct mlx5_accel_esp_xfrm_attrs attrs;
	struct mlx5e_ipsec_sa_entry	*sa_entry;
};

static void _update_xfrm_state(struct work_struct *work)
{
	int ret;
	struct mlx5e_ipsec_modify_state_work *modify_work =
		container_of(work, struct mlx5e_ipsec_modify_state_work, work);
	struct mlx5e_ipsec_sa_entry *sa_entry = modify_work->sa_entry;

	ret = mlx5_accel_esp_modify_xfrm(sa_entry->xfrm,
					 &modify_work->attrs);
	if (ret)
		netdev_warn(sa_entry->ipsec->en_priv->netdev,
			    "Not an IPSec offload device\n");

	kfree(modify_work);
}

static void mlx5e_xfrm_advance_esn_state(struct xfrm_state *x)
{
	struct mlx5e_ipsec_sa_entry *sa_entry = to_ipsec_sa_entry(x);
	struct mlx5e_ipsec_modify_state_work *modify_work;
	bool need_update;

	if (!sa_entry)
		return;

	need_update = mlx5e_ipsec_update_esn_state(sa_entry);
	if (!need_update)
		return;

	modify_work = kzalloc(sizeof(*modify_work), GFP_ATOMIC);
	if (!modify_work)
		return;

	mlx5e_ipsec_build_accel_xfrm_attrs(sa_entry, &modify_work->attrs);
	modify_work->sa_entry = sa_entry;

	INIT_WORK(&modify_work->work, _update_xfrm_state);
	WARN_ON(!queue_work(sa_entry->ipsec->wq, &modify_work->work));
}

static const struct xfrmdev_ops mlx5e_ipsec_xfrmdev_ops = {
	.xdo_dev_state_add	= mlx5e_xfrm_add_state,
	.xdo_dev_state_delete	= mlx5e_xfrm_del_state,
	.xdo_dev_state_free	= mlx5e_xfrm_free_state,
	.xdo_dev_offload_ok	= mlx5e_ipsec_offload_ok,
	.xdo_dev_state_advance_esn = mlx5e_xfrm_advance_esn_state,
};

void mlx5e_ipsec_build_netdev(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct net_device *netdev = priv->netdev;

	DEBUG_FL("Enter");
	if (!priv->ipsec)
		return;

	if (!(mlx5_accel_ipsec_device_caps(mdev) & MLX5_ACCEL_IPSEC_CAP_ESP) ||
	    !MLX5_CAP_ETH(mdev, swp)) {
		mlx5_core_info(mdev, "mlx5e: ESP and SWP offload not supported\n");
		return;
	}

	DEBUG_FL("Init ops");
	mlx5_core_info(mdev, "mlx5e: IPSec ESP acceleration enabled for device %s\n", netdev_name(netdev));
	netdev->xfrmdev_ops = &mlx5e_ipsec_xfrmdev_ops;
	netdev->features |= NETIF_F_HW_ESP;
	netdev->hw_enc_features |= NETIF_F_HW_ESP;

	if (!MLX5_CAP_ETH(mdev, swp_csum)) {
		mlx5_core_dbg(mdev, "mlx5e: SWP checksum not supported\n");
		return;
	}

	netdev->features |= NETIF_F_HW_ESP_TX_CSUM;
	netdev->hw_enc_features |= NETIF_F_HW_ESP_TX_CSUM;

	if (!(mlx5_accel_ipsec_device_caps(mdev) & MLX5_ACCEL_IPSEC_CAP_LSO) ||
	    !MLX5_CAP_ETH(mdev, swp_lso)) {
		mlx5_core_dbg(mdev, "mlx5e: ESP LSO not supported\n");
		return;
	}

	if (mlx5_is_ipsec_device(mdev))
		netdev->gso_partial_features |= NETIF_F_GSO_ESP;

	mlx5_core_dbg(mdev, "mlx5e: ESP GSO capability turned on\n");
	netdev->features |= NETIF_F_GSO_ESP;
	netdev->hw_features |= NETIF_F_GSO_ESP;
	netdev->hw_enc_features |= NETIF_F_GSO_ESP;
}

enum {
	ARM_SOFT = BIT(0),
	SET_SOFT = BIT(1),
	SET_CNT_BIT31  = BIT(3),
};

#define UPPER32_MASK 0xFFFFFFFF00000000

static void ipsec_aso_set(struct mlx5e_priv *priv, u32 obj_id, u8 flags,
			  u32 comparator, u32 *hard_cnt, u32 *soft_cnt)
{
	struct mlx5e_aso_ctrl_param param = {};

	if (!flags) {
		mlx5e_aso_send_ipsec_aso(priv, obj_id, NULL, hard_cnt, soft_cnt);
		return;
	}

	param.data_mask_mode = ASO_DATA_MASK_MODE_BITWISE_64BIT;
	param.condition_0_operand = ALWAYS_TRUE;
	param.condition_1_operand = ALWAYS_TRUE;

	if (flags & SET_SOFT) {
		param.data_offset = MLX5_IPSEC_ASO_REMOVE_FLOW_SOFT_LFT_OFFSET;
		param.bitwise_data = (u64)(comparator) << 32;
		param.data_mask = UPPER32_MASK;
		mlx5e_aso_send_ipsec_aso(priv, obj_id, &param, hard_cnt, soft_cnt);
		if (flags == SET_SOFT)
			return;
	}

	/* For ASO_WQE big Endian format,
	 * ARM_SOFT is BIT(25 + 32)
	 * SET COUNTER BIT 31 is BIT(31)
	 */
	param.data_offset = MLX5_IPSEC_ASO_REMOVE_FLOW_PKT_CNT_OFFSET;
	param.bitwise_data = IPSEC_SW_LIMIT | ((BIT(24) | BIT(25)) << 32);
	param.data_mask = param.bitwise_data;
	mlx5e_aso_send_ipsec_aso(priv, obj_id, &param, hard_cnt, soft_cnt);
}

static void _mlx5e_ipsec_async_event(struct work_struct *work)
{
	struct mlx5e_ipsec_async_work *async_work;
	struct mlx5e_ipsec_sa_entry *sa_entry;
	struct mlx5e_ipsec_state_lft *lft;
	struct delayed_work *dwork;
	struct mlx5e_priv *priv;
	u32 hard_cnt, soft_cnt;
	struct xfrm_state *xs;
	u32 obj_id;

	dwork = to_delayed_work(work);
	async_work = container_of(dwork, struct mlx5e_ipsec_async_work, dwork);
	priv = async_work->priv;
	obj_id = async_work->obj_id;

	xs = mlx5e_ipsec_sadb_tx_lookup(priv->ipsec, obj_id);
	if (!xs)
		goto out_async_work;

	sa_entry = to_ipsec_sa_entry(xs);
	if (!sa_entry)
		goto out_xs;

	lft = &sa_entry->lft;

	//ipsec_aso_set(priv, obj_id, 0, 0);
	mlx5_core_err(priv->mdev, "_mlx5e_ipsec_async_event 001 priv->ipsec=%p, obj_id=0x%x, async_work->retry=%d\n", priv->ipsec, obj_id, async_work->retry);
	mlx5_core_err(priv->mdev, "_mlx5e_ipsec_async_event obj_id=0x%d, xs=%p, real_soft=%d, real_hard=%d, lft->last_cnt=%d\n", obj_id, xs, lft->real_soft_pkt_limit, lft->real_hard_pkt_limit, lft->last_cnt);

/*
	if (async_work->retry) {
		ipsec_aso_set(priv, obj_id, 0, 0, &hard_cnt, &soft_cnt);
		printk(KERN_ERR, "retry=%d, hard_cnt=%d, soft_cnt=%d\n", async_work->retry, hard_cnt, soft_cnt);
		if (hard_cnt == soft_cnt) {
			struct mlx5e_ipsec_async_work *retry_work;
			if (async_work->retry > 1) {
				retry_work = kzalloc(sizeof(*retry_work), GFP_ATOMIC);
				if (!retry_work)
					xfrm_state_expire(xs, 1);
				retry_work->priv = priv;
				retry_work->obj_id = obj_id;
				retry_work->retry = async_work->retry - 1;
				INIT_DELAYED_WORK(&retry_work->dwork, _mlx5e_ipsec_async_event);
				WARN_ON(!queue_delayed_work(priv->ipsec->wq, &retry_work->dwork, HZ));
			}
		} else {
			printk(KERN_ERR, "retry arm_soft, set_bit32\n");
			ipsec_aso_set(priv, obj_id,
				      ARM_SOFT | SET_CNT_BIT31,
				      0, &hard_cnt, &soft_cnt);
		
			lft->real_hard_pkt_limit -= (lft->last_cnt - hard_cnt);
			if (lft->real_soft_pkt_limit > IPSEC_SW_LIMIT)
				lft->real_soft_pkt_limit -= (lft->last_cnt - hard_cnt);
			lft->last_cnt = hard_cnt | IPSEC_SW_LIMIT;
		}
		goto out_xs;
	}

	if (lft->real_soft_pkt_limit <= IPSEC_SW_LIMIT) {
		if (lft->real_hard_pkt_limit < IPSEC_SW_LIMIT) {
			ipsec_aso_set(priv, obj_id, 0, 0, &hard_cnt, &soft_cnt);
			if (!hard_cnt) {
				xfrm_state_expire(xs, 1);
				printk("Notify hard obj_id=0x%d, xs=%p\n", obj_id, xs);
			} else {
				xfrm_state_expire(xs, 0);
				printk("Notify soft obj_id=0x%d, xs=%p\n", obj_id, xs);
			}
		} else {
			// check if need to set new packet limit
			if ((lft->real_hard_pkt_limit - (lft->last_cnt - lft->real_soft_pkt_limit)) > IPSEC_SW_LIMIT) {
				ipsec_aso_set(priv, obj_id,
					      ARM_SOFT | SET_SOFT | SET_CNT_BIT31,
					      lft->real_soft_pkt_limit,
					      &hard_cnt, &soft_cnt);
				printk("pkt_cnt=%d, arm soft, set soft, set bit 31", hard_cnt);
			} else // this is last soft event {
				ipsec_aso_set(priv, obj_id, 0, 0, &hard_cnt, &soft_cnt);
				xfrm_state_expire(xs, 0);
				printk("Notify soft obj_id=0x%d, xs=%p\n", obj_id, xs);
			}
				
			lft->real_hard_pkt_limit -= (lft->last_cnt - hard_cnt);
			lft->last_cnt = hard_cnt | IPSEC_SW_LIMIT;
		}
	} else {
		ipsec_aso_set(priv, obj_id,
			      ARM_SOFT | SET_CNT_BIT31,
			      0, &hard_cnt, &soft_cnt);
		
		lft->real_hard_pkt_limit -= (lft->last_cnt - hard_cnt);
		lft->real_soft_pkt_limit -= (lft->last_cnt - hard_cnt);
		lft->last_cnt = hard_cnt | IPSEC_SW_LIMIT;

		if (hard_cnt == soft_cnt) {
			// There is no more traffic after soft event
			struct mlx5e_ipsec_async_work *retry_work;

			retry_work = kzalloc(sizeof(*retry_work), GFP_ATOMIC);
			if (!retry_work)
				xfrm_state_expire(xs, 1);
			retry_work->priv = priv;
			retry_work->obj_id = obj_id;
			retry_work->retry = NO_TRAFFIC_RETRY;
			INIT_DELAYED_WORK(&retry_work->dwork, _mlx5e_ipsec_async_event);
			WARN_ON(!queue_delayed_work(priv->ipsec->wq, &retry_work->dwork, HZ));
		}
		printk("set bit 32, arm soft\n");
	}
*/

	/* Check if this is last hard event */
	if (lft->real_hard_pkt_limit <= lft->real_soft_pkt_limit) {
		ipsec_aso_set(priv, obj_id, 0, 0, &hard_cnt, &soft_cnt);
		if (!hard_cnt) {
			xfrm_state_expire(xs, 1);
			printk("Notify hard obj_id=0x%d, xs=%p\n", obj_id, xs);
		} else {
			printk("Something wrong. Should have hard event now\n");
		}
		goto out_xs;
	}

	/* Check if this is last soft event */
	if (lft->real_hard_pkt_limit <= lft->last_cnt) {
		lft->real_hard_pkt_limit -= (lft->last_cnt - hard_cnt);	
		xfrm_state_expire(xs, 0);
		printk("Notify soft obj_id=0x%d, xs=%p\n", obj_id, xs);
		goto out_xs;
	}

	if (lft->real_soft_pkt_limit < IPSEC_SW_LIMIT) {
		ipsec_aso_set(priv, obj_id,
			      ARM_SOFT | SET_SOFT | SET_CNT_BIT31,
			      lft->real_soft_pkt_limit,
			      &hard_cnt, &soft_cnt);

		lft->real_hard_pkt_limit -= (lft->last_cnt - hard_cnt);
		lft->last_cnt = hard_cnt | IPSEC_SW_LIMIT;
		goto out_xs;
	}

	/* soft pkt limit >= IPSEC_SW_LIMIT */
	ipsec_aso_set(priv, obj_id,
		      ARM_SOFT | SET_CNT_BIT31,
		      0, &hard_cnt, &soft_cnt);
	
	lft->real_hard_pkt_limit -= (lft->last_cnt - hard_cnt);
	if (lft->real_soft_pkt_limit > IPSEC_SW_LIMIT)
		lft->real_soft_pkt_limit -= (lft->last_cnt - hard_cnt);
	lft->last_cnt = hard_cnt | IPSEC_SW_LIMIT;

	/* If there is no packet after the soft event, need to setup workqueue to monitor */
	if (hard_cnt == soft_cnt) {
		// There is no more traffic after soft event
		struct mlx5e_ipsec_async_work *retry_work;

		retry_work = kzalloc(sizeof(*retry_work), GFP_ATOMIC);
		if (!retry_work)
			xfrm_state_expire(xs, 1);
		retry_work->priv = priv;
		retry_work->obj_id = obj_id;
		if (async_work->retry == 1)
			goto out_xs;

		retry_work->retry = async_work->retry > 1 ? async_work->retry - 1 : NO_TRAFFIC_RETRY;

		INIT_DELAYED_WORK(&retry_work->dwork, _mlx5e_ipsec_async_event);
		WARN_ON(!queue_delayed_work(priv->ipsec->wq, &retry_work->dwork, RETRY_SECOND));
	}

out_xs:
	/* read back remove later */
	ipsec_aso_set(priv, obj_id, 0, 0, &hard_cnt, &soft_cnt);

	printk("_mlx5e_ipsec_async_event real_hard=%d, real_soft=%d 009\n",  lft->real_hard_pkt_limit, lft->real_soft_pkt_limit);
	xfrm_state_put(xs);

out_async_work:
	kfree(async_work);
}

int mlx5e_ipsec_async_event(struct mlx5e_priv *priv, u32 obj_id)
{
	struct mlx5e_ipsec_async_work *async_work;

	mlx5_core_err(priv->mdev, "mlx5e_ipsec_async_event 001\n");

	async_work = kzalloc(sizeof(*async_work), GFP_ATOMIC);
	if (!async_work)
		return NOTIFY_DONE;

	async_work->priv = priv;
	async_work->obj_id = obj_id;

	INIT_DELAYED_WORK(&async_work->dwork, _mlx5e_ipsec_async_event);

	WARN_ON(!queue_delayed_work(priv->ipsec->wq, &async_work->dwork, 0));

	return NOTIFY_OK;
}
