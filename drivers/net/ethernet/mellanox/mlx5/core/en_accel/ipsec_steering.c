// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020, Mellanox Technologies inc. All rights reserved. */

#include <linux/netdevice.h>
#include "accel/ipsec_offload.h"
#include "ipsec_steering.h"
#include "en_accel/accel_fs.h"
#include "fs_core.h"

#define NUM_IPSEC_FTE BIT(15)
#define NUM_IPSEC_FG 1

static int mlx5e_add_ipsec_copy_action_rule(struct mlx5e_priv *priv,
					    struct mlx5e_accel_proto *prot,
					    struct mlx5e_ipsec_rx_err *rx_err)
{
	u8 action[MLX5_UN_SZ_BYTES(set_add_copy_action_in_auto)] = {};
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_flow_act flow_act = {};
	struct mlx5_modify_hdr *modify_hdr;
	struct mlx5_flow_handle *fte;
	struct mlx5_flow_spec *spec;
	int err = 0;

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	/* Action to copy 7 bit ipsec_syndrome to regB[0:6] */
	MLX5_SET(copy_action_in, action, action_type, MLX5_ACTION_TYPE_COPY);
	MLX5_SET(copy_action_in, action, src_field, MLX5_ACTION_IN_FIELD_IPSEC_SYNDROME);
	MLX5_SET(copy_action_in, action, src_offset, 0);
	MLX5_SET(copy_action_in, action, length, 7);
	MLX5_SET(copy_action_in, action, dst_field, MLX5_ACTION_IN_FIELD_METADATA_REG_B);
	MLX5_SET(copy_action_in, action, dst_offset, 0);

	modify_hdr = mlx5_modify_header_alloc(mdev, MLX5_FLOW_NAMESPACE_KERNEL,
					      1, action);

	if (IS_ERR(modify_hdr)) {
		mlx5_core_err(mdev, "fail to alloc ipsec copy modify_header_id\n");
		err = PTR_ERR(modify_hdr);
		goto out_spec;
	}

	/* create fte */
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_MOD_HDR |
			  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	flow_act.modify_hdr = modify_hdr;
	fte = mlx5_add_flow_rules(rx_err->ft_rx_err, spec, &flow_act, &prot->default_dest, 1);
	if (IS_ERR(fte)) {
		err = PTR_ERR(fte);
		mlx5_core_err(mdev, "fail to add ipsec rx err copy rule err=%d\n", err);
		goto out;
	}

	rx_err->copy_fte = fte;
	rx_err->copy_modify_hdr = modify_hdr;

out:
	if (err)
		mlx5_modify_header_dealloc(mdev, modify_hdr);
out_spec:
	kfree(spec);
	return err;
}

static void mlx5e_del_ipsec_copy_action_rule(struct mlx5e_priv *priv, struct mlx5e_ipsec_rx_err *rx_err)
{
	if (rx_err->copy_fte) {
		mlx5_del_flow_rules(rx_err->copy_fte);
		rx_err->copy_fte = NULL;
	}

	if (rx_err->copy_modify_hdr) {
		mlx5_modify_header_dealloc(priv->mdev, rx_err->copy_modify_hdr);
		rx_err->copy_modify_hdr = NULL;
	}
}

static void mlx5e_ipsec_destroy_rx_err_ft(struct mlx5e_priv *priv, struct mlx5e_ipsec_rx_err *rx_err)
{
	mlx5e_del_ipsec_copy_action_rule(priv, rx_err);

	if (rx_err->ft_rx_err) {
		mlx5_destroy_flow_table(rx_err->ft_rx_err);
		rx_err->ft_rx_err = NULL;
	}
}

static int create_rx_inline_err_ft(struct mlx5e_priv *priv,
				   struct mlx5e_accel_proto *prot,
				   struct mlx5e_ipsec_rx_err *rx_err)
{
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_table *ft;
	int err;

	ft_attr.max_fte = 1;
	ft_attr.autogroup.max_num_groups = 1;
	ft_attr.level = MLX5E_ACCEL_FS_ERR_FT_LEVEL;
	ft_attr.prio = MLX5E_NIC_PRIO;	
	ft = mlx5_create_auto_grouped_flow_table(priv->fs.ns, &ft_attr);
	if (IS_ERR(ft)) {
		mlx5_core_err(priv->mdev, "fail to create ipsec rx inline ft\n");
		return PTR_ERR(ft);
	}

	rx_err->ft_rx_err = ft;
	err = mlx5e_add_ipsec_copy_action_rule(priv, prot, rx_err);
	if (err)
		goto out_err;

	mlx5_core_dbg(priv->mdev, "created ipsec err table id %u level %u\n", ft->id, ft->level);
	return 0;

out_err:
	mlx5_destroy_flow_table(ft);
	rx_err->ft_rx_err = NULL;
	return err;
}

int mlx5e_xfrm_add_rule(struct mlx5e_priv *priv, struct mlx5e_ipsec_sa_entry *sa_entry)
{
	struct mlx5_accel_esp_xfrm_attrs *attrs = &sa_entry->xfrm->attrs;
	u8 action[MLX5_UN_SZ_BYTES(set_add_copy_action_in_auto)] = {};
	struct mlx5_ipsec_sa_ctx *sa_ctx = sa_entry->hw_context;
	struct mlx5_modify_hdr *modify_hdr = NULL;
	struct mlx5_flow_handle *rule_tmp = NULL;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_spec *spec = NULL;
	struct mlx5e_accel_proto *prot;
	enum mlx5e_traffic_types type;
	u8 ip_version;
	int err = 0;

	if(!mlx5_is_ipsec_device(mdev))
		return 0;

	if (attrs->is_ipv6) {
		ip_version = 6;
		type = MLX5E_TT_IPV6_IPSEC_ESP;
	} else {
		ip_version = 4;
		type = MLX5E_TT_IPV4_IPSEC_ESP;
	}
	
	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec) {
		err = -ENOMEM;
		goto out;
	}

	/* Set 1  bit ipsec marker */
	/* Set 24 bit ipsec_obj_id */
	sa_ctx->set_modify_hdr = NULL;
	if (attrs->action == MLX5_ACCEL_ESP_ACTION_DECRYPT) {
		MLX5_SET(set_action_in,
			 action,
			 action_type,
			 MLX5_ACTION_TYPE_SET);
		MLX5_SET(set_action_in, action,
			 field,
			 MLX5_ACTION_IN_FIELD_METADATA_REG_B);
		MLX5_SET(set_action_in, action, data, (sa_ctx->ipsec_obj_id << 1) | 0x1);
		MLX5_SET(set_action_in, action, offset, 7);
		MLX5_SET(set_action_in, action, length, 25);

		modify_hdr = mlx5_modify_header_alloc(mdev, MLX5_FLOW_NAMESPACE_KERNEL, 1, action);

		if (IS_ERR(modify_hdr)) {
			mlx5_core_err(mdev, "fail to alloc ipsec set modify_header_id\n");
			err = PTR_ERR(modify_hdr);
			goto out;
		}
	}

	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS | MLX5_MATCH_MISC_PARAMETERS;

	/* ip_version */
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.ip_version);
	MLX5_SET(fte_match_param, spec->match_value, outer_headers.ip_version, ip_version);

	/* Non fragmented */
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.frag);
	MLX5_SET(fte_match_param, spec->match_value, outer_headers.frag, 0);

	/* ESP header */
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.ip_protocol);
	MLX5_SET(fte_match_param, spec->match_value, outer_headers.ip_protocol, IPPROTO_ESP);

	/* SPI number */
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, misc_parameters.outer_esp_spi);
	MLX5_SET(fte_match_param, spec->match_value, misc_parameters.outer_esp_spi, cpu_to_be32(attrs->spi));

	if (ip_version == 4) {
		memcpy(MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    outer_headers.src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &attrs->saddr.a4, 4);
		memcpy(MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &attrs->daddr.a4, 4);
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
				 outer_headers.src_ipv4_src_ipv6.ipv4_layout.ipv4);
		MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
				 outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	} else {
		memcpy(MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    outer_headers.src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &attrs->saddr.a6, 16);
		memcpy(MLX5_ADDR_OF(fte_match_param, spec->match_value,
				    outer_headers.dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &attrs->daddr.a6, 16);
		memset(MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				    outer_headers.src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       0xff, 16);
		memset(MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				    outer_headers.dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       0xff, 16);
	}

	/* XFRM_OFFLOAD_INBOUND destination is error FT.
	 * Outbound action is ALLOW.
	 */
	flow_act.ipsec_obj_id = sa_ctx->ipsec_obj_id;
	flow_act.flags |= FLOW_ACT_NO_APPEND;

	if (attrs->action == MLX5_ACCEL_ESP_ACTION_DECRYPT) {
		flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
				  MLX5_FLOW_CONTEXT_ACTION_IPSEC_DECRYPT |
				  MLX5_FLOW_CONTEXT_ACTION_MOD_HDR;
		dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		flow_act.modify_hdr = modify_hdr;

		prot = priv->fs.accel.prot[type];
		/* Fail safe check if ESP FTs are not initialized */
		if (!prot->ft)
			goto out_modify_header;

		dest.ft = ((struct mlx5e_ipsec_rx_err *)(prot->proto_priv))->ft_rx_err;
		rule_tmp = mlx5_add_flow_rules(prot->ft, spec, &flow_act, &dest, 1);
	} else {
		/* Add IPsec indicator in metdata_reg_a */
		spec->match_criteria_enable |= MLX5_MATCH_MISC_PARAMETERS_2;
		MLX5_SET(fte_match_param,
			 spec->match_criteria, misc_parameters_2.metadata_reg_a,
			 MLX5_ETH_WQE_FT_META_IPSEC);
		MLX5_SET(fte_match_param, spec->match_value, misc_parameters_2.metadata_reg_a,
			 MLX5_ETH_WQE_FT_META_IPSEC);

		flow_act.action = MLX5_FLOW_CONTEXT_ACTION_ALLOW |
				  MLX5_FLOW_CONTEXT_ACTION_IPSEC_ENCRYPT;
		rule_tmp = mlx5_add_flow_rules(priv->ipsec->ft_tx, spec,
					       &flow_act, NULL, 0);
	}

	if (IS_ERR(rule_tmp)) {
		err = PTR_ERR(rule_tmp);
		mlx5_core_err(mdev, "fail to add ipsec rule attrs->action=0x%x, ip_version=%d\n",
			      attrs->action, ip_version);
		goto out_modify_header;
	} else {
		sa_entry->ipsec_rule.rule = rule_tmp;
		sa_entry->ipsec_rule.set_modify_hdr = modify_hdr;
	}

	if (attrs->action == MLX5_ACCEL_ESP_ACTION_DECRYPT)
		mlx5e_accel_fs_ref_prot(priv, type, 1);

	goto out;

out_modify_header:
	if (attrs->action == MLX5_ACCEL_ESP_ACTION_DECRYPT)
		mlx5_modify_header_dealloc(mdev, modify_hdr);
out:
	kvfree(spec);
	return err;
}

void mlx5e_xfrm_del_rule(struct mlx5e_priv *priv, struct mlx5e_ipsec_sa_entry *sa_entry)
{
	struct mlx5_accel_esp_xfrm_attrs *attrs = &sa_entry->xfrm->attrs;

	if (attrs->action == MLX5_ACCEL_ESP_ACTION_DECRYPT)
		mlx5e_accel_fs_ref_prot(priv,
					attrs->is_ipv6 ?
					MLX5E_TT_IPV6_IPSEC_ESP : MLX5E_TT_IPV4_IPSEC_ESP,
					-1);

	if (sa_entry->ipsec_rule.rule) {
		mlx5_del_flow_rules(sa_entry->ipsec_rule.rule);
		sa_entry->ipsec_rule.rule = NULL;
	}

	if (sa_entry->ipsec_rule.set_modify_hdr) {
		mlx5_modify_header_dealloc(priv->mdev, sa_entry->ipsec_rule.set_modify_hdr);
		sa_entry->ipsec_rule.set_modify_hdr = NULL;
	}
}

int mlx5e_ipsec_create_tx_ft(struct mlx5e_priv *priv)
{
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5e_ipsec *ipsec = priv->ipsec;
	struct mlx5_flow_table *ft;

	if (!ipsec)
		return 0;

	ft_attr.max_fte = NUM_IPSEC_FTE;
	ft_attr.autogroup.max_num_groups = NUM_IPSEC_FG;
	ft = mlx5_create_auto_grouped_flow_table(priv->fs.egress_ns, &ft_attr);
	if (IS_ERR(ft)) {
		mlx5_core_err(priv->mdev, "fail to create ipsec tx ft\n");
		return PTR_ERR(ft);
	}
	ipsec->ft_tx = ft;
	return 0;
}

void mlx5e_ipsec_destroy_tx_ft(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec *ipsec = priv->ipsec;

	if (!ipsec)
		return;

	if (!IS_ERR_OR_NULL(ipsec->ft_tx)) {
		mlx5_destroy_flow_table(ipsec->ft_tx);
		ipsec->ft_tx = NULL;
	}
}

static void ipsec_rx_inline_priv_remove(struct mlx5e_priv *priv, enum mlx5e_traffic_types type)
{
	struct mlx5e_ipsec_rx_err *rx_err;
	struct mlx5e_accel_proto *prot;

	if (!priv->fs.accel.prot[type])
		return;
	prot = priv->fs.accel.prot[type];

	if (prot->proto_priv) {
		rx_err = (struct mlx5e_ipsec_rx_err *)priv->fs.accel.prot[type]->proto_priv;
		mlx5e_ipsec_destroy_rx_err_ft(priv, rx_err);
		kfree(rx_err);
		prot->proto_priv = NULL;
	}
}

static int ipsec_rx_inline_priv_init(struct mlx5e_priv *priv, enum mlx5e_traffic_types type)
{
	struct mlx5e_ipsec_rx_err *rx_err;
	struct mlx5e_accel_proto *prot;
	int err;

	rx_err = kvzalloc(sizeof(*rx_err), GFP_KERNEL);
	if (!rx_err)
		return -ENOMEM;

	prot = priv->fs.accel.prot[type];
	err = create_rx_inline_err_ft(priv, prot, rx_err);
	if (err)
		goto out_err;

	prot->proto_priv = rx_err;
	return 0;

out_err:
	kfree(rx_err);
	return err;
}

int mlx5e_ipsec_rx_inline_remove(struct mlx5e_priv *priv, enum mlx5e_traffic_types type)
{
	struct mlx5e_accel_proto *prot;

	/* The netdev unreg already happened, so all offloaded rule are already removed */
	if (!priv->fs.accel.prot[type])
		return 0;
	prot = priv->fs.accel.prot[type];

	ipsec_rx_inline_priv_remove(priv, type);

	if (prot->miss_rule) {
		mlx5_del_flow_rules(priv->fs.accel.prot[type]->miss_rule);
		prot->miss_rule = NULL;
	}

	if (prot->miss_group) {
		mlx5_destroy_flow_group(priv->fs.accel.prot[type]->miss_group);
		prot->miss_group = NULL;
	}

	if (prot->ft) {
		mlx5_destroy_flow_table(priv->fs.accel.prot[type]->ft);
		prot->ft = NULL;
	}

	return 0;
}

int mlx5e_ipsec_is_supported(struct mlx5e_priv *priv, enum mlx5e_traffic_types type)
{
	return (mlx5_ipsec_device_caps(priv->mdev) & MLX5_ACCEL_IPSEC_CAP_DEVICE);
}

int mlx5e_ipsec_rx_inline_init(struct mlx5e_priv *priv, enum mlx5e_traffic_types type)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_flow_group *miss_group;
	struct mlx5_flow_handle *miss_rule;
	MLX5_DECLARE_FLOW_ACT(flow_act);
	struct mlx5_flow_spec *spec;
	struct mlx5_flow_table *ft;
	u32 *flow_group_in;
	int err = 0;

	err = ipsec_rx_inline_priv_init(priv, type);
	if (err)
		return err;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!flow_group_in || !spec) {
		err = -ENOMEM;
		goto out_alloc;
	}

	/* Create FT */
	ft_attr.max_fte = NUM_IPSEC_FTE;
	ft_attr.level = MLX5E_ACCEL_FS_FT_LEVEL;
	ft_attr.prio = MLX5E_NIC_PRIO;	
	ft_attr.autogroup.num_reserved_entries = 1;
	ft_attr.autogroup.max_num_groups = NUM_IPSEC_FG;
	ft = mlx5_create_auto_grouped_flow_table(priv->fs.ns, &ft_attr);
	if (IS_ERR(ft)) {
		mlx5_core_err(priv->mdev, "fail to create ipsec rx ft, type=%d\n", type);
		err = PTR_ERR(ft);
		goto out_alloc;
	}
	priv->fs.accel.prot[type]->ft = ft;

	/* Create miss_group */
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index,
		 ft->max_fte - 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index,
		 ft->max_fte - 1);
	miss_group = mlx5_create_flow_group(ft, flow_group_in);
	if (IS_ERR(miss_group)) {
		mlx5_core_err(priv->mdev, "fail to create ipsec rx miss_group, type=%d\n", type);
		err = PTR_ERR(miss_group);
		goto err_steering;
	}
	priv->fs.accel.prot[type]->miss_group = miss_group;

	/* Create miss rule */
	miss_rule = mlx5_add_flow_rules(ft, spec, &flow_act, &priv->fs.accel.prot[type]->default_dest, 1);
	if (IS_ERR(miss_rule)) {
		mlx5_core_err(priv->mdev, "fail to create ipsec rx miss_rule, type=%d\n", type);
		err = PTR_ERR(miss_rule);
		goto err_steering;
	}
	priv->fs.accel.prot[type]->miss_rule = miss_rule;

	goto out_alloc;

err_steering:
	mlx5e_ipsec_rx_inline_remove(priv, type);

out_alloc:
	kfree(flow_group_in);
	kfree(spec);
	return err;
}
