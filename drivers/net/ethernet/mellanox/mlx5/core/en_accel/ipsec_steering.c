// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2020, Mellanox Technologies inc. All rights reserved. */

#include "ipsec_steering.h"
#include "fs.h"
#include "fs_core.h"

static int mlx5e_add_ipsec_copy_action_rule(struct mlx5e_priv *priv,
					    enum accel_fs_type type)
{
	u8 action[MLX5_UN_SZ_BYTES(set_add_copy_action_in_auto)] = {};
	enum accel_fs_ipsec_default_type ipsec_default_type;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_tir *tir = priv->indir_tir;
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_modify_hdr *modify_hdr;
	struct mlx5e_flow_table *fs_t;
	struct mlx5_flow_handle *fte;
	struct mlx5_flow_spec *spec;
	enum mlx5e_traffic_types tt;
	int err = 0;

	if (type == ACCEL_FS_IPV4_ESP) {
		tt = MLX5E_TT_IPV4_IPSEC_ESP;
		ipsec_default_type = IPV4_ESP;
	} else if (type == ACCEL_FS_IPV6_ESP) {
		tt = MLX5E_TT_IPV6_IPSEC_ESP;
		ipsec_default_type = IPV6_ESP;
	} else {
		return -EINVAL;
	}

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	/* Action to copy 7 bit ipsec_syndrome */
	MLX5_SET(copy_action_in, action, action_type, MLX5_ACTION_TYPE_COPY);
	MLX5_SET(copy_action_in,
		 action,
		 src_field,
		 MLX5_ACTION_IN_FIELD_IPSEC_SYNDROME);
	MLX5_SET(copy_action_in, action, src_offset, 0);
	MLX5_SET(copy_action_in, action, length, 7);
	MLX5_SET(copy_action_in,
		 action,
		 dst_field,
		 MLX5_ACTION_IN_FIELD_METADATA_REG_B);
	MLX5_SET(copy_action_in, action, dst_offset, 0);

	modify_hdr = mlx5_modify_header_alloc(mdev,
					      MLX5_FLOW_NAMESPACE_KERNEL,
					      1,
					      action);

	if (IS_ERR(modify_hdr)) {
		mlx5_core_err(mdev, "fail to alloc ipsec copy modify_header_id\n");
		err = PTR_ERR(modify_hdr);
		goto out_spec;
	}
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_MOD_HDR |
			  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	flow_act.modify_hdr = modify_hdr;
	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	dest.tir_num = tir[tt].tirn;

	fs_t = &priv->fs.accel.ipsec_default[ipsec_default_type].ft_rx_err;
	fte = mlx5_add_flow_rules(fs_t->t, spec, &flow_act, &dest, 1);
	if (IS_ERR(fte)) {
		err = PTR_ERR(fte);
		mlx5_core_err(mdev,
			      "fail to add ipsec modify header rule err=%d\n",
			      err);
		fte = NULL;
		goto out;
	}

	priv->fs.accel.ipsec_default[ipsec_default_type].copy_fte = fte;
	priv->fs.accel.ipsec_default[ipsec_default_type].copy_modify_hdr = modify_hdr;

out:
	if (err)
		mlx5_modify_header_dealloc(mdev, modify_hdr);
out_spec:
	kfree(spec);
	return err;
}

static void mlx5e_del_ipsec_copy_action_rule(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec_default *ipsec_default;
	struct mlx5_core_dev *mdev;
	int i;

	mdev = priv->mdev;
	ipsec_default = priv->fs.accel.ipsec_default;

	for (i = 0; i < IPSEC_DEFAULT_TYPES; i++) {
		if (ipsec_default[i].copy_fte) {
			mlx5_del_flow_rules(ipsec_default[i].copy_fte);
			ipsec_default[i].copy_fte = NULL;
		}

		if (ipsec_default[i].copy_modify_hdr) {
			mlx5_modify_header_dealloc(mdev,
						   ipsec_default[i].copy_modify_hdr);
			ipsec_default[i].copy_modify_hdr = NULL;
		}
	}
}

void mlx5e_ipsec_destroy_rx_err_ft(struct mlx5e_priv *priv)
{
	int i;

	if (!(mlx5_ipsec_device_caps(priv->mdev) & MLX5_ACCEL_IPSEC_CAP_DEVICE))
		return;

	mlx5e_del_ipsec_copy_action_rule(priv);

	for (i = 0; i < IPSEC_DEFAULT_TYPES; i++) {
		if (priv->fs.accel.ipsec_default[i].ft_rx_err.t) {
			mlx5e_destroy_flow_table(&priv->fs.accel.ipsec_default[i].ft_rx_err);
			priv->fs.accel.ipsec_default[i].ft_rx_err.t = NULL;
		}
	}
}

static int create_empty_groups(struct mlx5e_flow_table *ft)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	u32 *in;
	int err;

	ft->g = kcalloc(1, sizeof(*ft->g), GFP_KERNEL);
	in = kvzalloc(inlen, GFP_KERNEL);
	if  (!in || !ft->g) {
		kvfree(ft->g);
		kvfree(in);
		return -ENOMEM;
	}

	MLX5_SET_CFG(in, start_flow_index, 0);
	MLX5_SET_CFG(in, end_flow_index, 0);
	ft->g[ft->num_groups] = mlx5_create_flow_group(ft->t, in);

	kvfree(in);

	if (IS_ERR(ft->g[ft->num_groups]))
		goto err;
	ft->num_groups++;

	return 0;

err:
	err = PTR_ERR(ft->g[ft->num_groups]);
	ft->g[ft->num_groups] = NULL;
	return err;
}

static int create_default_ft(struct mlx5e_priv *priv,
			     struct mlx5e_flow_table *ft,
			     enum accel_fs_type type)
{
	struct mlx5_flow_table_attr ft_attr = {};
	int err;

	ft->num_groups = 0;
	ft_attr.max_fte = 1;
	ft_attr.level = MLX5E_ACCEL_FS_ERR_FT_LEVEL;
	ft_attr.prio = MLX5E_NIC_PRIO;

	ft->t = mlx5_create_flow_table(priv->fs.ns, &ft_attr);
	if (IS_ERR(ft->t)) {
		err = PTR_ERR(ft->t);
		ft->t = NULL;
		return err;
	}

	err = create_empty_groups(ft);
	if (err)
		return err;

	err = mlx5e_add_ipsec_copy_action_rule(priv, type);

	mlx5_core_dbg(priv->mdev, "created ipsec err table id %u level %u\n",
		      ft->t->id, ft->t->level);

	return err;
}

int mlx5e_ipsec_create_rx_err_ft(struct mlx5e_priv *priv)
{
	struct mlx5e_flow_table *ft;
	int err = 0;
	int i;

	if (!(mlx5_ipsec_device_caps(priv->mdev) & MLX5_ACCEL_IPSEC_CAP_DEVICE))
		return 0;

	for (i = 0; i < IPSEC_DEFAULT_TYPES; i++) {
		ft = &priv->fs.accel.ipsec_default[i].ft_rx_err;
		err = create_default_ft(priv, ft, ACCEL_FS_IPV4_ESP + i);
		if (err)
			goto out_err;
	}

	return err;

out_err:
	mlx5e_ipsec_destroy_rx_err_ft(priv);

	return err;
}
