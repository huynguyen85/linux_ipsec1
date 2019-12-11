/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2020, Mellanox Technologies inc. All rights reserved. */

#ifndef __MLX5_IPSEC_STEERING_H__
#define __MLX5_IPSEC_STEERING_H__

#ifdef CONFIG_MLX5_EN_IPSEC
#include "en.h"
#include "ipsec.h"
#include "accel/ipsec_offload.h"
#include "en/fs.h"

struct mlx5e_ipsec_rx_err {
	struct mlx5_flow_table *ft_rx_err;
	struct mlx5_flow_handle *copy_fte;
	struct mlx5_modify_hdr *copy_modify_hdr;
};

int mlx5e_xfrm_add_rule(struct mlx5e_priv *priv,
			struct mlx5e_ipsec_sa_entry *sa_entry);
void mlx5e_xfrm_del_rule(struct mlx5e_priv *priv,
			 struct mlx5e_ipsec_sa_entry *sa_entry);
int mlx5e_ipsec_create_tx_ft(struct mlx5e_priv *priv);
void mlx5e_ipsec_destroy_tx_ft(struct mlx5e_priv *priv);
int mlx5e_ipsec_rx_inline_init(struct mlx5e_priv *priv, enum mlx5e_traffic_types type);
int mlx5e_ipsec_rx_inline_remove(struct mlx5e_priv *priv, enum mlx5e_traffic_types type);
int mlx5e_ipsec_is_supported(struct mlx5e_priv *priv, enum mlx5e_traffic_types type);
#endif /* CONFIG_MLX5_EN_IPSEC */
#endif /* __MLX5_IPSEC_STEERING_H__ */
