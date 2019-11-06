/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB. */
/* Copyright (c) 2020 Mellanox Technologies. All rights reserved. */

#ifndef __MLX5_ESWITCH_ACL_EGRESS_H__
#define __MLX5_ESWITCH_ACL_EGRESS_H__

#include "eswitch.h"

/* Eswitch general egress acl APIs */
int esw_acl_egress_table_create(struct mlx5_eswitch *esw,
				struct mlx5_vport *vport, int table_size);
void esw_acl_egress_table_destroy(struct mlx5_vport *vport);
int esw_egress_acl_vlan_create(struct mlx5_eswitch *esw, struct mlx5_vport *vport,
			       struct mlx5_flow_destination *fwd_dest,
			       u16 vlan_id, u32 flow_action);
void esw_acl_egress_vlan_destroy(struct mlx5_vport *vport);
int esw_acl_egress_vlan_grp_create(struct mlx5_eswitch *esw, struct mlx5_vport *vport);
void esw_acl_egress_vlan_grp_destroy(struct mlx5_vport *vport);

/* Eswitch egress acl APIs in LEGACY mode */
int esw_acl_egress_lgcy_setup(struct mlx5_eswitch *esw, struct mlx5_vport *vport);
void esw_acl_egress_lgcy_cleanup(struct mlx5_eswitch *esw, struct mlx5_vport *vport);

/* Eswitch egress acl APIs in OFFLOADS mode */
int esw_acl_egress_ofld_setup(struct mlx5_eswitch *esw, struct mlx5_vport *vport);
void esw_acl_egress_ofld_cleanup(struct mlx5_vport *vport);

#endif /* __MLX5_ESWITCH_ACL_EGRESS_H__ */
