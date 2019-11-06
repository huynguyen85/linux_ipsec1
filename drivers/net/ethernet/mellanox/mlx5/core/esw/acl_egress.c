// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB.
/* Copyright (c) 2020 Mellanox Technologies. All rights reserved. */

#include "mlx5_core.h"
#include "eswitch.h"
#include "acl_egress.h"

int esw_egress_acl_vlan_create(struct mlx5_eswitch *esw,
			       struct mlx5_vport *vport,
			       struct mlx5_flow_destination *fwd_dest,
			       u16 vlan_id, u32 flow_action)
{
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_spec *spec;
	int err = 0;

	if (vport->egress.allowed_vlan)
		return -EEXIST;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.cvlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, spec->match_value, outer_headers.cvlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria, outer_headers.first_vid);
	MLX5_SET(fte_match_param, spec->match_value, outer_headers.first_vid, vlan_id);

	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
	flow_act.action = flow_action;
	vport->egress.allowed_vlan =
		mlx5_add_flow_rules(vport->egress.acl, spec,
				    &flow_act, fwd_dest, 0);
	if (IS_ERR(vport->egress.allowed_vlan)) {
		err = PTR_ERR(vport->egress.allowed_vlan);
		esw_warn(esw->dev,
			 "vport[%d] configure egress vlan rule failed, err(%d)\n",
			 vport->vport, err);
		vport->egress.allowed_vlan = NULL;
	}

	kvfree(spec);
	return err;
}

void esw_acl_egress_vlan_destroy(struct mlx5_vport *vport)
{
	if (!IS_ERR_OR_NULL(vport->egress.allowed_vlan)) {
		mlx5_del_flow_rules(vport->egress.allowed_vlan);
		vport->egress.allowed_vlan = NULL;
	}
}

int esw_acl_egress_vlan_grp_create(struct mlx5_eswitch *esw, struct mlx5_vport *vport)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_group *vlan_grp;
	void *match_criteria;
	u32 *flow_group_in;
	int ret = 0;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	if (!flow_group_in)
		return -ENOMEM;

	MLX5_SET(create_flow_group_in, flow_group_in,
		 match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	match_criteria = MLX5_ADDR_OF(create_flow_group_in,
				      flow_group_in, match_criteria);
	MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.cvlan_tag);
	MLX5_SET_TO_ONES(fte_match_param, match_criteria, outer_headers.first_vid);
	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index, 0);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index, 0);

	vlan_grp = mlx5_create_flow_group(vport->egress.acl, flow_group_in);
	if (IS_ERR(vlan_grp)) {
		ret = PTR_ERR(vlan_grp);
		esw_warn(esw->dev,
			 "Failed to create E-Switch vport[%d] egress pop vlans flow group, err(%d)\n",
			 vport->vport, ret);
		goto out;
	}
	vport->egress.vlan_grp = vlan_grp;

out:
	kvfree(flow_group_in);
	return ret;
}

void esw_acl_egress_vlan_grp_destroy(struct mlx5_vport *vport)
{
	if (!IS_ERR_OR_NULL(vport->egress.vlan_grp)) {
		mlx5_destroy_flow_group(vport->egress.vlan_grp);
		vport->egress.vlan_grp = NULL;
	}
}

int esw_acl_egress_table_create(struct mlx5_eswitch *esw,
				struct mlx5_vport *vport, int table_size)
{
	struct mlx5_core_dev *dev = esw->dev;
	struct mlx5_flow_namespace *root_ns;
	struct mlx5_flow_table *acl;
	int err = 0;
	int id;

	if (!MLX5_CAP_ESW_EGRESS_ACL(dev, ft_support))
		return -EOPNOTSUPP;

	if (!IS_ERR_OR_NULL(vport->egress.acl))
		return 0;

	esw_debug(dev, "Create vport[%d] egress ACL log_max_size(%d)\n",
		  vport->vport, MLX5_CAP_ESW_EGRESS_ACL(dev, log_max_ft_size));

	id = mlx5_eswitch_vport_num_to_index(esw, vport->vport);
	root_ns = mlx5_get_flow_vport_acl_namespace(dev, MLX5_FLOW_NAMESPACE_ESW_EGRESS, id);
	if (!root_ns) {
		esw_warn(dev, "Failed to get E-Switch egress flow namespace for vport (%d)\n",
			 vport->vport);
		return -EOPNOTSUPP;
	}

	acl = mlx5_create_vport_flow_table(root_ns, 0, table_size, 0, vport->vport);
	if (IS_ERR(acl)) {
		err = PTR_ERR(acl);
		esw_warn(dev, "Failed to create E-Switch vport[%d] egress flow Table, err(%d)\n",
			 vport->vport, err);
		return err;
	}
	vport->egress.acl = acl;
	return 0;
}

void esw_acl_egress_table_destroy(struct mlx5_vport *vport)
{
	if (IS_ERR_OR_NULL(vport->egress.acl))
		return;

	mlx5_destroy_flow_table(vport->egress.acl);
	vport->egress.acl = NULL;
}
