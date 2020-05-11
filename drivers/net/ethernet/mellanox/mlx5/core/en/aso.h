#include "en.h"
#include "en_accel/ipsec.h"
#include "linux/dma-mapping.h"

#ifndef __MLX5_EN_ASO_H__
#define __MLX5_EN_ASO_H__

#define MLX5E_ASO_WQEBBS \
	(DIV_ROUND_UP(sizeof(struct mlx5e_aso_wqe), MLX5_SEND_WQE_BB))

enum {
	MLX5_ACCESS_ASO_OPC_MOD_IPSEC,
};

#define ASO_OPC_MOD_IPSEC_SHIFTED (MLX5_ACCESS_ASO_OPC_MOD_IPSEC << MLX5_WQE_CTRL_WQE_OPC_MOD_SHIFT)
#define ASO_CTRL_READ_EN BIT(1)
struct mlx5e_aso_wqe {
	struct mlx5_wqe_ctrl_seg		ctrl;
	struct mlx5_wqe_aso_ctrl_seg		aso_ctrl;
	struct mlx5_wqe_aso_data_seg		aso_data;
};

int mlx5e_aso_reg_mr(struct mlx5e_priv *priv);
void mlx5e_aso_dereg_mr(struct mlx5e_priv *priv);

#endif
