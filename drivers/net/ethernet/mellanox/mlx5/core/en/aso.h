#include "en.h"
#include "en_accel/ipsec.h"
#include "linux/dma-mapping.h"
#include "en/txrx.h"
#include "en/params.h"

#ifndef __MLX5_EN_ASO_H__
#define __MLX5_EN_ASO_H__

#define MLX5E_ASO_WQEBBS \
	(DIV_ROUND_UP(sizeof(struct mlx5e_aso_wqe), MLX5_SEND_WQE_BB))

enum {
	MLX5_ACCESS_ASO_OPC_MOD_IPSEC,
};

#define ASO_OPC_MOD_IPSEC_SHIFTED (MLX5_ACCESS_ASO_OPC_MOD_IPSEC << MLX5_WQE_CTRL_WQE_OPC_MOD_SHIFT)
#define ASO_CTRL_READ_EN BIT(0)
struct mlx5e_aso_wqe {
	struct mlx5_wqe_ctrl_seg		ctrl;
	struct mlx5_wqe_aso_ctrl_seg		aso_ctrl;
	struct mlx5_wqe_aso_data_seg		aso_data;
};

struct mlx5e_asosq {
	/* data path */
	u16                        cc;
	u16                        pc;

	struct mlx5_wqe_ctrl_seg  *doorbell_cseg;
	struct mlx5e_cq            cq;

	/* write@xmit, read@completion */
	struct {
		struct mlx5e_sq_wqe_info *aso_wqe;
	} db;

	/* read only */
	struct mlx5_wq_cyc         wq;
	void __iomem              *uar_map;
	u32                        sqn;
	unsigned long              state;

	/* control path */
	struct mlx5_wq_ctrl        wq_ctrl;
	//struct mlx5e_channel      *channel;
	//
	//struct work_struct         recover_ddwork;
} ____cacheline_aligned_in_smp;

struct mlx5e_ipsec_aso {
	struct mlx5_core_mkey mkey;
	dma_addr_t dma_addr;
	void *ctx;
	size_t size;
	u32 pdn;
	struct mlx5e_cq_param cq_param;
	int cpu;
	struct mlx5e_asosq sq;
	struct mlx5e_sq_param sq_param;
};

enum {
	ALWAYS_FALSE = 0,
	ALWAYS_TRUE,
	EQUAL,
	NOT_EQUAL,
	GREATER_OR_EQUAL,
	LESSER_OR_EQUAL,
	LESSER,
	GREATER,
	CYCLIC_GREATER,
	CYCLIC_LESSER,
};

enum {
	ASO_DATA_MASK_MODE_BITWISE_64BIT = 0,
	ASO_DATA_MASK_MODE_BYTEWISE_64BYTE,
	ASO_DATA_MASK_MODE_CALCULATED_64BYTE,
};

#define MLX5_IPSEC_ASO_REMOVE_FLOW_PKT_CNT_OFFSET 0

struct mlx5e_aso_ctrl_param {
	u8	data_mask_mode;
	u8	condition_0_operand;
	u8      condition_1_operand;
	u8	condition_0_offset;
	u8      condition_1_offset;
	u8	data_offset;
	u8      condition_operand;
	u32	condition_0_data;
	u32	condition_0_mask;
	u32	condition_1_data;
	u32	condition_1_mask;
	u64	bitwise_data;
	u64	data_mask;
};

int mlx5e_aso_reg_mr(struct mlx5e_priv *priv);
void mlx5e_aso_dereg_mr(struct mlx5e_priv *priv);
int mlx5e_aso_send_ipsec_aso(struct mlx5e_priv *priv, u32 ipsec_obj_id,
			     struct mlx5e_aso_ctrl_param *param);
void mlx5e_aso_setup(struct mlx5e_priv *priv, struct mlx5e_channel *c);
void mlx5e_aso_cleanup(struct mlx5e_priv *priv);

#endif
