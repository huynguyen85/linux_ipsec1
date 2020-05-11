#include "eswitch.h"
#include "en.h"
#include "en/txrx.h"
#include "en/params.h"

#ifndef __MLX5_EN_ASO_H__
#define __MLX5_EN_ASO_H__

#define ASO_LOG_WQ_SZ 0
#define ASO_CPU_IX 0

struct mlx5e_asosq_wqe_info {
	u8  opcode;

	/* Auxiliary data for different opcodes. */
	union {
		struct {
			struct mlx5e_rq *rq;
		} umr;
	};
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
} ____cacheline_aligned_in_smp;

struct mlx5e_aso {
	int cpu;
	struct mlx5e_priv *priv;
	struct mlx5e_sq_param param;
	struct mlx5e_asosq sq;
}

#endif
