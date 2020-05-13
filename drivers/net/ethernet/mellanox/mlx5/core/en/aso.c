#include "aso.h"

static int mlx5e_aso_create_mkey(struct mlx5_core_dev *mdev, u32 pdn, struct mlx5_core_mkey *mkey)
{
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	void *mkc;
	u32 *in;
	int err;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_PA);
	MLX5_SET(mkc, mkc, lw, 1);
	MLX5_SET(mkc, mkc, lr, 1);

	MLX5_SET(mkc, mkc, pd, pdn);
	MLX5_SET(mkc, mkc, length64, 1);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);

	err = mlx5_core_create_mkey(mdev, mkey, in, inlen);

	kvfree(in);
	return err;
}

int mlx5e_aso_reg_mr(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec_aso *aso = &priv->ipsec->aso;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct device *dma_device = &mdev->pdev->dev;
	size_t size = MLX5_ST_SZ_BYTES(ipsec_aso);
	dma_addr_t dma_addr;
	int err;

/*
	err = mlx5_core_alloc_pd(mdev, &aso->pdn);
	if (err) {
		mlx5_core_err(mdev, "alloc pd failed, %d\n", err);
		return err;
	}
	mlx5_core_err(mdev, "aso->pdn=0x%x\n", aso->pdn);
*/
	dma_addr = dma_map_single(dma_device, aso->ctx, size, DMA_BIDIRECTIONAL);
	err = dma_mapping_error(dma_device, dma_addr);
	if (err) {
		mlx5_core_warn(mdev, "Can't dma ipsec_aso\n");
		goto out_dma;
	}

	/* Huy to do aso_pdn */
/*
	err = mlx5e_aso_create_mkey(mdev, aso->pdn, &aso->mkey);
	if (err) {
		mlx5_core_warn(mdev, "Can't create mkey\n");
		goto out_mkey;
	}
*/
	mlx5_core_err(mdev, "Huy dma_addr=0x%lx, aso->mkey.key=0x%x\n", dma_addr, aso->mkey.key);

	aso->dma_addr = dma_addr;
	aso->size = size;
	return 0;

//out_mkey:
//	dma_unmap_single(dma_device, dma_addr, size, DMA_BIDIRECTIONAL);

out_dma:
//	mlx5_core_dealloc_pd(mdev, aso->pdn);
	return err;	
}

void mlx5e_aso_dereg_mr(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec_aso *aso = &priv->ipsec->aso;

//	mlx5_core_destroy_mkey(priv->mdev, &aso->mkey);
	dma_unmap_single(&priv->mdev->pdev->dev, aso->dma_addr, aso->size, DMA_BIDIRECTIONAL);
//	mlx5_core_dealloc_pd(priv->mdev, aso->pdn);
}

static inline void mlx5e_build_aso_wqe(struct mlx5e_ipsec_aso *aso,
				       struct mlx5e_icosq *sq,
				       struct mlx5e_aso_wqe *wqe,
				       u32 ipsec_obj_id)
{
	struct mlx5_wqe_ctrl_seg *cseg = &wqe->ctrl;
	struct mlx5_wqe_aso_ctrl_seg *aso_ctrl = &wqe->aso_ctrl;
	u8 ds_cnt;

	ds_cnt = DIV_ROUND_UP(sizeof(struct mlx5e_aso_wqe), MLX5_SEND_WQE_DS);
	cseg->opmod_idx_opcode = cpu_to_be32(ASO_OPC_MOD_IPSEC_SHIFTED |
					     (sq->pc << MLX5_WQE_CTRL_WQE_INDEX_SHIFT) |
					     MLX5_OPCODE_ACCESS_ASO);
	cseg->qpn_ds     = cpu_to_be32((sq->sqn << MLX5_WQE_CTRL_QPN_SHIFT) | ds_cnt);
	cseg->fm_ce_se   = MLX5_WQE_CTRL_CQ_UPDATE;
	cseg->general_id = cpu_to_be32(ipsec_obj_id);

	aso_ctrl->va_l  = cpu_to_be32((aso->dma_addr & 0xFFFFFFFF) | ASO_CTRL_READ_EN);
	aso_ctrl->va_h  = cpu_to_be32(aso->dma_addr >> 32);
	aso_ctrl->l_key = cpu_to_be32(aso->mkey.key);
}


int mlx5e_aso_query_ipsec_aso(struct mlx5e_priv *priv, u32 ipsec_obj_id)
{
	struct mlx5e_ipsec_aso *aso = &priv->ipsec->aso;
	struct mlx5e_icosq *sq = &priv->channels.c[0]->icosq;
	struct mlx5_wq_cyc *wq = &sq->wq;
	struct mlx5e_aso_wqe *aso_wqe;
	u16 pi, contig_wqebbs_room;

	printk("mlx5e_aso_query_ipsec_aso\n");

	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);
	
	if (unlikely(contig_wqebbs_room < MLX5E_ASO_WQEBBS)) {
		mlx5e_fill_icosq_frag_edge(sq, wq, pi, contig_wqebbs_room);
		pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	}

	aso_wqe = mlx5_wq_cyc_get_wqe(wq, pi);
	mlx5e_build_aso_wqe(aso, sq, aso_wqe, ipsec_obj_id);

	sq->db.ico_wqe[pi].opcode = MLX5_OPCODE_ACCESS_ASO;
	sq->pc += MLX5E_ASO_WQEBBS;
	sq->doorbell_cseg = &aso_wqe->ctrl;

	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, sq->doorbell_cseg);
	sq->doorbell_cseg = NULL;

	msleep(1);

	printk("mlx5e_aso_query_ipsec_aso 002 \n");
	mlx5e_poll_ico_cq(&sq->cq);

	return 0;
}


/*
void mlx5e_build_asosq_param(struct mlx5e_priv *priv,
			     struct mlx5e_sq_param *param)
{
	void *sqc = param->sqc;
	void *wq = MLX5_ADDR_OF(sqc, sqc, wq);

	// To do: have own pd for aso. priv->mdev->mlx5e_res.pdn
	mlx5e_build_sq_param_common(priv, param);

	MLX5_SET(wq, wq, log_wq_sz, ASO_LOG_WQ_SZ);
}

void mlx5e_initialize_asosq(struct mlx5e_priv *priv)
{
	struct mlx5e_aso *aso = &priv->aso;

	aso->cpu = cpumask_first(mlx5_comp_irq_get_affinity_mask(priv->mdev, ASO_CPU_IX));

	mlx5e_build_asosq_param(priv, &aso->param);


}

static void mlx5e_free_asosq_db(struct mlx5e_asosq *sq)
{
	kvfree(sq->db.aso_wqe);
}

static int mlx5e_alloc_asosq_db(struct mlx5e_asosq *sq, int numa)
{
	int wq_sz = mlx5_wq_cyc_get_size(&sq->wq);

	sq->db.aso_wqe = kvzalloc_node(array_size(wq_sz,
						  sizeof(*sq->db.aso_wqe)),
				       GFP_KERNEL, numa);
	if (!sq->db.aso_wqe)
		return -ENOMEM;

	return 0;
}

static int mlx5e_alloc_asosq(struct mlx5e_priv *priv)
{
	struct mlx5e_aso  *aso = &priv->aso;
	struct mlx5e_asosq *sq = &aso->sq;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_sq_param *param = &aso->param;
	void *sqc_wq = MLX5_ADDR_OF(sqc, param->sqc, wq);
	struct mlx5_wq_cyc *wq = &sq->wq;
	int err;

	sq->uar_map = mdev->mlx5e_res.bfreg.map;

	param->wq.db_numa_node = cpu_to_node(aso->cpu);
	err = mlx5_wq_cyc_create(mdev, &param->wq, sqc_wq, wq, &sq->wq_ctrl);
	if (err)
		return err;
	wq->db = &wq->db[MLX5_SND_DBR];

	err = mlx5e_alloc_asosq_db(sq, cpu_to_node(aso->cpu));
	if (err)
		mlx5_wq_destroy(&sq->wq_ctrl);

	return err;
}

static void mlx5e_free_asosq(struct mlx5e_asosq *sq)
{
	mlx5e_free_asosq_db(sq);
	mlx5_wq_destroy(&sq->wq_ctrl);
}

int mlx5e_open_asosq(struct mlx5e_priv *priv)
{
	struct mlx5e_create_sq_param csp = {};
	struct mlx5e_aso *aso = &priv->aso;
	struct mlx5e_sq_param *param = &aso->param;
	struct mlx5e_asosq *sq = &aso->sq;
	int err;

	err = mlx5e_alloc_asosq(priv, param, sq);
	if (err)
		return err;

	csp.cqn             = sq->cq.mcq.cqn;
	csp.wq_ctrl         = &sq->wq_ctrl;
	csp.min_inline_mode = params->tx_min_inline_mode;
	err = mlx5e_create_sq_rdy(c->mdev, param, &csp, &sq->sqn);
	if (err)
		goto err_free_asosq;

	return 0;

err_free_asosq:
	mlx5e_free_asosq(sq);

	return err;
}

void mlx5e_close_asosq(struct mlx5e_priv *priv)
{
	struct mlx5e_asosq *sq = &priv->aso.sq;

	mlx5e_destroy_sq(priv->mdev, sq->sqn);
	mlx5e_free_asosq(sq);
}

static int mlx5e_aso_open_queues(struct mlx5e_priv *priv)
{
	struct dim_cq_moder cq_moder = {0, 0};
	struct mlx5e_aso  *aso = &priv->aso;
	struct mlx5e_asosq *sq = &aso->sq;

	err = mlx5e_open_cq(c, cq_moder, &cparam->asosq_cq, &sq.cq);
	if (err)
		return err;

	printk("mlx5e_aso_open_queues sq->cq.mcq.cqn=0x%x\n", sq->cq.mcq.cqn);

	err = mlx5e_open_asosq(c, params, &cparam->asosq, &c->asosq);
	if (err)
		goto out_sq;

	printk("mlx5e_open_asosq sqn=0x%x\n", sq->sqn);
	return 0;


out_sq:
	mlx5e_close_cq(&sq.cq);
	return err;
}


static int mlx5e_aso_close_queues(struct mlx5e_priv *priv)
{
	struct mlx5e_asosq *sq = &priv->aso.sq;

	mlx5e_close_asosq(sq);
	mlx5e_close_cq(&sq.cq);
}
*/
