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

	aso->ctx = kzalloc(size, GFP_KERNEL);
	if (!aso->ctx)
		return -ENOMEM;

	err = mlx5_core_alloc_pd(mdev, &aso->pdn);
	if (err) {
		mlx5_core_err(mdev, "alloc pd failed, %d\n", err);
		return err;
	}
	mlx5_core_err(mdev, "aso->pdn=0x%x\n", aso->pdn);

	printk("mlx5e_aso_reg_mr size=%d, sizeof(aso->ctx)=%d\n", size, sizeof(aso->ctx));
	dma_addr = dma_map_single(dma_device, aso->ctx, size, DMA_BIDIRECTIONAL);
	err = dma_mapping_error(dma_device, dma_addr);
	if (err) {
		mlx5_core_warn(mdev, "Can't dma ipsec_aso\n");
		goto out_dma;
	}

	/* Huy to do aso_pdn */
	err = mlx5e_aso_create_mkey(mdev, aso->pdn, &aso->mkey);
	if (err) {
		mlx5_core_warn(mdev, "Can't create mkey\n");
		goto out_mkey;
	}

	mlx5_core_err(mdev, "Huy dma_addr=0x%lx, aso->mkey.key=0x%x\n", dma_addr, aso->mkey.key);

	aso->dma_addr = dma_addr;
	aso->size = size;
	return 0;

out_mkey:
	dma_unmap_single(dma_device, dma_addr, size, DMA_BIDIRECTIONAL);

out_dma:
	mlx5_core_dealloc_pd(mdev, aso->pdn);
	kfree(aso->ctx);
	return err;	
}

void mlx5e_aso_dereg_mr(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec_aso *aso = &priv->ipsec->aso;

	mlx5_core_destroy_mkey(priv->mdev, &aso->mkey);
	dma_unmap_single(&priv->mdev->pdev->dev, aso->dma_addr, aso->size, DMA_BIDIRECTIONAL);
	mlx5_core_dealloc_pd(priv->mdev, aso->pdn);
	kfree(aso->ctx);
}

static inline void mlx5e_build_aso_wqe(struct mlx5e_ipsec_aso *aso,
				       struct mlx5e_asosq *sq,
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

	aso_ctrl->va_l  = cpu_to_be32(aso->dma_addr | ASO_CTRL_READ_EN);
	aso_ctrl->va_h  = cpu_to_be32(aso->dma_addr >> 32);
	aso_ctrl->l_key = cpu_to_be32(aso->mkey.key);
	//aso_ctrl->l_key = cpu_to_be32(0);

	printk("aso->dma_addr=0x%lx, aso_ctrl->va_l=0x%x, aso_ctrl->va_h=0x%x\n", aso->dma_addr, aso_ctrl->va_l, aso_ctrl->va_h);
}

void mlx5e_poll_aso_cq(struct mlx5e_cq *cq)
{
	struct mlx5e_asosq *sq = container_of(cq, struct mlx5e_asosq, cq);
	struct mlx5_cqe64 *cqe;
	u16 sqcc;
	int i;

	if (unlikely(!test_bit(MLX5E_SQ_STATE_ENABLED, &sq->state)))
		return;

	cqe = mlx5_cqwq_get_cqe(&cq->wq);
	if (likely(!cqe))
		return;

	/* sq->cc must be updated only after mlx5_cqwq_update_db_record(),
	 * otherwise a cq overrun may occur
	 */
	sqcc = sq->cc;

	printk(KERN_ERR "sq->cc=0x%x\n", sq->cc);

	i = 0;
	do {
		u16 wqe_counter;
		bool last_wqe;

		mlx5_cqwq_pop(&cq->wq);


		wqe_counter = be16_to_cpu(cqe->wqe_counter);
		printk(KERN_ERR "001, wqe_counter=0x%x\n", wqe_counter);

		do {
			struct mlx5e_sq_wqe_info *wi;
			u16 ci;

			last_wqe = (sqcc == wqe_counter);

			ci = mlx5_wq_cyc_ctr2ix(&sq->wq, sqcc);
			wi = &sq->db.aso_wqe[ci];

			printk(KERN_ERR "002, sqcc=0x%x\n", sqcc);

			if (last_wqe && unlikely(get_cqe_opcode(cqe) != MLX5_CQE_REQ)) {
				netdev_WARN_ONCE(cq->channel->netdev,
						 "Bad OP in ICOSQ CQE: 0x%x\n",
						 get_cqe_opcode(cqe));
				//if (!test_and_set_bit(MLX5E_SQ_STATE_RECOVERING, &sq->state))
				//	queue_work(cq->channel->priv->wq, &sq->recover_work);
				printk(KERN_ERR "003, sqcc=0x%x\n", sqcc);
				break;
			}

			if (likely(wi->opcode == MLX5_OPCODE_UMR)) {
				sqcc += MLX5E_UMR_WQEBBS;
				wi->umr.rq->mpwqe.umr_completed++;
			} else if (likely(wi->opcode == MLX5_OPCODE_NOP)) {
				sqcc++;
			} else if (likely(wi->opcode == MLX5_OPCODE_ACCESS_ASO)) {
				sqcc += MLX5E_ASO_WQEBBS;
				printk("Huy ASO completion\n");
			} else {
				netdev_WARN_ONCE(cq->channel->netdev,
						 "Bad OPCODE in ICOSQ WQE info: 0x%x\n",
						 wi->opcode);
			}

			printk(KERN_ERR "003, sqcc=0x%x\n", sqcc);

		} while (!last_wqe);

		printk(KERN_ERR "004, sqcc=0x%x\n", sqcc);

	} while ((++i < MLX5E_TX_CQ_POLL_BUDGET) && (cqe = mlx5_cqwq_get_cqe(&cq->wq)));

	sq->cc = sqcc;

	printk(KERN_ERR "004, sqcc=0x%x\n", sqcc);

	mlx5_cqwq_update_db_record(&cq->wq);
}

void mlx5e_fill_asosq_frag_edge(struct mlx5e_asosq *sq,  struct mlx5_wq_cyc *wq,
				u16 pi, u16 nnops)
{
	struct mlx5e_sq_wqe_info *edge_wi, *wi = &sq->db.aso_wqe[pi];

	edge_wi = wi + nnops;

	/* fill sq frag edge with nops to avoid wqe wrapping two pages */
	for (; wi < edge_wi; wi++) {
		wi->opcode = MLX5_OPCODE_NOP;
		mlx5e_post_nop(wq, sq->sqn, &sq->pc);
	}
}

int mlx5e_aso_query_ipsec_aso(struct mlx5e_priv *priv, u32 ipsec_obj_id)
{
	struct mlx5e_ipsec_aso *aso = &priv->ipsec->aso;
	//struct mlx5e_icosq *sq = &priv->channels.c[0]->icosq;
	struct mlx5e_asosq *sq = &aso->sq;
	struct mlx5_wq_cyc *wq = &sq->wq;
	struct mlx5e_aso_wqe *aso_wqe;
	u16 pi, contig_wqebbs_room;

	printk("mlx5e_aso_query_ipsec_aso\n");

	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	contig_wqebbs_room = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);
	
	if (unlikely(contig_wqebbs_room < MLX5E_ASO_WQEBBS)) {
		mlx5e_fill_asosq_frag_edge(sq, wq, pi, contig_wqebbs_room);
		pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	}

	aso_wqe = mlx5_wq_cyc_get_wqe(wq, pi);
	mlx5e_build_aso_wqe(aso, sq, aso_wqe, ipsec_obj_id);

	sq->db.aso_wqe[pi].opcode = MLX5_OPCODE_ACCESS_ASO;
	sq->pc += MLX5E_ASO_WQEBBS;
	sq->doorbell_cseg = &aso_wqe->ctrl;

	printk(KERN_ERR "mlx5e_aso_query_ipsec_aso 001 \n");

	mlx5e_notify_hw(&sq->wq, sq->pc, sq->uar_map, sq->doorbell_cseg);
	sq->doorbell_cseg = NULL;

	printk(KERN_ERR "mlx5e_aso_query_ipsec_aso 002 \n");

	//msleep(1);

	printk(KERN_ERR "mlx5e_aso_query_ipsec_aso 003 \n");
	mlx5e_poll_aso_cq(&sq->cq);

	printk("MLX5_GET(ipsec_aso, aso_ctx, mode)=0x%x\n", MLX5_GET(ipsec_aso, aso->ctx, mode));
	printk("MLX5_GET(ipsec_aso, aso_ctx, remove_flow_soft_lft)=0x%x\n", MLX5_GET(ipsec_aso, aso->ctx, remove_flow_soft_lft));
	printk("MLX5_GET(ipsec_aso, aso_ctx, remove_flow_pkt_cnt)=0x%x\n", MLX5_GET(ipsec_aso, aso->ctx, remove_flow_pkt_cnt));
	print_hex_dump(KERN_ERR, "ipsec_aso: ", DUMP_PREFIX_ADDRESS, 16, 1, aso->ctx, aso->size, false);

	return 0;
}

void mlx5e_aso_build_cq_param(struct mlx5e_priv *priv,
			      struct mlx5e_cq_param *param)
{
	void *cqc = param->cqc;

	MLX5_SET(cqc, cqc, log_cq_size, 0);

	mlx5e_build_common_cq_param(priv, param);
	param->cq_period_mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
}

void mlx5e_build_asosq_param(struct mlx5e_priv *priv,
			     struct mlx5e_sq_param *param)
{
	void *sqc = param->sqc;
	void *wq = MLX5_ADDR_OF(sqc, sqc, wq);

	// To do: have own pd for aso. priv->mdev->mlx5e_res.pdn
	mlx5e_build_sq_param_common(priv, param);
	MLX5_SET(wq, wq, log_wq_sz, MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE);
}

void mlx5e_aso_build_param(struct mlx5e_priv *priv, struct mlx5e_ipsec_aso *aso)
{
	mlx5e_aso_build_cq_param(priv, &aso->cq_param);

	aso->cpu = cpumask_first(mlx5_comp_irq_get_affinity_mask(priv->mdev, 0));
	mlx5e_build_asosq_param(priv, &aso->sq_param);
}


static int mlx5e_alloc_asosq_db(struct mlx5e_asosq *sq, int numa)
{
	int wq_sz = mlx5_wq_cyc_get_size(&sq->wq);

	printk("mlx5e_alloc_asosq_db wq_sz=%d\n", wq_sz);

	sq->db.aso_wqe = kvzalloc_node(array_size(wq_sz,
						  sizeof(*sq->db.aso_wqe)),
				       GFP_KERNEL, numa);
	if (!sq->db.aso_wqe)
		return -ENOMEM;

	return 0;
}

static int mlx5e_alloc_asosq(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec_aso  *aso = &priv->ipsec->aso;
	struct mlx5e_asosq *sq = &aso->sq;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_sq_param *param = &aso->sq_param;
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

static void mlx5e_free_asosq_db(struct mlx5e_asosq *sq)
{
	kvfree(sq->db.aso_wqe);
}

static void mlx5e_free_asosq(struct mlx5e_asosq *sq)
{
	mlx5e_free_asosq_db(sq);
	mlx5_wq_destroy(&sq->wq_ctrl);
}

int mlx5e_open_asosq(struct mlx5e_priv *priv)
{
	struct mlx5e_create_sq_param csp = {};
	struct mlx5e_ipsec_aso *aso = &priv->ipsec->aso;
	struct mlx5e_sq_param *param = &aso->sq_param;
	struct mlx5e_asosq *sq = &aso->sq;
	int err;

	err = mlx5e_alloc_asosq(priv);
	if (err)
		return err;

	csp.cqn             = sq->cq.mcq.cqn;
	printk("mlx5e_open_asosq csp.cqn=0x%x\n", csp.cqn);
	csp.wq_ctrl         = &sq->wq_ctrl;
	csp.min_inline_mode = MLX5_INLINE_MODE_NONE;
	err = mlx5e_create_sq_rdy(priv->mdev, param, &csp, &sq->sqn);
	if (err)
		goto err_free_asosq;

	set_bit(MLX5E_SQ_STATE_ENABLED, &sq->state);
	printk("mlx5e_open_asosq sqn=0x%x\n", sq->sqn);

	return 0;

err_free_asosq:
	mlx5e_free_asosq(sq);

	return err;
}

void mlx5e_close_asosq(struct mlx5e_priv *priv)
{
	struct mlx5e_asosq *sq = &priv->ipsec->aso.sq;

	clear_bit(MLX5E_SQ_STATE_ENABLED, &sq->state);
	mlx5e_destroy_sq(priv->mdev, sq->sqn);
	mlx5e_free_asosq(sq);
}

void mlx5e_aso_setup(struct mlx5e_priv *priv, struct mlx5e_channel *c)
{
	struct dim_cq_moder icocq_moder = {0, 0};
	struct mlx5e_ipsec_aso *aso;
	int err;

	/* Huy to do check cap */
	if (!priv->ipsec)
		return;

	aso = &priv->ipsec->aso;

	mlx5e_aso_build_param(priv, aso);


	aso->sq.cq.is_aso = true;	
	err = mlx5e_open_cq(c, icocq_moder, &aso->cq_param, &aso->sq.cq);
	if (err)
		return;

	/* Huy To do Skip cq arm */
	printk("aso->sq.cq.mcq.cqn=0x%x\n", aso->sq.cq.mcq.cqn);

	mlx5e_open_asosq(priv);
}

void mlx5e_aso_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_ipsec_aso *aso;

	if (!priv->ipsec)
		return;

	mlx5e_close_asosq(priv);

	aso = &priv->ipsec->aso;
	mlx5e_close_cq(&aso->sq.cq);
}
