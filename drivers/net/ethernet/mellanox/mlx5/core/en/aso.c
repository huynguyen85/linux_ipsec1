#include "aso.h"

void mlx5e_build_asosq_param(struct mlx5e_priv *priv,
			     struct mlx5e_sq_param *param)
{
	void *sqc = param->sqc;
	void *wq = MLX5_ADDR_OF(sqc, sqc, wq);

	/* To do: have own pd for aso. priv->mdev->mlx5e_res.pdn */
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
