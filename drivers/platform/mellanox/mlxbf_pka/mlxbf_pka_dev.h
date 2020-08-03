/* SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#ifndef __MLXBF_PKA_DEV_H__
#define __MLXBF_PKA_DEV_H__

#include <linux/types.h>
#include <linux/vfio.h>

#include "mlxbf_pka_config.h"
#include "mlxbf_pka_cpu.h"
#include "mlxbf_pka_debug.h"
#include "mlxbf_pka_firmware.h"
#include "mlxbf_pka_ioctl.h"
#include "mlxbf_pka_mmio.h"
#include "mlxbf_pka_ring.h"

/**
 * mlxbf_pka_dev_res_t - PKA Device resource structure
 * @ioaddr: (iore)map-ped version of addr, for driver internal use
 * @base: base address of the device's resource
 * @size: size of IO
 * @type: type of resource addr points to
 * @status: status of the resource
 * @name: name of the resource
 */
struct mlxbf_pka_dev_res_t {
	void __iomem *ioaddr;
	u64 base;
	u64 size;
	u8 type;
	s8 status;
	char *name;
};

/* defines for mlxbf_pka_dev_res->type */
#define MLXBF_PKA_DEV_RES_TYPE_MEM 1
#define MLXBF_PKA_DEV_RES_TYPE_REG 2

/* defines for mlxbf_pka_dev_res->status */
#define MLXBF_PKA_DEV_RES_STATUS_MAPPED 1
#define MLXBF_PKA_DEV_RES_STATUS_UNMAPPED -1

/**
 * mlxbf_pka_dev_ring_res_t - PKA Ring resources structure
 * @info_words
 * @counters
 * @window_ram
 */
struct mlxbf_pka_dev_ring_res_t {
	struct mlxbf_pka_dev_res_t info_words;
	struct mlxbf_pka_dev_res_t counters;
	struct mlxbf_pka_dev_res_t window_ram;
};

/**
 * mlxbf_pka_dev_ring_t - PKA Ring structure
 * @rind_id
 * @shim
 * @resources_num
 * @resources
 * @ring_info
 * @num_cmd_desc
 * @status
 */
struct mlxbf_pka_dev_ring_t {
	u32 ring_id;
	struct mlxbf_pka_dev_shim_t *shim;
	u32 resources_num;
	struct mlxbf_pka_dev_ring_res_t resources;
	struct mlxbf_pka_dev_hw_ring_info_t *ring_info;
	u32 num_cmd_desc;
	s8 status;
};

/* defines for mlxbf_pka_dev_ring->status */
#define MLXBF_PKA_DEV_RING_STATUS_UNDEFINED -1
#define MLXBF_PKA_DEV_RING_STATUS_INITIALIZED 1
#define MLXBF_PKA_DEV_RING_STATUS_READY 2
#define MLXBF_PKA_DEV_RING_STATUS_BUSY 3
#define MLXBF_PKA_DEV_RING_STATUS_FINALIZED 4

/**
 * mlxbf_pka_dev_shim_res_t - PKA Shim resources structure
 * @buffer_ram
 * @master_prog_ram
 * @master_seq_ctrl
 * @aic_csr
 * @trng_csr
 */
struct mlxbf_pka_dev_shim_res_t {
	struct mlxbf_pka_dev_res_t buffer_ram;
	struct mlxbf_pka_dev_res_t master_prog_ram;
	struct mlxbf_pka_dev_res_t master_seq_ctrl;
	struct mlxbf_pka_dev_res_t aic_csr;
	struct mlxbf_pka_dev_res_t trng_csr;
};

#define MLXBF_PKA_DEV_SHIM_RES_CNT 5 /* Number of PKA device resources */

/**
 * mlxbf_pka_dev_gbl_shim_res_info_t - Platform shim resource structure
 * @res_tbl
 * @res_cnt
 */
struct mlxbf_pka_dev_gbl_shim_res_info_t {
	struct mlxbf_pka_dev_res_t *res_tbl[MLXBF_PKA_DEV_SHIM_RES_CNT];
	u8 res_cnt;
};

/**
 * mlxbf_pka_dev_shim_t - PKA Shim structure
 * @base
 * @size
 * @trng_err_cycle
 * @shim_id
 * @rings_num
 * @rings
 * @rings_priority: priority through which rings are handled
 * @ring_type: indicates if the ring delivers results strictly in-order
 * @window_ram_split: if non-zero, the split window RAM scheme is used
 * @busy_ring_num
 * @trng_enabled
 * @status
 */
struct mlxbf_pka_dev_shim_t {
	u64 base;
	u64 size;
	u64 trng_err_cycle;
	u32 shim_id;
	u32 rings_num;
	struct mlxbf_pka_dev_ring_t **rings;
	u8 ring_priority;
	u8 ring_type;
	struct mlxbf_pka_dev_shim_res_t resources;
	u8 window_ram_split;
	u32 busy_ring_num;
	u8 trng_enabled;
	s8 status;
};

/* defines for mlxbf_pka_dev_shim->status */
#define MLXBF_PKA_SHIM_STATUS_UNDEFINED -1
#define MLXBF_PKA_SHIM_STATUS_CREATED 1
#define MLXBF_PKA_SHIM_STATUS_INITIALIZED 2
#define MLXBF_PKA_SHIM_STATUS_RUNNING 3
#define MLXBF_PKA_SHIM_STATUS_STOPPED 4
#define MLXBF_PKA_SHIM_STATUS_FINALIZED 5

/* defines for mlxbf_pka_dev_shim->window_ram_split */
/* window RAM is split into 4x16KB blocks */
#define MLXBF_PKA_SHIM_WINDOW_RAM_SPLIT_ENABLED 1
/* window RAM is not split and occupies 64KB */
#define MLXBF_PKA_SHIM_WINDOW_RAM_SPLIT_DISABLED 2

/* defines for mlxbf_pka_dev_shim->trng_enabled */
#define MLXBF_PKA_SHIM_TRNG_ENABLED 1
#define MLXBF_PKA_SHIM_TRNG_DISABLED 0

/**
 * mlxbf_pka_dev_gbl_config_t - Platform global configuration structure
 * @dev_shims_cnt
 * @dev_rings_cnt
 * @dev_shims
 * @dev_rings
 */
struct mlxbf_pka_dev_gbl_config_t {
	u32 dev_shims_cnt;
	u32 dev_rings_cnt;
	struct mlxbf_pka_dev_shim_t *dev_shims[MLXBF_PKA_MAX_NUM_IO_BLOCKS];
	struct mlxbf_pka_dev_ring_t *dev_rings[MLXBF_PKA_MAX_NUM_RINGS];
};

extern struct mlxbf_pka_dev_gbl_config_t mlxbf_pka_gbl_config;

/*
 * Ring getter for mlxbf_pka_dev_gbl_config_t structure which holds all system
 * global configuration. This configuration is shared and common to kernel
 * device driver associated with PKA hardware.
 */
inline struct mlxbf_pka_dev_ring_t *mlxbf_pka_dev_get_ring(u32 ring_id);

/*
 * Shim getter for mlxbf_pka_dev_gbl_config_t structure which holds all system
 * global configuration. This configuration is shared and common to kernel
 * device driver associated with PKA hardware.
 */
inline struct mlxbf_pka_dev_shim_t *mlxbf_pka_dev_get_shim(u32 shim_id);

/*
 * Register a Ring. This function initializes a Ring and configures its
 * related resources, and returns a pointer to that ring.
 */
struct mlxbf_pka_dev_ring_t *mlxbf_pka_dev_register_ring(u32 ring_id,
							 u32 shim_id);

/* Unregister a Ring. */
int mlxbf_pka_dev_unregister_ring(struct mlxbf_pka_dev_ring_t *ring);

/*
 * Register PKA IO block. This function initializes a shim and configures its
 * related resources, and returns a pointer to that ring.
 */
struct mlxbf_pka_dev_shim_t *mlxbf_pka_dev_register_shim(u32 shim_id,
							 u64 shim_base,
							 u64 shim_size,
							 u8 shim_fw_id);

/* Unregister PKA IO block. */
int mlxbf_pka_dev_unregister_shim(struct mlxbf_pka_dev_shim_t *shim);

/* Reset a Ring. */
int mlxbf_pka_dev_reset_ring(struct mlxbf_pka_dev_ring_t *ring);

/*
 * Read data from the TRNG. Drivers can fill up to 'cnt' bytes of data into
 * the buffer 'data'. The buffer 'data' is aligned for any type and 'cnt' is
 * a multiple of 4.
 */
int mlxbf_pka_dev_trng_read(struct mlxbf_pka_dev_shim_t *shim, u32 *data,
			    u32 cnt);

/* Return true if the TRNG engine is enabled, false if not. */
bool mlxbf_pka_dev_has_trng(struct mlxbf_pka_dev_shim_t *shim);

/*
 * Open the file descriptor associated with ring. It returns an integer value,
 * which is used to refer to the file. If un-successful, it returns a negative
 * error.
 */
int mlxbf_pka_dev_open_ring(u32 ring_id);

/*
 * Close the file descriptor associated with ring. The function returns 0 if
 * successful, negative value to indicate an error.
 */
int mlxbf_pka_dev_close_ring(u32 ring_id);

#endif /* __MLXBF_PKA_DEV_H__ */
