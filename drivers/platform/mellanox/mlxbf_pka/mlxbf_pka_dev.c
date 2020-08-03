// SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB

/*
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timex.h>
#include <linux/vfio.h>
#include "mlxbf_pka_dev.h"

#define MLXBF_PKA_BYTES_PER_WORD 4
#define MLXBF_PKA_BYTES_PER_DOUBLE_WORD 8

#define MLXBF_PKA_KILO_100 100000
#define MLXBF_PKA_GIGA 1000000000

#define MLXBF_PKA_BYTE_OFFSET BIT(3)
#define MLXBF_PKA_BIT_RING_ORDER BIT(0)
#define MLXBF_PKA_MASK_LEAST_BYTE GENMASK(7, 0)
#define MLXBF_PKA_MASK_HOST_DESC GENMASK(9, 0)
#define MLXBF_PKA_MASK_NUM_CMD_DESC GENMASK(15, 0)
#define MLXBF_PKA_MASK_NUM_RINGS GENMASK(15, 8)
#define MLXBF_PKA_MASK_RING_SIGN GENMASK(31, 24)

struct mlxbf_pka_dev_gbl_config_t mlxbf_pka_gbl_config;

/* Global PKA shim resource info table */
static struct mlxbf_pka_dev_gbl_shim_res_info_t
	mlxbf_pka_gbl_res_tbl[MLXBF_PKA_MAX_NUM_IO_BLOCKS];

/* Start a PKA device timer. */
static u64 mlxbf_pka_dev_timer_start(u32 usec)
{
	u64 cur_time = get_cycles();

	return (cur_time +
		(mlxbf_pka_early_cpu_speed() * usec) / MLXBF_PKA_MEGA);
}

/* Test a PKA device timer for completion. */
static int mlxbf_pka_dev_timer_done(u64 timer)
{
	return (get_cycles() >= timer);
}

/* Return register base address */
static u64 mlxbf_pka_dev_get_register_base(u64 base, u64 reg_addr)
{
	return (base + reg_addr) & PAGE_MASK;
}

/* Return register offset */
static u64 mlxbf_pka_dev_get_register_offset(u64 base, u64 reg_addr)
{
	return (base + reg_addr) & ~PAGE_MASK;
}

/* Return word offset within io memory */
static u64 mlxbf_pka_dev_get_word_offset(u64 mem_base, u64 word_addr,
					 u64 mem_size)
{
	return (mem_base + word_addr) & (mem_size - 1);
}

static u64 mlxbf_pka_dev_io_read(void __iomem *mem_ptr, u64 mem_off)
{
	u64 data;

	data = mlxbf_pka_mmio_read(mem_ptr + mem_off);

	return data;
}

static void mlxbf_pka_dev_io_write(void __iomem *mem_ptr, u64 mem_off,
				   u64 value)
{
	mlxbf_pka_mmio_write(mem_ptr + mem_off, value);
}

/* Add the resource to the global resource table */
static int mlxbf_pka_dev_add_resource(struct mlxbf_pka_dev_res_t *res_ptr,
				      u32 shim_idx)
{
	u8 res_cnt;

	res_cnt = mlxbf_pka_gbl_res_tbl[shim_idx].res_cnt;

	if (res_cnt >= MLXBF_PKA_DEV_SHIM_RES_CNT)
		return -ENOMEM;

	mlxbf_pka_gbl_res_tbl[shim_idx].res_tbl[res_cnt] = res_ptr;
	mlxbf_pka_gbl_res_tbl[shim_idx].res_cnt++;

	return 0;
}

/* Remove the resource from the global resource table */
static int mlxbf_pka_dev_put_resource(struct mlxbf_pka_dev_res_t *res,
				      u32 shim_idx)
{
	struct mlxbf_pka_dev_res_t *res_ptr;
	u8 res_idx;

	for (res_idx = 0; res_idx < MLXBF_PKA_DEV_SHIM_RES_CNT; res_idx++) {
		res_ptr = mlxbf_pka_gbl_res_tbl[shim_idx].res_tbl[res_idx];
		if (res_ptr && !strcmp(res_ptr->name, res->name)) {
			mlxbf_pka_gbl_res_tbl[shim_idx].res_tbl[res_idx] = NULL;
			mlxbf_pka_gbl_res_tbl[shim_idx].res_cnt--;
			break;
		}
	}

	/*
	 * Check whether the resource shares the same memory map; If so,
	 * the memory map shouldn't be released.
	 */
	for (res_idx = 0; res_idx < MLXBF_PKA_DEV_SHIM_RES_CNT; res_idx++) {
		res_ptr = mlxbf_pka_gbl_res_tbl[shim_idx].res_tbl[res_idx];
		if (res_ptr && res_ptr->base == res->base)
			return -EBUSY;
	}

	return 0;
}

static void __iomem *mlxbf_pka_dev_get_resource_ioaddr(u64 res_base,
						       u32 shim_idx)
{
	struct mlxbf_pka_dev_res_t *res_ptr;
	u8 res_cnt, res_idx;

	res_cnt = mlxbf_pka_gbl_res_tbl[shim_idx].res_cnt;

	if (!res_cnt)
		return NULL;

	for (res_idx = 0; res_idx < res_cnt; res_idx++) {
		res_ptr = mlxbf_pka_gbl_res_tbl[shim_idx].res_tbl[res_idx];
		if (res_ptr->base == res_base)
			return res_ptr->ioaddr;
	}

	return NULL;
}

/* Set PKA device resource config - - map io memory if needed. */
static int mlxbf_pka_dev_set_resource_config(
	struct mlxbf_pka_dev_shim_t *shim, struct mlxbf_pka_dev_res_t *res_ptr,
	u64 res_base, u64 res_size, u64 res_type, char *res_name)
{
	if (res_ptr->status == MLXBF_PKA_DEV_RES_STATUS_MAPPED)
		return -EPERM;

	/*
	 * res_type is either MLXBF_PKA_DEV_RES_TYPE_REG or
	 * MLXBF_PKA_DEV_RES_TYPE_MEM
	 */
	if (res_type == MLXBF_PKA_DEV_RES_TYPE_REG)
		res_ptr->base = res_base;
	else
		res_ptr->base = shim->base + res_base;

	res_ptr->size = res_size;
	res_ptr->type = res_type;
	res_ptr->name = res_name;
	res_ptr->status = MLXBF_PKA_DEV_RES_STATUS_UNMAPPED;
	res_ptr->ioaddr =
		mlxbf_pka_dev_get_resource_ioaddr(res_ptr->base, shim->shim_id);
	if (!res_ptr->ioaddr) {
		if (!request_mem_region(res_ptr->base, res_ptr->size,
					res_ptr->name)) {
			MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
					"failed to get io memory region\n");
			return -EPERM;
		}

		res_ptr->ioaddr = ioremap_nocache(res_ptr->base, res_ptr->size);
	}

	res_ptr->status = MLXBF_PKA_DEV_RES_STATUS_MAPPED;

	if (!res_ptr->ioaddr ||
	    mlxbf_pka_dev_add_resource(res_ptr, shim->shim_id)) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "unable to map io memory\n");
		release_mem_region(res_ptr->base, res_ptr->size);
		return -ENOMEM;
	}
	return 0;
}

/* Unset PKA device resource config - unmap io memory if needed. */
static void
mlxbf_pka_dev_unset_resource_config(struct mlxbf_pka_dev_shim_t *shim,
				    struct mlxbf_pka_dev_res_t *res_ptr)
{
	if (res_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED)
		return;

	if (res_ptr->ioaddr &&
	    mlxbf_pka_dev_put_resource(res_ptr, shim->shim_id) != -EBUSY) {
		iounmap(res_ptr->ioaddr);
		release_mem_region(res_ptr->base, res_ptr->size);
	}

	res_ptr->status = MLXBF_PKA_DEV_RES_STATUS_UNMAPPED;
}

/*
 * Initialize ring. Set ring parameters and configure ring resources.
 * It returns 0 on success, a negative error code on failure.
 */
static int mlxbf_pka_dev_init_ring(struct mlxbf_pka_dev_ring_t *ring,
				   u32 ring_id,
				   struct mlxbf_pka_dev_shim_t *shim)
{
	struct mlxbf_pka_dev_res_t *ring_info_words_ptr;
	struct mlxbf_pka_dev_res_t *ring_window_ram_ptr;
	struct mlxbf_pka_dev_res_t *ring_counters_ptr;
	u8 window_ram_split;
	u32 ring_words_off;
	u32 ring_cntrs_off;
	u32 ring_mem_base;
	u32 ring_mem_size;
	u32 ring_mem_off;
	u32 shim_ring_id;

	if (ring->status != MLXBF_PKA_DEV_RING_STATUS_UNDEFINED) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "MLXBF_PKA ring is undefined\n");
		return -EPERM;
	}

	if (ring_id > MLXBF_PKA_MAX_NUM_RINGS - 1) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "invalid ring identifier\n");
		return -EINVAL;
	}

	ring->ring_id = ring_id;
	ring->shim = shim;
	ring->resources_num = MLXBF_PKA_MAX_NUM_RING_RESOURCES;

	shim_ring_id = ring_id % MLXBF_PKA_MAX_NUM_IO_BLOCK_RINGS;
	shim->rings[shim_ring_id] = ring;

	/* Configure ring information control/status words resource */
	ring_info_words_ptr = &ring->resources.info_words;
	ring_words_off = shim_ring_id * MLXBF_PKA_RING_WORDS_SPACING;
	ring_info_words_ptr->base = ring_words_off + MLXBF_PKA_RING_WORDS_ADDR;
	ring_info_words_ptr->size = MLXBF_PKA_RING_WORDS_SIZE;
	ring_info_words_ptr->type = MLXBF_PKA_DEV_RES_TYPE_MEM;
	ring_info_words_ptr->status = MLXBF_PKA_DEV_RES_STATUS_UNMAPPED;
	ring_info_words_ptr->name = "MLXBF_PKA_RING_INFO";

	/* Configure ring counters registers resource */
	ring_counters_ptr = &ring->resources.counters;
	ring_cntrs_off = shim_ring_id * MLXBF_PKA_RING_CNTRS_SPACING;
	ring_counters_ptr->base = ring_cntrs_off + MLXBF_PKA_RING_CNTRS_ADDR;
	ring_counters_ptr->size = MLXBF_PKA_RING_CNTRS_SIZE;
	ring_counters_ptr->type = MLXBF_PKA_DEV_RES_TYPE_REG;
	ring_counters_ptr->status = MLXBF_PKA_DEV_RES_STATUS_UNMAPPED;
	ring_counters_ptr->name = "MLXBF_PKA_RING_CNTRS";

	/* Configure ring window RAM resource */
	window_ram_split = shim->window_ram_split;
	if (window_ram_split == MLXBF_PKA_SHIM_WINDOW_RAM_SPLIT_ENABLED) {
		ring_mem_off = shim_ring_id * MLXBF_PKA_RING_MEM_1_SPACING;
		ring_mem_base = ring_mem_off + MLXBF_PKA_RING_MEM_1_BASE;
		ring_mem_size = MLXBF_PKA_RING_MEM_1_SIZE;
	} else {
		ring_mem_off = shim_ring_id * MLXBF_PKA_RING_MEM_0_SPACING;
		ring_mem_base = ring_mem_off + MLXBF_PKA_RING_MEM_0_BASE;
		ring_mem_size = MLXBF_PKA_RING_MEM_0_SIZE;
	}

	ring_window_ram_ptr = &ring->resources.window_ram;
	ring_window_ram_ptr->base = ring_mem_base;
	ring_window_ram_ptr->size = ring_mem_size;
	ring_window_ram_ptr->type = MLXBF_PKA_DEV_RES_TYPE_MEM;
	ring_window_ram_ptr->status = MLXBF_PKA_DEV_RES_STATUS_UNMAPPED;
	ring_window_ram_ptr->name = "MLXBF_PKA_RING_WINDOW";

	ring->ring_info = kzalloc(sizeof(struct mlxbf_pka_dev_hw_ring_info_t),
				  GFP_KERNEL);
	if (!ring->ring_info) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "unable to kmalloc\n");
		kfree(ring->ring_info);
		return -ENOMEM;
	}

	ring->status = MLXBF_PKA_DEV_RING_STATUS_INITIALIZED;

	return 0;
}

/* Release a given Ring. */
static int mlxbf_pka_dev_release_ring(struct mlxbf_pka_dev_ring_t *ring)
{
	struct mlxbf_pka_dev_shim_t *shim;
	u32 shim_ring_id;

	if (ring->status == MLXBF_PKA_DEV_RING_STATUS_UNDEFINED)
		return 0;

	if (ring->status == MLXBF_PKA_DEV_RING_STATUS_BUSY) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "MLXBF_PKA ring is busy\n");
		return -EBUSY;
	}

	shim = ring->shim;

	if (shim->status == MLXBF_PKA_SHIM_STATUS_RUNNING) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "MLXBF_PKA shim is running\n");
		return -EPERM;
	}

	mlxbf_pka_dev_unset_resource_config(shim, &ring->resources.info_words);
	mlxbf_pka_dev_unset_resource_config(shim, &ring->resources.counters);
	mlxbf_pka_dev_unset_resource_config(shim, &ring->resources.window_ram);

	kfree(ring->ring_info);

	ring->status = MLXBF_PKA_DEV_RING_STATUS_UNDEFINED;
	shim_ring_id = ring->ring_id % MLXBF_PKA_MAX_NUM_IO_BLOCK_RINGS;
	shim->rings[shim_ring_id] = NULL;
	shim->rings_num--;

	return 0;
}

/*
 * Partition the window RAM for a given PKA ring.  Here we statically divide
 * the 16K memory region into three partitions:  First partition is reserved
 * for command descriptor ring (1K), second partition is reserved for result
 * descriptor ring (1K), and the remaining 14K are reserved for vector data.
 * Through this memroy partition scheme, command/result descriptor rings hold
 * a total of 1KB/64B = 16 descriptors each. The addresses for the rings start
 * at offset 0x3800.  Also note that it is possible to have rings full while
 * the vector data can support more data,  the opposite can also happen, but
 * it is not suitable. For instance ECC point multiplication requires 8 input
 * vectors and 2 output vectors, a total of 10 vectors. If each vector has a
 * length of 24 words (24x4B = 96B), we can process 14KB/960B = 14 operations
 * which is close to 16 the total descriptors supported by rings. On the other
 * hand, using 12K vector data region, allows to process only 12 operations,
 * while rings can hold 32 descriptors (ring usage is significantly low).
 * For ECDSA verify, we have 12 vectors which require 1152B, with 14KB we can
 * handle 12 operations, against 10 operations with 12KB vector data memory.
 * We believe that the aformentionned memory partition help us to leverage
 * the trade-off between supported descriptors and required vectors. Note
 * that these examples gives approximative values and does not include buffer
 * word padding across vectors.
 *
 * The function also writes the result descriptor rings base addresses, size
 * and type, and initialize the read and write pointers and statistics. It
 * returns 0 on success, a negative error code on failure.
 *
 * This function must be called once per ring, at initialization before any
 * other fonctions are called.
 */
static int mlxbf_pka_dev_partition_mem(struct mlxbf_pka_dev_ring_t *ring)
{
	struct mlxbf_pka_dev_hw_ring_info_t *ring_info;
	struct mlxbf_pka_dev_shim_t *shim;
	u64 rslt_desc_ring_base;
	u32 rslt_desc_ring_size;
	u64 cmd_desc_ring_base;
	u32 cmd_desc_ring_size;
	u64 window_ram_base;
	u64 window_ram_size;
	u16 host_desc_size;
	u32 ring_mem_base;
	u32 ring_mem_size;
	u32 data_mem_base;
	u32 data_mem_size;
	u16 num_cmd_desc;
	u8 ring_in_order;

	shim = ring->shim;

	if (!ring->shim ||
	    ring->status != MLXBF_PKA_DEV_RING_STATUS_INITIALIZED)
		return -EPERM;

	ring_in_order = shim->ring_type;
	window_ram_base = ring->resources.window_ram.base;
	window_ram_size = ring->resources.window_ram.size;
	/*
	 * Partition ring memory.  Give ring pair (cmmd descriptor ring and rslt
	 * descriptor ring) an equal portion of the memory.  The cmmd descriptor
	 * ring and result descriptor ring are used as "non-overlapping" ring.
	 * Currently set aside 1/8 of the window RAM for command/result
	 * descriptor rings - giving a total of 1K/64B = 16 descriptors per
	 * ring. The remaining memory is "Data Memory" - i.e. memory to hold
	 * the command operands and results - also called input/output vectors
	 * (in all cases these vectors are just single large integers - often
	 * in the range of hundreds to thousands of bits long).
	 */
	ring_mem_size = MLXBF_PKA_WINDOW_RAM_RING_MEM_SIZE / 2;
	data_mem_size = MLXBF_PKA_WINDOW_RAM_DATA_MEM_SIZE;
	data_mem_base = window_ram_base;
	ring_mem_base = data_mem_base + data_mem_size;

	num_cmd_desc = ring_mem_size / MLXBF_PKA_CMD_DESC_SIZE;
	host_desc_size = MLXBF_PKA_CMD_DESC_SIZE / MLXBF_PKA_BYTES_PER_WORD;

	cmd_desc_ring_size = num_cmd_desc * MLXBF_PKA_CMD_DESC_SIZE;
	rslt_desc_ring_size = cmd_desc_ring_size;

	ring->num_cmd_desc = num_cmd_desc;

	/*
	 * The command and result descriptor rings may be placed at different
	 * (non-overlapping) locations in Window RAM memory space. PKI command
	 * interface: Most of the functionality is defined by the EIP-154 master
	 * firmware on the EIP-154 master controller Sequencer.
	 */
	cmd_desc_ring_base = ring_mem_base;
	rslt_desc_ring_base = ring_mem_base + rslt_desc_ring_size;

	cmd_desc_ring_base =
		MLXBF_PKA_RING_MEM_ADDR(cmd_desc_ring_base, window_ram_size);
	rslt_desc_ring_base =
		MLXBF_PKA_RING_MEM_ADDR(rslt_desc_ring_base, window_ram_size);

	ring_info = ring->ring_info;
	/* Fill ring information. */
	ring_info->cmmd_base = cmd_desc_ring_base;
	ring_info->rslt_base = rslt_desc_ring_base;
	ring_info->size = num_cmd_desc - 1;
	ring_info->host_desc_size = host_desc_size;
	ring_info->in_order = ring_in_order;
	ring_info->cmmd_rd_ptr = 0x0;
	ring_info->rslt_wr_ptr = 0x0;
	ring_info->cmmd_rd_stats = 0x0;
	ring_info->rslt_wr_stats = 0x0;

	return 0;
}

/*
 * Write the ring base address, ring size and type, and initialize (clear)
 * the read and write pointers and statistics.
 */
static int
mlxbf_pka_dev_write_ring_info(struct mlxbf_pka_dev_res_t *buffer_ram_ptr,
			      u8 ring_id, u32 ring_cmmd_base_val,
			      u32 ring_rslt_base_val, u32 ring_size_type_val)
{
	u32 ring_spacing;
	u64 word_off;

	if (buffer_ram_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED ||
	    buffer_ram_ptr->type != MLXBF_PKA_DEV_RES_TYPE_MEM)
		return -EPERM;

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
			"Writing ring information control/status words\n");

	ring_spacing = ring_id * MLXBF_PKA_RING_WORDS_SPACING;

	/*
	 * Write the command ring base address  that  the  EIP-154
	 * master firmware uses with the command ring read pointer
	 * to get command descriptors from the Host ring. After the
	 * initialization, although the word is writeable it should
	 * be regarded as read-only.
	 */
	word_off = mlxbf_pka_dev_get_word_offset(
		buffer_ram_ptr->base,
		MLXBF_PKA_RING_CMMD_BASE_0_ADDR + ring_spacing,
		MLXBF_PKA_BUFFER_RAM_SIZE);
	mlxbf_pka_dev_io_write(buffer_ram_ptr->ioaddr, word_off,
			       ring_cmmd_base_val);

	/*
	 * Write the result  ring base address  that  the  EIP-154
	 * master firmware uses with the result ring write pointer
	 * to put the result descriptors in the Host ring.   After
	 * the initialization,  although the word is writeable  it
	 * should be regarded as read-only.
	 */
	word_off = mlxbf_pka_dev_get_word_offset(
		buffer_ram_ptr->base,
		MLXBF_PKA_RING_RSLT_BASE_0_ADDR + ring_spacing,
		MLXBF_PKA_BUFFER_RAM_SIZE);
	mlxbf_pka_dev_io_write(buffer_ram_ptr->ioaddr, word_off,
			       ring_rslt_base_val);

	/*
	 * Write the ring size (number of descriptors), the size of
	 * the descriptor and the result reporting scheme. After the
	 * initialization,  although the word is writeable it should
	 * be regarded as read-only.
	 */
	word_off = mlxbf_pka_dev_get_word_offset(
		buffer_ram_ptr->base,
		MLXBF_PKA_RING_SIZE_TYPE_0_ADDR + ring_spacing,
		MLXBF_PKA_BUFFER_RAM_SIZE);
	mlxbf_pka_dev_io_write(buffer_ram_ptr->ioaddr, word_off,
			       ring_size_type_val);

	/*
	 * Write the command and result ring indices that the  EIP-154
	 * master firmware uses. This word should be written with zero
	 * when the ring information is initialized.  After the
	 * initialization, although the word is writeable it should be
	 * regarded as read-only.
	 */
	word_off = mlxbf_pka_dev_get_word_offset(buffer_ram_ptr->base,
						 MLXBF_PKA_RING_RW_PTRS_0_ADDR +
							 ring_spacing,
						 MLXBF_PKA_BUFFER_RAM_SIZE);
	mlxbf_pka_dev_io_write(buffer_ram_ptr->ioaddr, word_off, 0);

	/*
	 * Write the ring statistics   (two 16-bit counters,  one for
	 * commands and one for results) from EIP-154 master firmware
	 * point of view.  This word should be written with zero when
	 * the ring information is initialized.  After the initializa-
	 * -tion, although the word is writeable it should be regarded
	 * as read-only.
	 */
	word_off = mlxbf_pka_dev_get_word_offset(buffer_ram_ptr->base,
						 MLXBF_PKA_RING_RW_STAT_0_ADDR +
							 ring_spacing,
						 MLXBF_PKA_BUFFER_RAM_SIZE);
	mlxbf_pka_dev_io_write(buffer_ram_ptr->ioaddr, word_off, 0);

	return 0;
}

/*
 * Set up the control/status words. Upon a PKI command the EIP-154 master
 * firmware will read and partially update the ring information.
 */
static int mlxbf_pka_dev_set_ring_info(struct mlxbf_pka_dev_ring_t *ring)
{
	struct mlxbf_pka_dev_hw_ring_info_t *ring_info;
	struct mlxbf_pka_dev_res_t *buffer_ram_ptr;
	struct mlxbf_pka_dev_shim_t *shim;
	u32 ring_cmmd_base_val;
	u32 ring_rslt_base_val;
	u32 ring_size_type_val;
	u8 ring_id;
	int ret;

	shim = ring->shim;
	/*
	 * Ring info configuration MUST be done when the PKA ring
	 * is initilaized.
	 */
	if ((shim->status != MLXBF_PKA_SHIM_STATUS_INITIALIZED &&
	     shim->status != MLXBF_PKA_SHIM_STATUS_RUNNING &&
	     shim->status != MLXBF_PKA_SHIM_STATUS_STOPPED) ||
	    ring->status != MLXBF_PKA_DEV_RING_STATUS_INITIALIZED)
		return -EPERM;

	ring_id = ring->ring_id % MLXBF_PKA_MAX_NUM_IO_BLOCK_RINGS;

	/* Partition ring memory. */
	ret = mlxbf_pka_dev_partition_mem(ring);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"failed to initialize ring memory\n");
		return ret;
	}

	/* Fill ring information. */
	ring_info = ring->ring_info;

	ring_cmmd_base_val = ring_info->cmmd_base;
	ring_rslt_base_val = ring_info->rslt_base;

	ring_size_type_val =
		(ring_info->in_order & MLXBF_PKA_BIT_RING_ORDER) << 31;
	ring_size_type_val |=
		(ring_info->host_desc_size & MLXBF_PKA_MASK_HOST_DESC) << 18;
	ring_size_type_val |=
		(ring->num_cmd_desc - 1) & MLXBF_PKA_MASK_NUM_CMD_DESC;

	buffer_ram_ptr = &shim->resources.buffer_ram;
	/* Write ring information status/control words in the PKA Buffer RAM */
	ret = mlxbf_pka_dev_write_ring_info(buffer_ram_ptr, ring_id,
					    ring_cmmd_base_val,
					    ring_rslt_base_val,
					    ring_size_type_val);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"failed to write ring information\n");
		return ret;
	}

	ring->status = MLXBF_PKA_DEV_RING_STATUS_READY;

	return ret;
}

/*
 * Create shim. Set shim parameters and configure shim resources.
 * It returns 0 on success, a negative error code on failure.
 */
static int mlxbf_pka_dev_create_shim(struct mlxbf_pka_dev_shim_t *shim,
				     u32 shim_id, u64 shim_base, u64 shim_size,
				     u8 split)
{
	u64 reg_base;
	u64 reg_size;
	int ret = 0;

	if (shim->status == MLXBF_PKA_SHIM_STATUS_CREATED)
		return ret;

	if (shim->status != MLXBF_PKA_SHIM_STATUS_UNDEFINED) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"MLXBF_PKA device must be undefined\n");
		return -EPERM;
	}

	if (shim_id > MLXBF_PKA_MAX_NUM_IO_BLOCKS - 1) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "invalid shim identifier\n");
		return -EINVAL;
	}

	shim->shim_id = shim_id;
	shim->base = shim_base;
	shim->size = shim_size;

	if (split)
		shim->window_ram_split =
			MLXBF_PKA_SHIM_WINDOW_RAM_SPLIT_ENABLED;
	else
		shim->window_ram_split =
			MLXBF_PKA_SHIM_WINDOW_RAM_SPLIT_DISABLED;

	shim->ring_type = MLXBF_PKA_RING_TYPE_IN_ORDER;
	shim->ring_priority = MLXBF_PKA_RING_OPTIONS_PRIORITY;
	shim->rings_num = MLXBF_PKA_MAX_NUM_IO_BLOCK_RINGS;
	shim->rings = kcalloc(shim->rings_num,
			      sizeof(struct mlxbf_pka_dev_ring_t), GFP_KERNEL);
	if (!shim->rings) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "unable to kmalloc\n");
		kfree(shim->rings);
		return -ENOMEM;
	}

	/* Set PKA device Buffer RAM config */
	ret = mlxbf_pka_dev_set_resource_config(
		shim, &shim->resources.buffer_ram, MLXBF_PKA_BUFFER_RAM_BASE,
		MLXBF_PKA_BUFFER_RAM_SIZE, MLXBF_PKA_DEV_RES_TYPE_MEM,
		"MLXBF_PKA_BUFFER_RAM");
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"unable to set Buffer RAM config\n");
		kfree(shim->rings);
		return ret;
	}

	/* Set PKA device Master Program RAM config */
	ret = mlxbf_pka_dev_set_resource_config(
		shim, &shim->resources.master_prog_ram,
		MLXBF_PKA_MASTER_PROG_RAM_BASE, MLXBF_PKA_MASTER_PROG_RAM_SIZE,
		MLXBF_PKA_DEV_RES_TYPE_MEM, "MLXBF_PKA_MASTER_PROG_RAM");
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"unable to set Master Program RAM config\n");
		kfree(shim->rings);
		return ret;
	}

	/* Set PKA device Master Controller register */
	reg_size = PAGE_SIZE;
	reg_base = mlxbf_pka_dev_get_register_base(
		shim->base, MLXBF_PKA_MASTER_SEQ_CTRL_ADDR);
	ret = mlxbf_pka_dev_set_resource_config(
		shim, &shim->resources.master_seq_ctrl, reg_base, reg_size,
		MLXBF_PKA_DEV_RES_TYPE_REG, "MLXBF_PKA_MASTER_SEQ_CTRL");
	if (ret) {
		MLXBF_PKA_ERROR(
			MLXBF_PKA_DEV,
			"unable to set Master Controller register config\n");
		kfree(shim->rings);
		return ret;
	}

	/* Set PKA device AIC registers */
	reg_size = PAGE_SIZE;
	reg_base = mlxbf_pka_dev_get_register_base(shim->base,
						   MLXBF_PKA_AIC_POL_CTRL_ADDR);
	ret = mlxbf_pka_dev_set_resource_config(shim, &shim->resources.aic_csr,
						reg_base, reg_size,
						MLXBF_PKA_DEV_RES_TYPE_REG,
						"MLXBF_PKA_AIC_CSR");
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"unable to set AIC registers config\n");
		kfree(shim->rings);
		return ret;
	}

	/* Set PKA device TRNG registers */
	reg_size = PAGE_SIZE;
	reg_base = mlxbf_pka_dev_get_register_base(
		shim->base, MLXBF_PKA_TRNG_OUTPUT_0_ADDR);
	ret = mlxbf_pka_dev_set_resource_config(shim, &shim->resources.trng_csr,
						reg_base, reg_size,
						MLXBF_PKA_DEV_RES_TYPE_REG,
						"MLXBF_PKA_TRNG_CSR");
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "unable to setup the TRNG\n");
		kfree(shim->rings);
		return ret;
	}

	shim->status = MLXBF_PKA_SHIM_STATUS_CREATED;

	return ret;
}

/* Delete shim and unset shim resources. */
static int mlxbf_pka_dev_delete_shim(struct mlxbf_pka_dev_shim_t *shim)
{
	struct mlxbf_pka_dev_res_t *res_master_seq_ctrl, *res_aic_csr,
		*res_trng_csr;
	struct mlxbf_pka_dev_res_t *res_buffer_ram, *res_master_prog_ram;

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "MLXBF_PKA device delete shim\n");

	if (shim->status == MLXBF_PKA_SHIM_STATUS_UNDEFINED)
		return 0;

	if (shim->status != MLXBF_PKA_SHIM_STATUS_FINALIZED &&
	    shim->status != MLXBF_PKA_SHIM_STATUS_CREATED) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"MLXBF_PKA device status must be finalized\n");
		return -EPERM;
	}

	res_buffer_ram = &shim->resources.buffer_ram;
	res_master_prog_ram = &shim->resources.master_prog_ram;
	res_master_seq_ctrl = &shim->resources.master_seq_ctrl;
	res_aic_csr = &shim->resources.aic_csr;
	res_trng_csr = &shim->resources.trng_csr;

	mlxbf_pka_dev_unset_resource_config(shim, res_buffer_ram);
	mlxbf_pka_dev_unset_resource_config(shim, res_master_prog_ram);
	mlxbf_pka_dev_unset_resource_config(shim, res_master_seq_ctrl);
	mlxbf_pka_dev_unset_resource_config(shim, res_aic_csr);
	mlxbf_pka_dev_unset_resource_config(shim, res_trng_csr);

	kfree(shim->rings);

	shim->status = MLXBF_PKA_SHIM_STATUS_UNDEFINED;

	return 0;
}

static int
mlxbf_pka_dev_config_aic_interrupts(struct mlxbf_pka_dev_res_t *aic_csr_ptr)
{
	u64 csr_reg_base, csr_reg_off;
	void __iomem *csr_reg_ptr;

	if (aic_csr_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED ||
	    aic_csr_ptr->type != MLXBF_PKA_DEV_RES_TYPE_REG)
		return -EPERM;

	MLXBF_PKA_DEBUG(
		MLXBF_PKA_DEV,
		"configure the AIC so that all interrupts are properly recognized\n");

	csr_reg_base = aic_csr_ptr->base;
	csr_reg_ptr = aic_csr_ptr->ioaddr;

	/* Configure the signal polarity for each interrupt. */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_AIC_POL_CTRL_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
			       MLXBF_PKA_AIC_POL_CTRL_REG_VAL);

	/* Configure the signal type for each interrupt */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_AIC_TYPE_CTRL_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
			       MLXBF_PKA_AIC_TYPE_CTRL_REG_VAL);

	/* Set the enable control register */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_AIC_ENABLE_CTRL_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
			       MLXBF_PKA_AIC_ENABLE_CTRL_REG_VAL);

	/* Set the enabled status register */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_AIC_ENABLED_STAT_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
			       MLXBF_PKA_AIC_ENABLE_STAT_REG_VAL);

	/*
	 * Note: Write MLXBF_PKA_INT_MASK_RESET with 1's for each interrupt bit
	 * to allow them to propagate out the interrupt controller.
	 * EIP-154 interrupts can still be programmed and observed via polling
	 * regardless of whether MLXBF_PKA_INT_MASK is masking out the
	 * interrupts or not. The mask is for system propagation,
	 * i.e. propagate to the GIC.
	 * Bit positions are as follows:
	 *  Bit  10   - parity_error_irq (non EIP-154 interrupt)
	 *  Bit   9   - trng_irq
	 *  Bit   8   - mlxbf_pka_master_irq
	 *  Bits  7:4 - mlxbf_pka_queue_*_result_irq
	 *  Bits  3:0 - mlxbf_pka_queue_*_empty_irq
	 */

	return 0;
}

static int mlxbf_pka_dev_load_image(struct mlxbf_pka_dev_res_t *res_ptr,
				    const u32 *data_buf, u32 size)
{
	unsigned int mismatches;
	u64 data_rd;
	int i;

	if (res_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED ||
	    res_ptr->type != MLXBF_PKA_DEV_RES_TYPE_MEM)
		return -EPERM;

	if (res_ptr->size < size) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"image size greater than memory size\n");
		return -EINVAL;
	}

	for (i = 0; i < size; i++)
		mlxbf_pka_dev_io_write(res_ptr->ioaddr,
				       i * MLXBF_PKA_BYTES_PER_DOUBLE_WORD,
				       (u64)data_buf[i]);

	mismatches = 0;
	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
			"MLXBF_PKA DEV: verifying image (%u bytes)\n", size);
	for (i = 0; i < size; i++) {
		data_rd = mlxbf_pka_dev_io_read(
			res_ptr->ioaddr, i * MLXBF_PKA_BYTES_PER_DOUBLE_WORD);
		if (data_rd != (u64)data_buf[i]) {
			mismatches++;
			MLXBF_PKA_DEBUG(
				MLXBF_PKA_DEV,
				"error while loading image: addr:0x%llx expected data: 0x%x actual data: 0x%llx\n",
				res_ptr->base +
					i * MLXBF_PKA_BYTES_PER_DOUBLE_WORD,
				data_buf[i], data_rd);
		}
	}

	if (mismatches) {
		MLXBF_PKA_PANIC(MLXBF_PKA_DEV,
				"error while loading image: mismatches: %d\n",
				mismatches);
		return -EAGAIN;
	}

	return 0;
}

static int mlxbf_pka_dev_config_master_seq_controller(
	struct mlxbf_pka_dev_shim_t *shim,
	struct mlxbf_pka_dev_res_t *master_seq_ctrl_ptr)
{
	struct mlxbf_pka_dev_res_t *aic_csr_ptr, *master_prog_ram;
	const u32 *boot_img_ptr, *master_img_ptr;
	u64 master_reg_base, master_reg_off;
	u32 boot_img_size, master_img_size;
	u64 aic_reg_base, aic_reg_off;
	void __iomem *master_reg_ptr;
	void __iomem *aic_reg_ptr;
	u32 mlxbf_pka_master_irq;
	u8 status_bits;
	u8 shim_fw_id;
	u64 timer;
	int ret;

	if (master_seq_ctrl_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED ||
	    master_seq_ctrl_ptr->type != MLXBF_PKA_DEV_RES_TYPE_REG)
		return -EPERM;

	master_reg_base = master_seq_ctrl_ptr->base;
	master_reg_ptr = master_seq_ctrl_ptr->ioaddr;
	master_reg_off = mlxbf_pka_dev_get_register_offset(
		master_reg_base, MLXBF_PKA_MASTER_SEQ_CTRL_ADDR);

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
			"push the EIP-154 master controller into reset\n");
	mlxbf_pka_dev_io_write(master_reg_ptr, master_reg_off,
			       MLXBF_PKA_MASTER_SEQ_CTRL_RESET_VAL);

	shim_fw_id = mlxbf_pka_firmware_get_id();

	/* Load boot image into MLXBF_PKA_MASTER_PROG_RAM */
	boot_img_size = mlxbf_pka_firmware_array[shim_fw_id].boot_img_size;
	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "loading boot image (%d bytes)\n",
			boot_img_size);

	boot_img_ptr = mlxbf_pka_firmware_array[shim_fw_id].boot_img;
	ret = mlxbf_pka_dev_load_image(&shim->resources.master_prog_ram,
				       boot_img_ptr, boot_img_size);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "failed to load boot image\n");
		return ret;
	}

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
			"take the EIP-154 master controller out of reset\n");
	mlxbf_pka_dev_io_write(master_reg_ptr, master_reg_off, 0);

	/*
	 * Poll for 'mlxbf_pka_master_irq' bit in MLXBF_PKA_AIC_ENABLED_STAT
	 * register to indicate sequencer is initialized
	 */
	aic_csr_ptr = &shim->resources.aic_csr;
	if (aic_csr_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED ||
	    aic_csr_ptr->type != MLXBF_PKA_DEV_RES_TYPE_REG)
		return -EPERM;

	aic_reg_base = aic_csr_ptr->base;
	aic_reg_ptr = aic_csr_ptr->ioaddr;
	aic_reg_off = mlxbf_pka_dev_get_register_offset(
		aic_reg_base, MLXBF_PKA_AIC_ENABLED_STAT_ADDR);

	mlxbf_pka_master_irq = 0;
	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "poll for 'mlxbf_pka_master_irq'\n");
	timer = mlxbf_pka_dev_timer_start(MLXBF_PKA_KILO_100); /* 100 msec */
	while (!mlxbf_pka_master_irq) {
		mlxbf_pka_master_irq |=
			mlxbf_pka_dev_io_read(aic_reg_ptr, aic_reg_off) &
			MLXBF_PKA_AIC_ENABLED_STAT_MASTER_IRQ_MASK;
		if (mlxbf_pka_dev_timer_done(timer))
			return -EAGAIN;
	}
	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "'mlxbf_pka_master_irq' is active\n");

	/* Verify that the EIP-154 boot firmware has finished without errors */
	status_bits =
		(u8)((mlxbf_pka_dev_io_read(master_reg_ptr, master_reg_off) >>
		      MLXBF_PKA_MASTER_SEQ_CTRL_MASTER_IRQ_BIT) &
		     MLXBF_PKA_MASK_LEAST_BYTE);
	if (status_bits != MLXBF_PKA_MASTER_SEQ_CTRL_STATUS_BYTE) {
		/*
		 * If the error indication (bit [15]) is set, the EIP-154 boot
		 * firmware encountered an error and is stopped.
		 */
		if ((status_bits >>
		     (MLXBF_PKA_MASTER_SEQ_CTRL_MASTER_IRQ_BIT - 1)) == 1) {
			MLXBF_PKA_ERROR(
				MLXBF_PKA_DEV,
				"boot firmware encountered an error 0x%x and is stopped\n",
				status_bits);
			return -EAGAIN;
		}
		MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "boot firmware in progress %d",
				status_bits);
	}
	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
			"boot firmware has finished successfully\n");

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
			"push the EIP-154 master controller into reset\n");
	mlxbf_pka_dev_io_write(master_reg_ptr, master_reg_off,
			       MLXBF_PKA_MASTER_SEQ_CTRL_RESET_VAL);

	/* Load Master image into MLXBF_PKA_MASTER_PROG_RAM */
	master_img_size = mlxbf_pka_firmware_array[shim_fw_id].master_img_size;
	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "loading master image (%d bytes)\n",
			master_img_size);
	master_prog_ram = &shim->resources.master_prog_ram;
	master_img_ptr = mlxbf_pka_firmware_array[shim_fw_id].master_img;
	ret = mlxbf_pka_dev_load_image(master_prog_ram, master_img_ptr,
				       master_img_size);
	if (ret) {
		pr_err("MLXBF_PKA DEV: failed to load master image\n");
		return ret;
	}

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
			"take the EIP-154 master controller out of reset\n");
	mlxbf_pka_dev_io_write(master_reg_ptr, master_reg_off, 0);

	return ret;
}

/* Configure ring options. */
static int
mlxbf_pka_dev_config_ring_options(struct mlxbf_pka_dev_res_t *buffer_ram_ptr,
				  u32 rings_num, u8 ring_priority)
{
	u64 control_word;
	u64 word_off;

	if (buffer_ram_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED ||
	    buffer_ram_ptr->type != MLXBF_PKA_DEV_RES_TYPE_MEM)
		return -EPERM;

	if (rings_num > MLXBF_PKA_MAX_NUM_RINGS || rings_num < 1) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "invalid rings number\n");
		return -EINVAL;
	}

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
			"Configure MLXBF_PKA ring options control word\n");

	/*
	 * Write MLXBF_PKA_RING_OPTIONS control word located in the
	 * MLXBF_PKA_BUFFER_RAM. The value of this word is determined
	 * by the MLXBF_PKA I/O block (Shim).
	 * Set the number of implemented command/result ring pairs that is
	 * available in this EIP-154, encoded as binary value, which is 4.
	 */
	control_word = 0;
	control_word |= ring_priority & MLXBF_PKA_MASK_LEAST_BYTE;
	control_word |= ((rings_num - 1) << 8) & MLXBF_PKA_MASK_NUM_RINGS;
	control_word |= (MLXBF_PKA_RING_OPTIONS_SIGNATURE_BYTE << 24) &
			MLXBF_PKA_MASK_RING_SIGN;
	word_off = mlxbf_pka_dev_get_word_offset(buffer_ram_ptr->base,
						 MLXBF_PKA_RING_OPTIONS_ADDR,
						 MLXBF_PKA_BUFFER_RAM_SIZE);
	mlxbf_pka_dev_io_write(buffer_ram_ptr->ioaddr, word_off, control_word);

	return 0;
}

static int
mlxbf_pka_dev_config_trng_clk(struct mlxbf_pka_dev_res_t *aic_csr_ptr)
{
	u64 csr_reg_base, csr_reg_off;
	void __iomem *csr_reg_ptr;
	u32 trng_clk_en = 0;
	u64 timer;

	if (aic_csr_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED ||
	    aic_csr_ptr->type != MLXBF_PKA_DEV_RES_TYPE_REG)
		return -EPERM;

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "Turn on TRNG clock\n");

	csr_reg_base = aic_csr_ptr->base;
	csr_reg_ptr = aic_csr_ptr->ioaddr;

	/*
	 * Enable the TRNG clock in MLXBF_PKA_CLK_FORCE.
	 * In general, this register should be left in its default state of all
	 * zeroes! Only when the TRNG is directly controlled via the Host slave
	 * interface, the engine needs to be turned on using the 'trng_clk_on'
	 * bit in this register. In case the TRNG is controlled via internal
	 * firmware, this is not required.
	 */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_CLK_FORCE_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
			       MLXBF_PKA_CLK_FORCE_TRNG_ON);
	/*
	 * Check whether the system clock for TRNG engine is enabled. The clock
	 * MUST be running to provide access to the TRNG.
	 */
	timer = mlxbf_pka_dev_timer_start(MLXBF_PKA_KILO_100); /* 100 msec */
	while (!trng_clk_en) {
		trng_clk_en |= mlxbf_pka_dev_io_read(csr_reg_ptr, csr_reg_off) &
			       MLXBF_PKA_CLK_FORCE_TRNG_ON;
		if (mlxbf_pka_dev_timer_done(timer)) {
			MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
					"Failed to enable TRNG clock\n");
			return -EAGAIN;
		}
	}
	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "'trng_clk_on' is enabled\n");

	return 0;
}

/* Configure the TRNG. */
static int mlxbf_pka_dev_config_trng(struct mlxbf_pka_dev_res_t *aic_csr_ptr,
				     struct mlxbf_pka_dev_res_t *trng_csr_ptr)
{
	u64 csr_reg_base, csr_reg_off;
	void __iomem *csr_reg_ptr;
	int ret;

	if (trng_csr_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED ||
	    trng_csr_ptr->type != MLXBF_PKA_DEV_RES_TYPE_REG)
		return -EPERM;

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "Starting up the TRNG\n");

	ret = mlxbf_pka_dev_config_trng_clk(aic_csr_ptr);
	if (ret)
		return ret;

	csr_reg_base = trng_csr_ptr->base;
	csr_reg_ptr = trng_csr_ptr->ioaddr;

	/*
	 * Starting up the TRNG without a DRBG (default configuration);
	 * When not using the AES-256 DRBG, the startup sequence is relatively
	 * straightforward and the engine will generate data automatically to
	 * keep the output register and buffer RAM filled.
	 */

	/* Make sure the engine is idle. */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_CONTROL_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off, 0);

	/* Disable all FROs initially */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_FROENABLE_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off, 0);
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_FRODETUNE_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off, 0);

	/*
	 * Write all configuration values in the TRNG_CONFIG and TRNG_ALARMCNT,
	 * write zeroes to the TRNG_ALARMMASK and TRNG_ALARMSTOP registers.
	 */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_CONFIG_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
			       MLXBF_PKA_TRNG_CONFIG_REG_VAL);
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_ALARMCNT_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
			       MLXBF_PKA_TRNG_ALARMCNT_REG_VAL);

	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_ALARMMASK_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off, 0);
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_ALARMSTOP_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off, 0);

	/*
	 * Enable all FROs in the TRNG_FROENABLE register. Note that this can
	 * only be done after clearing the TRNG_ALARMSTOP register.
	 */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_FROENABLE_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
			       MLXBF_PKA_TRNG_FROENABLE_REG_VAL);

	/*
	 * Start the actual engine by setting the 'enable_trng' bit in the
	 * TRNG_CONTROL register (also a nice point to set the interrupt mask
	 * bits).
	 */
	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_CONTROL_ADDR);
	mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
			       MLXBF_PKA_TRNG_CONTROL_REG_VAL);

	/*
	 * Optionally, when buffer RAM is configured: Set a data available
	 * interrupt threshold using the 'load_thresh' and 'blocks_thresh'
	 * fields of the TRNG_INTACK register. This allows delaying the data
	 * available interrupt until the indicated number of 128-bit words are
	 * available in the buffer RAM.
	 */

	return ret;
}

/*
 * Initialize MLXBF_PKA IO block referred to as shim. It configures shim's
 * parameters and prepare resources by mapping corresponding memory.
 * The function also configures shim registers and load firmware to
 * shim internal rams. The mlxbf_pka_dev_shim_t passed as input is also an
 * output. It returns 0 on success, a negative error code on failure.
 */
static int mlxbf_pka_dev_init_shim(struct mlxbf_pka_dev_shim_t *shim)
{
	const u32 *farm_img_ptr;
	u32 farm_img_size;
	u8 shim_fw_id;
	int ret;

	if (shim->status != MLXBF_PKA_SHIM_STATUS_CREATED) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"MLXBF_PKA device must be created\n");
		return -EPERM;
	}

	/* Configure AIC registers */
	ret = mlxbf_pka_dev_config_aic_interrupts(&shim->resources.aic_csr);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "failed to configure AIC\n");
		return ret;
	}

	shim_fw_id = mlxbf_pka_firmware_get_id();

	/*
	 * Load Farm image into MLXBF_PKA_BUFFER_RAM for non-High Assurance mode
	 * or into MLXBF_PKA_SECURE_RAM for High Assurance mode.
	 */
	farm_img_size = mlxbf_pka_firmware_array[shim_fw_id].farm_img_size;
	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV, "loading farm image (%d bytes)\n",
			farm_img_size);

	farm_img_ptr = mlxbf_pka_firmware_array[shim_fw_id].farm_img;
	ret = mlxbf_pka_dev_load_image(&shim->resources.buffer_ram,
				       farm_img_ptr, farm_img_size);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "failed to load farm image\n");
		return ret;
	}

	/* Configure EIP-154 Master controller Sequencer */
	ret = mlxbf_pka_dev_config_master_seq_controller(
		shim, &shim->resources.master_seq_ctrl);
	if (ret) {
		MLXBF_PKA_ERROR(
			MLXBF_PKA_DEV,
			"failed to configure Master controller Sequencer\n");
		return ret;
	}

	/* Configure MLXBF_PKA Ring options control word */
	ret = mlxbf_pka_dev_config_ring_options(&shim->resources.buffer_ram,
						shim->rings_num,
						shim->ring_priority);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"failed to configure ring options\n");
		return ret;
	}

	shim->trng_enabled = MLXBF_PKA_SHIM_TRNG_ENABLED;
	shim->trng_err_cycle = 0;

	/* Configure the TRNG */
	ret = mlxbf_pka_dev_config_trng(&shim->resources.aic_csr,
					&shim->resources.trng_csr);
	if (ret) {
		/*
		 * Keep running without TRNG since it does not hurt, but
		 * notify users.
		 */
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "failed to configure TRNG\n");
		shim->trng_enabled = MLXBF_PKA_SHIM_TRNG_DISABLED;
	}

	shim->busy_ring_num = 0;
	shim->status = MLXBF_PKA_SHIM_STATUS_INITIALIZED;

	return ret;
}

/* Release a given shim. */
static int mlxbf_pka_dev_release_shim(struct mlxbf_pka_dev_shim_t *shim)
{
	u32 ring_idx;
	int ret;

	if (shim->status != MLXBF_PKA_SHIM_STATUS_INITIALIZED &&
	    shim->status != MLXBF_PKA_SHIM_STATUS_STOPPED) {
		MLXBF_PKA_ERROR(
			MLXBF_PKA_DEV,
			"MLXBF_PKA device must be initialized or stopped\n");
		return -EPERM;
	}

	/*
	 * Release rings which belong to the shim. The operating system might
	 * release ring devices before shim devices. The global configuration
	 * must be checked before proceeding to the release of ring devices.
	 */
	if (mlxbf_pka_gbl_config.dev_rings_cnt) {
		for (ring_idx = 0; ring_idx < shim->rings_num; ring_idx++) {
			ret = mlxbf_pka_dev_release_ring(shim->rings[ring_idx]);
			if (ret) {
				MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
						"failed to release ring %d\n",
						ring_idx);
				return ret;
			}
		}
	}

	shim->busy_ring_num = 0;
	shim->status = MLXBF_PKA_SHIM_STATUS_FINALIZED;

	return ret;
}

/* Return the ring associated with the given identifier. */
inline struct mlxbf_pka_dev_ring_t *mlxbf_pka_dev_get_ring(u32 ring_id)
{
	return mlxbf_pka_gbl_config.dev_rings[ring_id];
}

/* Return the shim associated with the given identifier. */
inline struct mlxbf_pka_dev_shim_t *mlxbf_pka_dev_get_shim(u32 shim_id)
{
	return mlxbf_pka_gbl_config.dev_shims[shim_id];
}

static struct mlxbf_pka_dev_ring_t *__mlxbf_pka_dev_register_ring(u32 ring_id,
								  u32 shim_id)
{
	struct mlxbf_pka_dev_shim_t *shim;
	struct mlxbf_pka_dev_ring_t *ring;
	int ret;

	shim = mlxbf_pka_dev_get_shim(shim_id);
	if (!shim)
		return NULL;

	ring = kzalloc(sizeof(struct mlxbf_pka_dev_ring_t), GFP_KERNEL);
	if (!ring)
		return ring;

	ring->status = MLXBF_PKA_DEV_RING_STATUS_UNDEFINED;

	ret = mlxbf_pka_dev_init_ring(ring, ring_id, shim);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "failed to initialize ring %d\n",
				ring_id);
		mlxbf_pka_dev_release_ring(ring);
		kfree(ring);
		return NULL;
	}

	return ring;
}

struct mlxbf_pka_dev_ring_t *mlxbf_pka_dev_register_ring(u32 ring_id,
							 u32 shim_id)
{
	struct mlxbf_pka_dev_ring_t *ring;

	ring = __mlxbf_pka_dev_register_ring(ring_id, shim_id);
	if (ring) {
		mlxbf_pka_gbl_config.dev_rings[ring->ring_id] = ring;
		mlxbf_pka_gbl_config.dev_rings_cnt += 1;
	}

	return ring;
}

static int __mlxbf_pka_dev_unregister_ring(struct mlxbf_pka_dev_ring_t *ring)
{
	int ret;

	if (!ring)
		return -EINVAL;

	ret = mlxbf_pka_dev_release_ring(ring);
	if (ret)
		return ret;

	kfree(ring);

	return ret;
}

int mlxbf_pka_dev_unregister_ring(struct mlxbf_pka_dev_ring_t *ring)
{
	mlxbf_pka_gbl_config.dev_rings[ring->ring_id] = NULL;
	mlxbf_pka_gbl_config.dev_rings_cnt -= 1;

	return __mlxbf_pka_dev_unregister_ring(ring);
}

static struct mlxbf_pka_dev_shim_t *
__mlxbf_pka_dev_register_shim(u32 shim_id, u64 shim_base, u64 shim_size)
{
	struct mlxbf_pka_dev_shim_t *shim;
	u8 split;
	int ret;

	MLXBF_PKA_DEBUG(MLXBF_PKA_DEV,
			"register shim id=%u, start=0x%llx end=0x%llx\n",
			shim_id, shim_base, shim_base + shim_size);

	shim = kzalloc(sizeof(struct mlxbf_pka_dev_shim_t), GFP_KERNEL);
	if (!shim)
		return shim;

	/*
	 * Shim state MUST be set to undefined before calling
	 * 'mlxbf_pka_dev_create_shim' function
	 */
	shim->status = MLXBF_PKA_SHIM_STATUS_UNDEFINED;

	split = MLXBF_PKA_SPLIT_WINDOW_RAM_MODE;

	ret = mlxbf_pka_dev_create_shim(shim, shim_id, shim_base, shim_size,
					split);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "failed to create shim %u\n",
				shim_id);
		mlxbf_pka_dev_delete_shim(shim);
		kfree(shim);
		return NULL;
	}

	ret = mlxbf_pka_dev_init_shim(shim);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV, "failed to init shim %u\n",
				shim_id);
		mlxbf_pka_dev_release_shim(shim);
		mlxbf_pka_dev_delete_shim(shim);
		kfree(shim);
		return NULL;
	}

	return shim;
}

struct mlxbf_pka_dev_shim_t *mlxbf_pka_dev_register_shim(u32 shim_id,
							 u64 shim_base,
							 u64 shim_size,
							 u8 shim_fw_id)
{
	struct mlxbf_pka_dev_shim_t *shim;

	mlxbf_pka_firmware_set_id(shim_fw_id);

	shim = __mlxbf_pka_dev_register_shim(shim_id, shim_base, shim_size);
	if (shim) {
		mlxbf_pka_gbl_config.dev_shims[shim->shim_id] = shim;
		mlxbf_pka_gbl_config.dev_shims_cnt += 1;
	}

	return shim;
}

static int __mlxbf_pka_dev_unregister_shim(struct mlxbf_pka_dev_shim_t *shim)
{
	int ret;

	if (!shim)
		return -EINVAL;

	ret = mlxbf_pka_dev_release_shim(shim);
	if (ret)
		return ret;

	ret = mlxbf_pka_dev_delete_shim(shim);
	if (ret)
		return ret;

	kfree(shim);

	return ret;
}

int mlxbf_pka_dev_unregister_shim(struct mlxbf_pka_dev_shim_t *shim)
{
	mlxbf_pka_gbl_config.dev_shims[shim->shim_id] = NULL;
	mlxbf_pka_gbl_config.dev_shims_cnt -= 1;

	return __mlxbf_pka_dev_unregister_shim(shim);
}

static bool
mlxbf_pka_dev_trng_shutdown_oflo(struct mlxbf_pka_dev_res_t *trng_csr_ptr,
				 u64 *err_cycle)
{
	u64 curr_cycle_cnt, fro_stopped_mask, fro_enabled_mask;
	u64 csr_reg_base, csr_reg_off, csr_reg_value;
	void __iomem *csr_reg_ptr;

	csr_reg_base = trng_csr_ptr->base;
	csr_reg_ptr = trng_csr_ptr->ioaddr;

	csr_reg_off = mlxbf_pka_dev_get_register_offset(
		csr_reg_base, MLXBF_PKA_TRNG_STATUS_ADDR);
	csr_reg_value = mlxbf_pka_dev_io_read(csr_reg_ptr, csr_reg_off);

	if (csr_reg_value & MLXBF_PKA_TRNG_STATUS_SHUTDOWN_OFLO) {
		curr_cycle_cnt = get_cycles();
		/*
		 * See if any FROs were shut down. If they were, toggle bits
		 * in the FRO detune register and reenable the FROs.
		 */
		csr_reg_off = mlxbf_pka_dev_get_register_offset(
			csr_reg_base, MLXBF_PKA_TRNG_ALARMSTOP_ADDR);
		fro_stopped_mask =
			mlxbf_pka_dev_io_read(csr_reg_ptr, csr_reg_off);
		if (fro_stopped_mask) {
			csr_reg_off = mlxbf_pka_dev_get_register_offset(
				csr_reg_base, MLXBF_PKA_TRNG_FROENABLE_ADDR);
			fro_enabled_mask =
				mlxbf_pka_dev_io_read(csr_reg_ptr, csr_reg_off);

			csr_reg_off = mlxbf_pka_dev_get_register_offset(
				csr_reg_base, MLXBF_PKA_TRNG_FRODETUNE_ADDR);
			mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
					       fro_stopped_mask);

			csr_reg_off = mlxbf_pka_dev_get_register_offset(
				csr_reg_base, MLXBF_PKA_TRNG_FROENABLE_ADDR);
			mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
					       fro_stopped_mask |
						       fro_enabled_mask);
		}

		/* Reset the error */
		csr_reg_off = mlxbf_pka_dev_get_register_offset(
			csr_reg_base, MLXBF_PKA_TRNG_ALARMMASK_ADDR);
		mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off, 0);

		csr_reg_off = mlxbf_pka_dev_get_register_offset(
			csr_reg_base, MLXBF_PKA_TRNG_ALARMSTOP_ADDR);
		mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off, 0);

		csr_reg_off = mlxbf_pka_dev_get_register_offset(
			csr_reg_base, MLXBF_PKA_TRNG_INTACK_ADDR);
		mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
				       MLXBF_PKA_TRNG_STATUS_SHUTDOWN_OFLO);

		/*
		 * If we're seeing this error again within about a second,
		 * the hardware is malfunctioning. Disable the trng and return
		 * an error.
		 */
		if (*err_cycle &&
		    (curr_cycle_cnt - *err_cycle < MLXBF_PKA_GIGA)) {
			csr_reg_off = mlxbf_pka_dev_get_register_offset(
				csr_reg_base, MLXBF_PKA_TRNG_CONTROL_ADDR);
			csr_reg_value =
				mlxbf_pka_dev_io_read(csr_reg_ptr, csr_reg_off);
			csr_reg_value &= ~MLXBF_PKA_TRNG_CONTROL_REG_VAL;
			mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
					       csr_reg_value);
			return false;
		}

		*err_cycle = curr_cycle_cnt;
	}

	return true;
}

int mlxbf_pka_dev_trng_read(struct mlxbf_pka_dev_shim_t *shim, u32 *data,
			    u32 cnt)
{
	u64 csr_reg_base, csr_reg_off, csr_reg_value;
	struct mlxbf_pka_dev_res_t *trng_csr_ptr;
	u8 output_idx, trng_ready = 0;
	void __iomem *csr_reg_ptr;
	u32 data_idx, word_cnt;
	u64 timer;

	if (!shim || !data || (cnt % MLXBF_PKA_TRNG_OUTPUT_CNT))
		return -EINVAL;

	if (!cnt)
		return 0;

	trng_csr_ptr = &shim->resources.trng_csr;

	if (trng_csr_ptr->status != MLXBF_PKA_DEV_RES_STATUS_MAPPED ||
	    trng_csr_ptr->type != MLXBF_PKA_DEV_RES_TYPE_REG)
		return -EPERM;

	csr_reg_base = trng_csr_ptr->base;
	csr_reg_ptr = trng_csr_ptr->ioaddr;

	if (!mlxbf_pka_dev_trng_shutdown_oflo(trng_csr_ptr,
					      &shim->trng_err_cycle))
		return -EWOULDBLOCK;

	/* Determine the number of 32-bit words. */
	word_cnt = cnt >> 2;

	for (data_idx = 0; data_idx < word_cnt; data_idx++) {
		output_idx = data_idx % MLXBF_PKA_TRNG_OUTPUT_CNT;
		/* Tell the hardware to advance */
		if (!output_idx) {
			csr_reg_off = mlxbf_pka_dev_get_register_offset(
				csr_reg_base, MLXBF_PKA_TRNG_INTACK_ADDR);
			mlxbf_pka_dev_io_write(csr_reg_ptr, csr_reg_off,
					       MLXBF_PKA_TRNG_STATUS_READY);
		}

		/*
		 * Wait until a data word is available in the TRNG_OUTPUT_X
		 * registers (using the interrupt and/or 'ready' status bit in
		 * the TRNG_STATUS register. The only way this would hang if
		 * the TRNG never initialized, and we would not call this
		 * function if that happened.
		 */
		timer = mlxbf_pka_dev_timer_start(MLXBF_PKA_MEGA); /* 1000 ms */
		csr_reg_off = mlxbf_pka_dev_get_register_offset(
			csr_reg_base, MLXBF_PKA_TRNG_STATUS_ADDR);
		while (!trng_ready) {
			csr_reg_value =
				mlxbf_pka_dev_io_read(csr_reg_ptr, csr_reg_off);
			trng_ready =
				csr_reg_value & MLXBF_PKA_TRNG_STATUS_READY;

			if (mlxbf_pka_dev_timer_done(timer)) {
				MLXBF_PKA_DEBUG(
					MLXBF_PKA_DEV,
					"Shim %u got error obtaining random number\n",
					shim->shim_id);
				return -EBUSY;
			}
		}

		/* Read the registers */
		csr_reg_off = mlxbf_pka_dev_get_register_offset(
			csr_reg_base,
			MLXBF_PKA_TRNG_OUTPUT_0_ADDR +
				(output_idx * MLXBF_PKA_BYTE_OFFSET));
		csr_reg_value = mlxbf_pka_dev_io_read(csr_reg_ptr, csr_reg_off);
		data[data_idx] = (u32)csr_reg_value;
	}

	return 0;
}

bool mlxbf_pka_dev_has_trng(struct mlxbf_pka_dev_shim_t *shim)
{
	if (!shim)
		return false;

	return (shim->trng_enabled == MLXBF_PKA_SHIM_TRNG_ENABLED);
}

/* Open ring. */
int mlxbf_pka_dev_open_ring(u32 ring_id)
{
	struct mlxbf_pka_dev_shim_t *shim;
	struct mlxbf_pka_dev_ring_t *ring;
	int ret;

	if (!mlxbf_pka_gbl_config.dev_rings_cnt)
		return -EPERM;

	ring = mlxbf_pka_dev_get_ring(ring_id);
	if (!ring || !ring->shim)
		return -ENXIO;

	shim = ring->shim;

	if (shim->status == MLXBF_PKA_SHIM_STATUS_UNDEFINED ||
	    shim->status == MLXBF_PKA_SHIM_STATUS_CREATED ||
	    shim->status == MLXBF_PKA_SHIM_STATUS_FINALIZED)
		return -EPERM;

	if (ring->status != MLXBF_PKA_DEV_RING_STATUS_INITIALIZED)
		return -EPERM;

	/* Set ring information words. */
	ret = mlxbf_pka_dev_set_ring_info(ring);
	if (ret) {
		MLXBF_PKA_ERROR(MLXBF_PKA_DEV,
				"failed to set ring information\n");
		return -EWOULDBLOCK;
	}

	if (!shim->busy_ring_num)
		shim->status = MLXBF_PKA_SHIM_STATUS_RUNNING;

	ring->status = MLXBF_PKA_DEV_RING_STATUS_BUSY;
	shim->busy_ring_num += 1;

	return ret;
}

/* Close ring. */
int mlxbf_pka_dev_close_ring(u32 ring_id)
{
	struct mlxbf_pka_dev_shim_t *shim;
	struct mlxbf_pka_dev_ring_t *ring;

	if (!mlxbf_pka_gbl_config.dev_rings_cnt)
		return -EPERM;

	ring = mlxbf_pka_dev_get_ring(ring_id);
	if (!ring || !ring->shim)
		return -ENXIO;

	shim = ring->shim;

	if (shim->status != MLXBF_PKA_SHIM_STATUS_RUNNING &&
	    ring->status != MLXBF_PKA_DEV_RING_STATUS_BUSY)
		return -EPERM;

	ring->status = MLXBF_PKA_DEV_RING_STATUS_INITIALIZED;
	shim->busy_ring_num -= 1;

	if (!shim->busy_ring_num)
		shim->status = MLXBF_PKA_SHIM_STATUS_STOPPED;

	return 0;
}
