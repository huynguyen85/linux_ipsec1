/* SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#ifndef __MLXBF_PKA_IOCTL_H__
#define __MLXBF_PKA_IOCTL_H__

#include <linux/ioctl.h>
#include <linux/types.h>

#define MLXBF_PKA_IOC_TYPE 0xB7

/** mlxbf_pka_dev_region_info_t - PKA device region structure
 * @reg_index: register index
 * @reg_size: register size (in bytes)
 * @reg_offset: register offset from start of device fd
 * @mem_index: memory index
 * @mem_size: memory size (in bytes)
 * @mem_offset: memory offset from start of device fd
 */
struct mlxbf_pka_dev_region_info_t {
	u32 reg_index;
	u64 reg_size;
	u64 reg_offset;
	u32 mem_index;
	u64 mem_size;
	u64 mem_offset;
};

/*
 * MLXBF_PKA_VFIO_GET_REGION_INFO:
 * _IORW(MLXBF_PKA_IOC_TYPE, 0x0, mlxbf_pka_dev_region_info_t)
 * Retrieve information about a device region. This is intended to describe
 * MMIO, I/O port, as well as bus specific regions (ex. PCI config space).
 * Zero sized regions may be used to describe unimplemented regions.
 * Return: 0 on success, -errno on failure.
 */
#define MLXBF_PKA_VFIO_GET_REGION_INFO                                         \
	_IOWR(MLXBF_PKA_IOC_TYPE, 0x0, struct mlxbf_pka_dev_region_info_t)

/** mlxbf_pka_dev_hw_ring_info_t - PKA device ring structure
 * @cmmd_base: Base address of command descriptor ring
 * @rslt_base: Base address of result descriptor ring
 * @size: Size of a command ring in number of descriptors, minus 1.
	  Min value is 0 (for 1 descriptor); Max value is 65535 (64K)
 * @host_desc_size: Size (in 32-bit words) of the space the PKI command
		    and result decriptor occupies on the Host.
 * @in_order: Indicates whether the result ring delivers results strictly
	      in-order('1') or that result descriptors are written to the
	      result ring as soon as they become available ('0')
 * @cmmd_rd_ptr: Read pointer of the command descriptor ring
 * @rslt_wr_ptr: Write pointer of the result descriptor ring
 * @cmmd_rd_stats
 * @rslt_wr_stats
 */
struct mlxbf_pka_dev_hw_ring_info_t { /* Bluefield specific ring information */
	u64 cmmd_base;
	u64 rslt_base;
	u16 size;
	u16 host_desc_size : 10;
	u8 in_order : 1;
	u16 cmmd_rd_ptr;
	u16 rslt_wr_ptr;
	u16 cmmd_rd_stats;
	u16 rslt_wr_stats;
};

/*
 * MLXBF_PKA_VFIO_GET_RING_INFO:
 * _IORW(MLXBF_PKA_IOC_TYPE, 0x1, struct mlxbf_pka_dev_ring_info_t)
 * Retrieve information about a ring. This is intended to describe ring
 * information words located in MLXBF_PKA_BUFFER_RAM. Ring information includes
 * base addresses, size and statistics.
 * Return: 0 on success, -errno on failure.
 */
#define MLXBF_PKA_VFIO_GET_RING_INFO                                           \
	_IOWR(MLXBF_PKA_IOC_TYPE, 0x1, struct mlxbf_pka_dev_hw_ring_info_t)

#endif /* __MLXBF_PKA_IOCTL_H__ */
