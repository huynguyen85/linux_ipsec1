/* SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#ifndef __MLXBF_PKA_MMIO_H__
#define __MLXBF_PKA_MMIO_H__

#include <linux/io.h>

/* Macros for standard MMIO functions. */
#define mlxbf_pka_mmio_read(addr) readq_relaxed(addr)
#define mlxbf_pka_mmio_write(addr, val) writeq_relaxed((val), (addr))

#endif /* __MLXBF_PKA_MMIO_H__ */
