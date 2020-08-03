/* SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#ifndef __MLXBF_PKA_CPU_H__
#define __MLXBF_PKA_CPU_H__

#include <linux/types.h>

#define MLXBF_PKA_MEGA 1000000

/*
 * Initial guess at our CPU speed.  We set this to be larger than any
 * possible real speed, so that any calculated delays will be too long,
 * rather than too short.
 *
 * Warning: use dummy value for frequency
 *
 * CPU Freq for High/Bin Chip
 */
#define MLXBF_PKA_CPU_HZ_MAX (1255 * MLXBF_PKA_MEGA)

/*
 * Processor speed in hertz; used in routines which might be called very
 * early in boot.
 */
static inline u64 mlxbf_pka_early_cpu_speed(void)
{
	return MLXBF_PKA_CPU_HZ_MAX;
}

#endif /* __MLXBF_PKA_CPU_H__ */
