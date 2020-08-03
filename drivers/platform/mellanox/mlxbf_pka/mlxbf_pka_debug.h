/* SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#ifndef __MLXBF_PKA_DEBUG_H__
#define __MLXBF_PKA_DEBUG_H__

/* PKA library bitmask. Use those bits to enable debug messages. */
#define MLXBF_PKA_DRIVER BIT(0)
#define MLXBF_PKA_DEV BIT(1)
#define MLXBF_PKA_RING BIT(2)
#define MLXBF_PKA_QUEUE BIT(3)
#define MLXBF_PKA_MEM BIT(4)
#define MLXBF_PKA_USER BIT(5)
#define MLXBF_PKA_TESTS BIT(6)
/* PKA debug mask. This indicates the debug/verbosity level. */
#define MLXBF_PKA_DEBUG_LIB_MASK BIT(6)

#define MLXBF_PKA_PRINT(lib, fmt, args...) ({ pr_info(#lib ": " fmt, ##args); })

#define MLXBF_PKA_ERROR(lib, fmt, args...)                                     \
	({ pr_err(#lib ": %s: error: " fmt, __func__, ##args); })

#define MLXBF_PKA_DEBUG(lib, fmt, args...)                                     \
	do {                                                                   \
		if ((lib) & MLXBF_PKA_DEBUG_LIB_MASK)                          \
			pr_debug(#lib ": %s: " fmt, __func__, ##args);         \
	} while (0)

#define MLXBF_PKA_PANIC(lib, msg, args...)                                     \
	do {                                                                   \
		pr_info(#lib ": %s: panic: " msg, __func__, ##args);           \
		panic(msg, ##args);                                            \
	} while (0)

#endif /* __MLXBF_PKA_DEBUG_H__ */
