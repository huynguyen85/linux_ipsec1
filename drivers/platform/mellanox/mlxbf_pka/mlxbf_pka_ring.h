/* SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#ifndef __MLXBF_PKA_RING_H__
#define __MLXBF_PKA_RING_H__

#include <linux/types.h>

/**
 * mlxbf_pka_ring_hw_cmd_desc_t - Bluefield PKA command descriptor structure
 * Structure is 64 bytes long. 64 bytes aligned
 * @pointer_a
 * @pointer_b
 * @pointer_c
 * @pointer_d
 * @tag
 * @pointer_e
 * @linked
 * @driver_status
 * @odd_poers: Shift count for shift operations
 * @kdk: Key decryption key number
 * @encryted_mask
 * @rsvd_3
 * @command
 * @rsvd_2
 * @length_b
 * @output_attr
 * @input_attr
 * @rsvd_1
 * @length_a
 * @rsvd_0
 * @rsvd_4
 */
struct mlxbf_pka_ring_hw_cmd_desc_t {
	u64 pointer_a;
	u64 pointer_b;
	u64 pointer_c;
	u64 pointer_d;
	u64 tag;
	u64 pointer_e;
#ifdef __BIG_ENDIAN_BITFIELD
	u64 linked : 1;
	u64 driver_status : 2;
	u64 odd_powers : 5;
	u64 kdk : 2;
	u64 encrypted_mask : 6;
	u64 rsvd_3 : 8;
	u64 command : 8;
	u64 rsvd_2 : 5;
	u64 length_b : 9;
	u64 output_attr : 1;
	u64 input_attr : 1;
	u64 rsvd_1 : 5;
	u64 length_a : 9;
	u64 rsvd_0 : 2;
#else
	u64 rsvd_0 : 2;
	u64 length_a : 9;
	u64 rsvd_1 : 5;
	u64 input_attr : 1;
	u64 output_attr : 1;
	u64 length_b : 9;
	u64 rsvd_2 : 5;
	u64 command : 8;
	u64 rsvd_3 : 8;
	u64 encrypted_mask : 6;
	u64 kdk : 2;
	u64 odd_powers : 5;
	u64 driver_status : 2;
	u64 linked : 1;
#endif
	u64 rsvd_4;
};

#define MLXBF_PKA_CMD_DESC_SIZE sizeof(struct mlxbf_pka_ring_hw_cmd_desc_t)

/**
 * mlxbf_pka_ring_hw_rslt_desc_t - Bluefield PKA result descriptor structure
 * Structure is 64 bytes long. 64 bytes aligned
 * @pointer_a
 * @pointer_b
 * @pointer_c
 * @pointer_d
 * @tag
 * @rsvd_5
 * @cmp_result
 * @modulo_is_0
 * @rsvd_4
 * @modulo_msw_offset
 * @rsvd_3
 * @rsvd_2
 * @main_result_msb_offset
 * @result_is_0
 * @rsvd_1
 * @main_result_msw_offset
 * @rsvd_0
 * @linked
 * @driver_status : Always written to 0
 * @odd_poers: Shift count for shift operations
 * @kdk: Key decryption key number
 * @encryted_mask
 * @result_code
 * @command
 * @rsvd_8
 * @length_b
 * @output_attr
 * @input_attr
 * @rsvd_7
 * @length_a
 * @rsvd_6
 * @rsvd_9
 */
struct mlxbf_pka_ring_hw_rslt_desc_t {
	u64 pointer_a;
	u64 pointer_b;
	u64 pointer_c;
	u64 pointer_d;
	u64 tag;
#ifdef __BIG_ENDIAN_BITFIELD
	u64 rsvd_5 : 13;
	u64 cmp_result : 3;
	u64 modulo_is_0 : 1;
	u64 rsvd_4 : 2;
	u64 modulo_msw_offset : 11;
	u64 rsvd_3 : 2;
	u64 rsvd_2 : 11;
	u64 main_result_msb_offset : 5;
	u64 result_is_0 : 1;
	u64 rsvd_1 : 2;
	u64 main_result_msw_offset : 11;
	u64 rsvd_0 : 2;
	u64 linked : 1;
	u64 driver_status : 2;
	u64 odd_powers : 5;
	u64 kdk : 2;
	u64 encrypted_mask : 6;
	u64 result_code : 8;
	u64 command : 8;
	u64 rsvd_8 : 5;
	u64 length_b : 9;
	u64 output_attr : 1;
	u64 input_attr : 1;
	u64 rsvd_7 : 5;
	u64 length_a : 9;
	u64 rsvd_6 : 2;
#else
	u64 rsvd_0 : 2;
	u64 main_result_msw_offset : 11;
	u64 rsvd_1 : 2;
	u64 result_is_0 : 1;
	u64 main_result_msb_offset : 5;
	u64 rsvd_2 : 11;
	u64 rsvd_3 : 2;
	u64 modulo_msw_offset : 11;
	u64 rsvd_4 : 2;
	u64 modulo_is_0 : 1;
	u64 cmp_result : 3;
	u64 rsvd_5 : 13;
	u64 rsvd_6 : 2;
	u64 length_a : 9;
	u64 rsvd_7 : 5;
	u64 input_attr : 1;
	u64 output_attr : 1;
	u64 length_b : 9;
	u64 rsvd_8 : 5;
	u64 command : 8;
	u64 result_code : 8;
	u64 encrypted_mask : 6;
	u64 kdk : 2;
	u64 odd_powers : 5;
	u64 driver_status : 2;
	u64 linked : 1;
#endif
	u64 rsvd_9;
};

#define MLXBF_PKA_RESULT_DESC_SIZE sizeof(struct mlxbf_pka_ring_hw_rslt_desc_t)

#endif /* __MLXBF_PKA_RING_H__ */
