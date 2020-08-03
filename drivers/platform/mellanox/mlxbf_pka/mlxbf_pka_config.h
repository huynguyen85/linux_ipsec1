/* SPDX-License-Identifier: GPL-2.0-only OR Linux-OpenIB
 *
 * Copyright (c) 2020 NVIDIA Corporation. All rights reserved.
 */

#ifndef __MLXBF_PKA_CONFIG_H__
#define __MLXBF_PKA_CONFIG_H__

#include "mlxbf_pka_addrs.h"

/* The maximum number of PKA shims referred to as IO blocks. */
#define MLXBF_PKA_MAX_NUM_IO_BLOCKS 8
/* The maximum number of Rings supported by IO block (shim). */
#define MLXBF_PKA_MAX_NUM_IO_BLOCK_RINGS 4

#define MLXBF_PKA_MAX_NUM_RINGS                                                \
	(MLXBF_PKA_MAX_NUM_IO_BLOCK_RINGS * MLXBF_PKA_MAX_NUM_IO_BLOCKS)

/*
 * Resources are regions which include info control/status words,
 * count registers and host window ram.
 */
#define MLXBF_PKA_MAX_NUM_RING_RESOURCES 3

/*
 * PKA Ring resources.
 * Define Ring resources parameters including base address, size (in bytes)
 * and ring spacing.
 */
#define MLXBF_PKA_RING_WORDS_ADDR MLXBF_PKA_BUFFER_RAM_BASE
#define MLXBF_PKA_RING_CNTRS_ADDR MLXBF_PKA_COMMAND_COUNT_0_ADDR
#define MLXBF_PKA_RING_MEM_0_BASE MLXBF_PKA_WINDOW_RAM_BASE
#define MLXBF_PKA_RING_MEM_1_BASE MLXBF_PKA_WINDOW_RAM_REGION_0_BASE

#define MLXBF_PKA_RING_WORDS_SIZE 0x40
#define MLXBF_PKA_RING_CNTRS_SIZE 0x20
#define MLXBF_PKA_RING_MEM_0_SIZE MLXBF_PKA_WINDOW_RAM_REGION_SIZE
#define MLXBF_PKA_RING_MEM_1_SIZE MLXBF_PKA_WINDOW_RAM_REGION_SIZE

#define MLXBF_PKA_RING_WORDS_SPACING 0x40
#define MLXBF_PKA_RING_CNTRS_SPACING 0x10000
#define MLXBF_PKA_RING_MEM_0_SPACING 0x4000
#define MLXBF_PKA_RING_MEM_1_SPACING 0x10000

/*
 * PKA Window RAM parameters.
 * Define whether to split or not Window RAM during PKA device creation phase.
 */
#define MLXBF_PKA_SPLIT_WINDOW_RAM_MODE_ENABLED 1
#define MLXBF_PKA_SPLIT_WINDOW_RAM_MODE_DISABLED 0
#define MLXBF_PKA_SPLIT_WINDOW_RAM_MODE MLXBF_PKA_SPLIT_WINDOW_RAM_MODE_DISABLED
/* Defines for Window RAM partition. It is valid for 16K memory. */
#define MLXBF_PKA_WINDOW_RAM_RING_MEM_SIZE 0x0800
#define MLXBF_PKA_WINDOW_RAM_DATA_MEM_SIZE 0x3800

/*
 * Macro for mapping PKA Ring address into Window RAM address. It converts the
 * ring address, either physical address or virtual address, to valid address
 * into the Window RAM. This is done assuming the Window RAM base and size.
 */
#define MLXBF_PKA_RING_MEM_ADDR(addr, size)                                    \
	(MLXBF_PKA_WINDOW_RAM_BASE |                                           \
	 (((addr) & 0xffff) | ((((addr) & ~((size) - 1)) & 0xf0000) >> 2)))

/*
 * PKA Master Sequencer Control/Status Register
 * Write '1' to bit [31] puts the Master controller Sequencer in a reset
 * reset state. Resetting the Sequencer (in order to load other firmware)
 * should only be done when the EIP-154 is not performing any operations.
 */
#define MLXBF_PKA_MASTER_SEQ_CTRL_RESET_VAL BIT(31)
/*
 * Bit [8] in the PKA Master Sequencer Control/Status Register is tied to
 * the 'mlxbf_pka_master_irq interrupt' on the EIP-154 interrupt controller.
 */
#define MLXBF_PKA_MASTER_SEQ_CTRL_MASTER_IRQ_BIT BIT(3)
/*
 * Sequencer status bits are used by the Master controller Sequencer to
 * reflect status. Bit [0] is tied to the 'mlxbf_pka_master_irq' interrupt on
 * the EIP-154 interrupt controller.
 */
#define MLXBF_PKA_MASTER_SEQ_CTRL_STATUS_BYTE BIT(0)
/*
 * 'mlxbf_pka_master_irq' mask for Master controller Sequencer Status Register.
 */
#define MLXBF_PKA_MASTER_SEQ_CTRL_MASTER_IRQ_MASK BIT(8)

/*
 * Advanced Interrupt Controller (AIC) configuration
 * AIC Polarity Control Register is used to set each individual interrupt
 * signal (High Level / Rising Edge) during the initialization phase.
 *   '0' = Low level or falling edge.
 *   '1' = High level or rising edge.
 */
#define MLXBF_PKA_AIC_POL_CTRL_REG_VAL GENMASK(19, 0)
/*
 * AIC Type Control Register is used to set each interrupt to level or edge.
 *   '0' = Level.
 *   '1' = Edge.
 */
#define MLXBF_PKA_AIC_TYPE_CTRL_REG_VAL GENMASK(19, 0)
/*
 * AIC Enable Control Register is used to enable interrupt inputs.
 *   '0' = Disabled.
 *   '1' = Enabled.
 */
#define MLXBF_PKA_AIC_ENABLE_CTRL_REG_VAL 0x000F030F
/*
 * AIC Enabled Status Register bits reflect the status of the interrupts
 * gated with the enable bits of the AIC_ENABLE_CTRL Register.
 *   '0' = Inactive.
 *   '1' = Pending.
 */
#define MLXBF_PKA_AIC_ENABLE_STAT_REG_VAL 0x000F030F

/* 'mlxbf_pka_master_irq' mask for the AIC Enabled Status Register. */
#define MLXBF_PKA_AIC_ENABLED_STAT_MASTER_IRQ_MASK 0x100

/*
 * MLXBF_PKA_RING_OPTIONS : Priority in which rings are handled:
 *  '00' = full rotating priority,
 *  '01' = fixed priority (ring 0 lowest),
 *  '10' = ring 0 has the highest priority and the remaining rings have
 *         rotating priority,
 *  '11' = reserved, do not use.
 */
#define MLXBF_PKA_FULL_ROTATING_PRIORITY 0x0
#define MLXBF_PKA_FIXED_PRIORITY 0x1
#define MLXBF_PKA_RING_0_HAS_THE_HIGHEST_PRIORITY 0x2
#define MLXBF_PKA_RESERVED 0x3
#define MLXBF_PKA_RING_OPTIONS_PRIORITY MLXBF_PKA_FULL_ROTATING_PRIORITY

/*
 * 'Signature' byte used because the ring options are transferred through RAM
 * which does not have a defined reset value.  The EIP-154  master controller
 * keeps reading the MLXBF_PKA_RING_OPTIONS word at start-up until the
 * 'Signature' byte contains 0x46 and the 'Reserved' field contains zero.
 */
#define MLXBF_PKA_RING_OPTIONS_SIGNATURE_BYTE 0x46

/*
 * Order of the result reporting: Two schemas are available:
 *  InOrder    - This means that the results will be reported in the same order
 *               as the commands were provided.
 *  OutOfOrder - This means that the results are reported as soon as they are
 *               available
 */
#define MLXBF_PKA_RING_TYPE_IN_ORDER_BIT 1
#define MLXBF_PKA_RING_TYPE_OUT_OF_ORDER_BIT 0
#define MLXBF_PKA_RING_TYPE_IN_ORDER MLXBF_PKA_RING_TYPE_OUT_OF_ORDER_BIT

/*
 * Byte order of the data written/read to/from Rings.
 *  Little Endian (LE) - The least significant bytes have the lowest address.
 *  Big    Endian (BE) - The most significant bytes come first.
 */
#define MLXBF_PKA_RING_BYTE_ORDER_LE 0
#define MLXBF_PKA_RING_BYTE_ORDER_BE 1
#define MLXBF_PKA_RING_BYTE_ORDER MLXBF_PKA_RING_BYTE_ORDER_LE

/*
 * 'trng_clk_on' mask for PKA Clock Switch Forcing Register. Turn on the
 * TRNG clock. When the TRNG is controlled via the Host slave interface,
 * this engine needs to be turned on by setting bit 11.
 */
#define MLXBF_PKA_CLK_FORCE_TRNG_ON 0x800

/* Number of TRNG Output registers */
#define MLXBF_PKA_TRNG_OUTPUT_CNT 4

/* TRNG Configuration */
#define MLXBF_PKA_TRNG_CONFIG_REG_VAL 0x00020008
/* TRNG Alarm Counter Register Value */
#define MLXBF_PKA_TRNG_ALARMCNT_REG_VAL 0x000200FF
/* TRNG FRO Enable Register Value */
#define MLXBF_PKA_TRNG_FROENABLE_REG_VAL 0x00FFFFFF
/*
 * TRNG Control Register Value; Set bit 10 to start the EIP-76 a.k.a TRNG
 * engine, gathering entropy from the FROs.
 */
#define MLXBF_PKA_TRNG_CONTROL_REG_VAL 0x00000400
/* TRNG Status bits */
#define MLXBF_PKA_TRNG_STATUS_READY 0x1
#define MLXBF_PKA_TRNG_STATUS_SHUTDOWN_OFLO 0x2

#endif /* __MLXBF_PKA_CONFIG_H__ */
