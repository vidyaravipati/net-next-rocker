/*
 * drivers/net/rocker.h - Rocker switch device driver
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ROCKER_H
#define _ROCKER_H

#include <linux/types.h>

#define PCI_VENDOR_ID_REDHAT		0x1b36
#define PCI_DEVICE_ID_REDHAT_ROCKER	0x0006

#define ROCKER_PCI_BAR0_SIZE		0x1000

/*
 * Rocker test registers
 */
#define ROCKER_TEST_REG			0x0010
#define ROCKER_TEST_REG64		0x0018  /* 8-byte */
#define ROCKER_TEST_IRQ			0x0020
#define ROCKER_TEST_DMA_ADDR		0x0028  /* 8-byte */
#define ROCKER_TEST_DMA_SIZE		0x0030
#define ROCKER_TEST_DMA_CTRL		0x0034

/*
 * Rocker test register ctrl
 */
#define ROCKER_TEST_DMA_CTRL_CLEAR	(1 << 0)
#define ROCKER_TEST_DMA_CTRL_FILL	(1 << 1)
#define ROCKER_TEST_DMA_CTRL_INVERT	(1 << 2)

/*
 * Rocker IRQ registers
 */
#define ROCKER_IRQ_MASK			0x0200
#define ROCKER_IRQ_STAT			0x0204

/*
 * Rocker IRQ status bits
 */
#define ROCKER_IRQ_LINK			(1 << 0)
#define ROCKER_IRQ_TX_DMA_DONE		(1 << 1)
#define ROCKER_IRQ_RX_DMA_DONE		(1 << 2)
#define ROCKER_IRQ_CMD_DMA_DONE		(1 << 3)
#define ROCKER_IRQ_EVENT_DMA_DONE	(1 << 4)
#define ROCKER_IRQ_TEST_DMA_DONE	(1 << 5)

/*
 * Rocker DMA ring register offsets
 */
#define ROCKER_DMA_DESC_ADDR(x)		(0x0100 + (x) * 32)  /* 8-byte */
#define ROCKER_DMA_DESC_SIZE(x)		(0x0108 + (x) * 32)
#define ROCKER_DMA_DESC_HEAD(x)		(0x010c + (x) * 32)
#define ROCKER_DMA_DESC_TAIL(x)		(0x0110 + (x) * 32)
#define ROCKER_DMA_DESC_CTRL(x)		(0x0114 + (x) * 32)
#define ROCKER_DMA_DESC_RES1(x)		(0x0118 + (x) * 32)
#define ROCKER_DMA_DESC_RES2(x)		(0x011c + (x) * 32)

/*
 * Rocker DMA ring types
 */
enum rocker_dma_type {
	ROCKER_DMA_TX,
	ROCKER_DMA_RX,
	ROCKER_DMA_CMD,
	ROCKER_DMA_EVENT,
};

/*
 * Rocker DMA ring size limits and default sizes
 */
#define ROCKER_DMA_SIZE_MIN		2ul
#define ROCKER_DMA_SIZE_MAX		65536ul
#define ROCKER_DMA_CMD_DEFAULT_SIZE	32ul

/*
 * Rocker DMA descriptor struct
 */
struct rocker_dma_desc {
	u64 buf_addr;
	u64 cookie;
	u16 buf_size;
	u16 tlv_size;
	u16 comp_status;
} __attribute__((packed, aligned (8)));

#define ROCKER_DMA_DESC_COMP_STATUS_GEN	(1 << 31)

/*
 * Rocker DMA TLV struct
 */
struct rocker_dma_tlv {
	u32 type;
	u16 len;
} __attribute__((packed, aligned (8)));

/*
 * TLVs
 */
enum {
	ROCKER_TLV_CMD_UNSPEC,
	ROCKER_TLV_CMD_TYPE,	/* u16 */
	ROCKER_TLV_CMD_INFO,	/* nest */

	__ROCKER_TLV_CMD_MAX,
	ROCKER_TLV_CMD_MAX = __ROCKER_TLV_CMD_MAX - 1,
};

enum {
	ROCKER_TLV_CMD_TYPE_GET_PORT_SETTINGS,
	ROCKER_TLV_CMD_TYPE_SET_PORT_SETTINGS,
};

enum {
	ROCKER_TLV_CMD_PORT_SETTINGS_UNSPEC,
	ROCKER_TLV_CMD_PORT_SETTINGS_PORT,		/* u16 */
	ROCKER_TLV_CMD_PORT_SETTINGS_SPEED,		/* u32 */
	ROCKER_TLV_CMD_PORT_SETTINGS_MAX_SPEED,		/* u32 */
	ROCKER_TLV_CMD_PORT_SETTINGS_DUPLEX,		/* u8 */
	ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR,		/* binary */

	__ROCKER_TLV_CMD_PORT_SETTINGS_MAX,
	ROCKER_TLV_CMD_PORT_SETTINGS_MAX = __ROCKER_TLV_CMD_PORT_SETTINGS_MAX - 1,
};

/*
 * Rocker general purpose registers
 */
#define ROCKER_CONTROL			0x0300
#define ROCKER_PORT_PHYS_COUNT		0x0304
#define ROCKER_PORT_PHYS_MODE		0x0308 /* 8-byte */
#define ROCKER_PORT_PHYS_LINK_STATUS	0x0310 /* 8-byte */
#define ROCKER_PORT_PHYS_ENABLE		0x0318 /* 8-byte */
#define ROCKER_SWITCH_ID		0x0320 /* 8-byte */

/*
 * Rocker control bits
 */
#define ROCKER_CONTROL_RESET		(1 << 0)

#endif
