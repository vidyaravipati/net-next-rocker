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

#define ROCKER_PCI_BAR0_SIZE		0x2000

/*
 * MSI-X vectors
 */

enum {
	ROCKER_MSIX_VEC_CMD,
	ROCKER_MSIX_VEC_EVENT,
	ROCKER_MSIX_VEC_TEST,
	ROCKER_MSIX_VEC_RESERVED0,
	__ROCKER_MSIX_VEC_TX,
	__ROCKER_MSIX_VEC_RX,
#define ROCKER_MSIX_VEC_TX(port) \
	(__ROCKER_MSIX_VEC_TX + (port * 2))
#define ROCKER_MSIX_VEC_RX(port) \
	(__ROCKER_MSIX_VEC_RX + (port * 2))
#define ROCKER_MSIX_VEC_COUNT(portcnt) \
	(ROCKER_MSIX_VEC_RX(portcnt) + 1)
};

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
 * Rocker DMA ring register offsets
 */
#define ROCKER_DMA_DESC_ADDR(x)		(0x1000 + (x) * 32)  /* 8-byte */
#define ROCKER_DMA_DESC_SIZE(x)		(0x1008 + (x) * 32)
#define ROCKER_DMA_DESC_HEAD(x)		(0x100c + (x) * 32)
#define ROCKER_DMA_DESC_TAIL(x)		(0x1010 + (x) * 32)
#define ROCKER_DMA_DESC_CTRL(x)		(0x1014 + (x) * 32)
#define ROCKER_DMA_DESC_RES1(x)		(0x1018 + (x) * 32)
#define ROCKER_DMA_DESC_RES2(x)		(0x101c + (x) * 32)

/*
 * Rocker DMA ring types
 */
enum rocker_dma_type {
	ROCKER_DMA_CMD,
	ROCKER_DMA_EVENT,
	__ROCKER_DMA_TX,
	__ROCKER_DMA_RX,
#define ROCKER_DMA_TX(port) (__ROCKER_DMA_TX + (port) * 2)
#define ROCKER_DMA_RX(port) (__ROCKER_DMA_RX + (port) * 2)
};


/*
 * Rocker DMA ring size limits and default sizes
 */
#define ROCKER_DMA_SIZE_MIN		2ul
#define ROCKER_DMA_SIZE_MAX		65536ul
#define ROCKER_DMA_CMD_DEFAULT_SIZE	32ul
#define ROCKER_DMA_EVENT_DEFAULT_SIZE	32ul
#define ROCKER_DMA_TX_DEFAULT_SIZE	64ul
#define ROCKER_DMA_TX_DESC_SIZE		256

/*
 * Rocker DMA descriptor struct
 */
struct rocker_dma_desc {
	u64 buf_addr;
	u64 cookie;
	u16 buf_size;
	u16 tlv_size;
	u16 resv[5];
	u16 comp_err;
} __attribute__((packed, aligned (8)));

#define ROCKER_DMA_DESC_COMP_ERR_GEN	(1 << 15)

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
	ROCKER_TLV_CMD_TYPE_UNSPEC,
	ROCKER_TLV_CMD_TYPE_GET_PORT_SETTINGS,
	ROCKER_TLV_CMD_TYPE_SET_PORT_SETTINGS,
	ROCKER_TLV_CMD_TYPE_FLOW,
	ROCKER_TLV_CMD_TYPE_TRUNK,
	ROCKER_TLV_CMD_TYPE_BRIDGE,

	__ROCKER_TLV_CMD_TYPE_MAX,
	ROCKER_TLV_CMD_TYPE_MAX = __ROCKER_TLV_CMD_TYPE_MAX - 1,
};

enum {
	ROCKER_TLV_CMD_PORT_SETTINGS_UNSPEC,
	ROCKER_TLV_CMD_PORT_SETTINGS_LPORT,		/* u16 */
	ROCKER_TLV_CMD_PORT_SETTINGS_SPEED,		/* u32 */
	ROCKER_TLV_CMD_PORT_SETTINGS_DUPLEX,		/* u8 */
	ROCKER_TLV_CMD_PORT_SETTINGS_AUTONEG,		/* u8 */
	ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR,		/* binary */
	ROCKER_TLV_CMD_PORT_SETTINGS_MODE,		/* u8 */

	__ROCKER_TLV_CMD_PORT_SETTINGS_MAX,
	ROCKER_TLV_CMD_PORT_SETTINGS_MAX = __ROCKER_TLV_CMD_PORT_SETTINGS_MAX - 1,
};

enum {
	ROCKER_TLV_RX_UNSPEC,
	ROCKER_TLV_RX_LPORT,		/* u16 */
	ROCKER_TLV_RX_FLAGS,		/* u16, see ROCKER_RX_FLAGS_ */
	ROCKER_TLV_RX_CSUM,		/* u16 */
	ROCKER_TLV_RX_PACKET,		/* binary */

	__ROCKER_TLV_RX_MAX,
	ROCKER_TLV_RX_MAX = __ROCKER_TLV_RX_MAX - 1,
};

#define ROCKER_RX_FLAGS_IPV4			(1 << 0)
#define ROCKER_RX_FLAGS_IPV6			(1 << 1)
#define ROCKER_RX_FLAGS_CSUM_CALC		(1 << 2)
#define ROCKER_RX_FLAGS_IPV4_CSUM_GOOD		(1 << 3)
#define ROCKER_RX_FLAGS_IP_FRAG			(1 << 4)
#define ROCKER_RX_FLAGS_TCP			(1 << 5)
#define ROCKER_RX_FLAGS_UDP			(1 << 6)
#define ROCKER_RX_FLAGS_TCP_UDP_CSUM_GOOD	(1 << 7)

enum {
	ROCKER_TLV_TX_UNSPEC,
	ROCKER_TLV_TX_LPORT,		/* u16 */
	ROCKER_TLV_TX_OFFLOAD,		/* u8, see ROCKER_TX_OFFLOAD_ */
	ROCKER_TLV_TX_L3_CSUM_OFF,	/* u16 */
	ROCKER_TLV_TX_TSO_MSS,		/* u16 */
	ROCKER_TLV_TX_TSO_HDR_LEN,	/* u16 */
	ROCKER_TLV_TX_FRAGS,		/* array */

	__ROCKER_TLV_TX_MAX,
	ROCKER_TLV_TX_MAX = __ROCKER_TLV_TX_MAX - 1,
};

#define ROCKER_TX_OFFLOAD_NONE		0
#define ROCKER_TX_OFFLOAD_IP_CSUM	1
#define ROCKER_TX_OFFLOAD_TCP_UDP_CSUM	2
#define ROCKER_TX_OFFLOAD_L3_CSUM	3
#define ROCKER_TX_OFFLOAD_TSO		4

#define ROCKER_TX_FRAGS_MAX		16

enum {
	ROCKER_TLV_TX_FRAG_UNSPEC,
	ROCKER_TLV_TX_FRAG,		/* nest */

	__ROCKER_TLV_TX_FRAG_MAX,
	ROCKER_TLV_TX_FRAG_MAX = __ROCKER_TLV_TX_FRAG_MAX - 1,
};

enum {
	ROCKER_TLV_TX_FRAG_ATTR_UNSPEC,
	ROCKER_TLV_TX_FRAG_ATTR_ADDR,	/* u64 */
	ROCKER_TLV_TX_FRAG_ATTR_LEN,	/* u16 */

	__ROCKER_TLV_TX_FRAG_ATTR_MAX,
	ROCKER_TLV_TX_FRAG_ATTR_MAX = __ROCKER_TLV_TX_FRAG_ATTR_MAX - 1,
};

/*
 * Rocker general purpose registers
 */
#define ROCKER_CONTROL			0x0300
#define ROCKER_PORT_PHYS_COUNT		0x0304
#define ROCKER_PORT_PHYS_LINK_STATUS	0x0310 /* 8-byte */
#define ROCKER_PORT_PHYS_ENABLE		0x0318 /* 8-byte */
#define ROCKER_SWITCH_ID		0x0320 /* 8-byte */

/*
 * Rocker control bits
 */
#define ROCKER_CONTROL_RESET		(1 << 0)

#endif
