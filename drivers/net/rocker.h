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

#define PCI_VENDOR_ID_REDHAT		0x1b36
#define PCI_DEVICE_ID_REDHAT_ROCKER	0x0006

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

#endif
