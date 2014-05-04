/*
 * drivers/net/rocker.c - Rocker switch device driver
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <asm-generic/io-64-nonatomic-lo-hi.h>
#include <generated/utsrelease.h>

#include "rocker.h"

static const char rocker_driver_name[] = "rocker";

static DEFINE_PCI_DEVICE_TABLE(rocker_pci_id_table) = {
	{PCI_VDEVICE(REDHAT, PCI_DEVICE_ID_REDHAT_ROCKER)},
	{0}
};

struct rocker;

struct rocker_port {
	struct net_device *dev;
	struct rocker *rocker;
	unsigned port_number;
};

struct rocker {
	struct pci_dev *pdev;
	u8 __iomem *hw_addr;
	wait_queue_head_t wait;
	u32 status;
	unsigned port_count;
	struct rocker_port **ports;
	struct {
		u64 id;
	} hw;
};

#define rocker_write32(rocker, reg, val)	\
	writel((val), (rocker)->hw_addr + (ROCKER_ ## reg))
#define rocker_read32(rocker, reg)	\
	readl((rocker)->hw_addr + (ROCKER_ ## reg))
#define rocker_write64(rocker, reg, val)	\
	writeq((val), (rocker)->hw_addr + (ROCKER_ ## reg))
#define rocker_read64(rocker, reg)	\
	readq((rocker)->hw_addr + (ROCKER_ ## reg))

static int rocker_reg_test(struct rocker *rocker)
{
	struct pci_dev *pdev = rocker->pdev;
	u64 test_reg;
	u64 rnd;

	rnd = prandom_u32();
	rnd >>= 1;
	rocker_write32(rocker, TEST_REG, rnd);
	test_reg = rocker_read32(rocker, TEST_REG);
	if (test_reg != rnd * 2) {
		dev_err(&pdev->dev, "unexpected 32bit register value %08llx, expected %08llx\n",
			test_reg, rnd * 2);
		return -EIO;
	}

	rnd = prandom_u32();
	rnd <<= 31;
	rnd |= prandom_u32();
	rocker_write64(rocker, TEST_REG64, rnd);
	test_reg = rocker_read64(rocker, TEST_REG64);
	if (test_reg != rnd * 2) {
		dev_err(&pdev->dev, "unexpected 64bit register value %16llx, expected %16llx\n",
			test_reg, rnd * 2);
		return -EIO;
	}

	return 0;
}

static int rocker_dma_test_one(struct rocker *rocker, u32 test_type,
			       dma_addr_t dma_handle, unsigned char *buf,
			       unsigned char *expect, size_t size)
{
	struct pci_dev *pdev = rocker->pdev;
	int i;

	rocker_write32(rocker, TEST_DMA_CTRL, test_type);

	wait_event_timeout(rocker->wait, rocker->status, HZ / 10);
	if (!rocker->status) {
		dev_err(&pdev->dev, "no interrupt received within a timeout\n");
		return -EIO;
	}

	for (i = 0; i < size; i++) {
		if (buf[i] != expect[i]) {
			dev_err(&pdev->dev, "unexpected memory content %02x at byte %x\n, %02x expected",
				buf[i], i, expect[i]);
			return -EIO;
		}
	}
	return 0;
}

#define ROCKER_TEST_DMA_BUF_SIZE (PAGE_SIZE * 4)
#define ROCKER_TEST_DMA_FILL_PATTERN 0x96

static int rocker_dma_test_offset(struct rocker *rocker, int offset)
{
	struct pci_dev *pdev = rocker->pdev;
	unsigned char *alloc;
	unsigned char *buf;
	unsigned char *expect;
	dma_addr_t dma_handle;
	int i;
	int err;

	alloc = kzalloc(ROCKER_TEST_DMA_BUF_SIZE * 2 + offset, GFP_KERNEL | GFP_DMA);
	if (!alloc)
		return -ENOMEM;
	buf = alloc + offset;
	expect = buf + ROCKER_TEST_DMA_BUF_SIZE;

	dma_handle = pci_map_single(pdev, buf, ROCKER_TEST_DMA_BUF_SIZE,
				    PCI_DMA_BIDIRECTIONAL);
	if (pci_dma_mapping_error(pdev, dma_handle)) {
		err = -EIO;
		goto free_alloc;
	}

	rocker_write64(rocker, TEST_DMA_ADDR, dma_handle);
	rocker_write32(rocker, TEST_DMA_SIZE, ROCKER_TEST_DMA_BUF_SIZE);
	rocker_write32(rocker, IRQ_MASK, ROCKER_IRQ_TEST_DMA_DONE);

	memset(expect, ROCKER_TEST_DMA_FILL_PATTERN, ROCKER_TEST_DMA_BUF_SIZE);
	err = rocker_dma_test_one(rocker, ROCKER_TEST_DMA_CTRL_FILL,
				  dma_handle, buf, expect,
				  ROCKER_TEST_DMA_BUF_SIZE);
	if (err)
		goto unmap;

	memset(expect, 0, ROCKER_TEST_DMA_BUF_SIZE);
	err = rocker_dma_test_one(rocker, ROCKER_TEST_DMA_CTRL_CLEAR,
				  dma_handle, buf, expect,
				  ROCKER_TEST_DMA_BUF_SIZE);
	if (err)
		goto unmap;

	prandom_bytes(buf, ROCKER_TEST_DMA_BUF_SIZE);
	for (i = 0; i < ROCKER_TEST_DMA_BUF_SIZE; i++)
		expect[i] = ~buf[i];
	err = rocker_dma_test_one(rocker, ROCKER_TEST_DMA_CTRL_INVERT,
				  dma_handle, buf, expect,
				  ROCKER_TEST_DMA_BUF_SIZE);
	if (err)
		goto unmap;


unmap:
	pci_unmap_single(pdev, dma_handle, ROCKER_TEST_DMA_BUF_SIZE,
			 PCI_DMA_BIDIRECTIONAL);
free_alloc:
	kfree(alloc);

	return err;
}

static int rocker_dma_test(struct rocker *rocker)
{
	int i;
	int err;

	for (i = 0; i < 8; i++) {
		err = rocker_dma_test_offset(rocker, i);
		if (err)
			return err;
	}
	return 0;
}

static irqreturn_t rocker_intr_test_irq_handler(int irq, void *dev_id)
{
	struct rocker *rocker = dev_id;
	u32 status = rocker_read32(rocker, IRQ_STAT);

	if (status == 0)
		return IRQ_NONE;

	rocker->status = status;
	wake_up(&rocker->wait);

	return IRQ_HANDLED;
}

static int rocker_basic_hw_test(struct rocker *rocker)
{
	struct pci_dev *pdev = rocker->pdev;
	u32 rnd;
	int err;

	err = rocker_reg_test(rocker);
	if (err) {
		dev_err(&pdev->dev, "reg test failed\n");
		return err;
	}

	init_waitqueue_head(&rocker->wait);
	err = request_irq(pdev->irq, rocker_intr_test_irq_handler, 0,
			  rocker_driver_name, rocker);
	if (err) {
		dev_err(&pdev->dev, "cannot assign irq %d\n", pdev->irq);
		return err;
	}

	rocker->status = 0;
	rocker_write32(rocker, IRQ_MASK, 0xFFFFFFFF);
	while (!(rnd = prandom_u32()));
	rocker_write32(rocker, TEST_IRQ, rnd);

	wait_event_timeout(rocker->wait, rocker->status, HZ / 10);
	if (!rocker->status) {
		dev_err(&pdev->dev, "no interrupt received within a timeout\n");
		err = -EIO;
		goto free_irq;
	}

	if (rocker->status != rnd) {
		dev_err(&pdev->dev, "enexpected irq status %08x, expected %08x\n",
			rocker->status, rnd);
		err = -EIO;
		goto free_irq;
	}

	err = rocker_dma_test(rocker);
	if (err)
		dev_err(&pdev->dev, "dma test failed\n");

free_irq:
	free_irq(pdev->irq, rocker);
	return err;
}

static void rocker_port_set_enable(struct rocker_port *rocker_port, bool enable)
{
	u64 val = rocker_read64(rocker_port->rocker, PORT_PHYS_ENABLE);

	if (enable)
		val |= 1 << (rocker_port->port_number + 1);
	else
		val &= !(1 << (rocker_port->port_number + 1));
	rocker_write64(rocker_port->rocker, PORT_PHYS_ENABLE, val);
}

static void rocker_port_link_up(struct rocker_port *rocker_port)
{
	rocker_port_set_enable(rocker_port, true);
	netif_carrier_on(rocker_port->dev);
	netdev_info(rocker_port->dev, "Link is up\n");
}

static void rocker_port_link_down(struct rocker_port *rocker_port)
{
	netif_carrier_off(rocker_port->dev);
	rocker_port_set_enable(rocker_port, false);
	netdev_info(rocker_port->dev, "Link is down\n");
}

static void rocker_link_changed(struct rocker *rocker)
{
	u64 link_status = rocker_read64(rocker, PORT_PHYS_LINK_STATUS);
	struct rocker_port *rocker_port;
	bool link_up;
	int i;

	for (i = 0; i < rocker->port_count; i++) {
		rocker_port = rocker->ports[i];
		link_up = link_status & (1 << (rocker_port->port_number + 1));
		if (netif_carrier_ok(rocker_port->dev) != link_up) {
			if (link_up)
				rocker_port_link_up(rocker_port);
			else
				rocker_port_link_down(rocker_port);
		}
	}
}

static irqreturn_t rocker_irq_handler(int irq, void *dev_id)
{
	struct rocker *rocker = dev_id;
	u32 status = rocker_read32(rocker, IRQ_STAT);

	if (status == 0)
		return IRQ_NONE;

	if (status & ROCKER_IRQ_LINK)
		rocker_link_changed(rocker);

	return IRQ_HANDLED;
}

static netdev_tx_t rocker_port_xmit(struct sk_buff *skb, struct net_device *dev)
{
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int rocker_port_swdev_get_id(struct net_device *dev,
				    struct netdev_phys_item_id *psid)
{
	struct rocker_port *rocker_port = netdev_priv(dev);
	struct rocker *rocker = rocker_port->rocker;

	psid->id_len = sizeof(rocker->hw.id);
	memcpy(&psid->id, &rocker->hw.id, psid->id_len);
	return 0;
}

static const struct net_device_ops rocker_port_netdev_ops = {
	.ndo_start_xmit		= rocker_port_xmit,
	.ndo_swdev_get_id	= rocker_port_swdev_get_id,
};

static void rocker_port_get_drvinfo(struct net_device *dev,
				    struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->driver, rocker_driver_name, sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, UTS_RELEASE, sizeof(drvinfo->version));
}

static const struct ethtool_ops rocker_port_ethtool_ops = {
	.get_drvinfo		= rocker_port_get_drvinfo,
	.get_link		= ethtool_op_get_link,
};

static void rocker_remove_ports(struct rocker *rocker)
{
	int i;

	for (i = 0; i < rocker->port_count; i++)
		unregister_netdev(rocker->ports[i]->dev);
	kfree(rocker->ports);
}

static int rocker_probe_port(struct rocker *rocker, unsigned port_number)
{
	struct pci_dev *pdev = rocker->pdev;
	struct rocker_port *rocker_port;
	struct net_device *dev;
	int err;

	dev = alloc_etherdev(sizeof(struct rocker_port));
	if (!dev)
		return -ENOMEM;
	rocker_port = netdev_priv(dev);
	rocker_port->dev = dev;
	rocker_port->rocker = rocker;
	rocker_port->port_number = port_number;

	eth_hw_addr_random(dev);
	dev->netdev_ops = &rocker_port_netdev_ops;
	dev->ethtool_ops = &rocker_port_ethtool_ops;
	netif_carrier_off(dev);

	err = register_netdev(dev);
	if (err) {
		dev_err(&pdev->dev, "register_netdev failed\n");
		goto free_netdev;
	}
	rocker->ports[port_number] = rocker_port;
	return 0;

free_netdev:
	free_netdev(dev);
	return err;
}

static int rocker_probe_ports(struct rocker *rocker)
{
	int i;
	size_t alloc_size;
	int err;

	rocker->port_count = rocker_read32(rocker, PORT_PHYS_COUNT);
	alloc_size = sizeof(struct rocker_port *) * rocker->port_count;
	rocker->ports = kmalloc(alloc_size, GFP_KERNEL);
	for (i = 0; i < rocker->port_count; i++) {
		err = rocker_probe_port(rocker, i);
		if (err)
			goto remove_ports;
	}
	return 0;

remove_ports:
	rocker_remove_ports(rocker);
	return err;
}

static int rocker_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct rocker *rocker;
	int err;

	rocker = kmalloc(sizeof(*rocker), GFP_KERNEL);
	if (!rocker)
		return -ENOMEM;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "pci_enable_device failed\n");
		goto err_pci_enable_device;
	}

	err = pci_request_regions(pdev, rocker_driver_name);
	if (err) {
		dev_err(&pdev->dev, "pci_request_regions failed\n");
		goto err_pci_request_regions;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (!err) {
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
		if (err) {
			dev_err(&pdev->dev, "pci_set_consistent_dma_mask failed\n");
			goto err_pci_set_dma_mask;
		}
	} else {
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "pci_set_dma_mask failed\n");
			goto err_pci_set_dma_mask;
		}
	}

	if (pci_resource_len(pdev, 0) < ROCKER_PCI_BAR0_SIZE) {
		dev_err(&pdev->dev, "invalid PCI region size\n");
		goto err_pci_resource_len_check;
	}

	rocker->hw_addr = ioremap(pci_resource_start(pdev, 0),
				  pci_resource_len(pdev, 0));
	if (!rocker->hw_addr) {
		dev_err(&pdev->dev, "ioremap failed\n");
		err = -EIO;
		goto err_ioremap;
	}
	pci_set_master(pdev);

	rocker->pdev = pdev;
	pci_set_drvdata(pdev, rocker);

	err = rocker_basic_hw_test(rocker);
	if (err) {
		dev_err(&pdev->dev, "basic hw test failed\n");
		goto err_basic_hw_test;
	}

	rocker_write32(rocker, CONTROL, ROCKER_CONTROL_RESET);

	err = request_irq(pdev->irq, rocker_irq_handler, 0,
			  rocker_driver_name, rocker);
	if (err) {
		dev_err(&pdev->dev, "cannot assign irq %d\n", pdev->irq);
		goto err_request_irq;
	}
	rocker_write32(rocker, IRQ_MASK, ROCKER_IRQ_LINK |
					 ROCKER_IRQ_TX_DMA_DONE |
					 ROCKER_IRQ_RX_DMA_DONE |
					 ROCKER_IRQ_CMD_DMA_DONE |
					 ROCKER_IRQ_EVENT_DMA_DONE);

	rocker->hw.id = rocker_read64(rocker, SWITCH_ID);

	err = rocker_probe_ports(rocker);
	if (err) {
		dev_err(&pdev->dev, "failed to probe ports\n");
		goto err_probe_ports;
	}

	rocker_link_changed(rocker);

	dev_info(&pdev->dev, "Rocker switch with id %016llx\n", rocker->hw.id);

	return 0;

err_probe_ports:
	free_irq(pdev->irq, rocker);
err_request_irq:
err_basic_hw_test:
	iounmap(rocker->hw_addr);
err_ioremap:
err_pci_resource_len_check:
err_pci_set_dma_mask:
	pci_release_regions(pdev);
err_pci_request_regions:
	pci_disable_device(pdev);
err_pci_enable_device:
	kfree(rocker);
	return err;
}

static void rocker_remove(struct pci_dev *pdev)
{
	struct rocker *rocker = pci_get_drvdata(pdev);

	rocker_remove_ports(rocker);
	free_irq(rocker->pdev->irq, rocker);
	iounmap(rocker->hw_addr);
	pci_release_regions(rocker->pdev);
	pci_disable_device(rocker->pdev);
	kfree(rocker);
}

static struct pci_driver rocker_pci_driver = {
	.name		= rocker_driver_name,
	.id_table	= rocker_pci_id_table,
	.probe		= rocker_probe,
	.remove		= rocker_remove,
};

static int __init rocker_module_init(void)
{
	return pci_register_driver(&rocker_pci_driver);
}

static void __exit rocker_module_exit(void)
{
	pci_unregister_driver(&rocker_pci_driver);
}

module_init(rocker_module_init);
module_exit(rocker_module_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jiri Pirko <jiri@resnulli.us>");
MODULE_DESCRIPTION("Rocker switch device driver");
MODULE_DEVICE_TABLE(pci, rocker_pci_id_table);
