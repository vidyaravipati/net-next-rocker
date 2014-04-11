/*
 * net/core/switchdev.c - Switch device API
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/switchdev.h>

/**
 *	swdev_get_id - Get ID of a switch
 *	@dev: port device
 *	@psid: switch ID
 *
 *	Get ID of a switch this port is part of.
 */
int swdev_get_id(struct net_device *dev, struct netdev_phys_item_id *psid)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (!ops->ndo_swdev_get_id)
		return -EOPNOTSUPP;
	return ops->ndo_swdev_get_id(dev, psid);
}
EXPORT_SYMBOL(swdev_get_id);

/**
 *	swdev_flow_insert - Insert a flow into switch
 *	@dev: port device
 *	@flow: flow descriptor
 *
 *	Insert a flow into switch this port is part of.
 */
int swdev_flow_insert(struct net_device *dev, const struct sw_flow *flow)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (!ops->ndo_swdev_flow_insert)
		return -EOPNOTSUPP;
	WARN_ON(!ops->ndo_swdev_get_id);
	BUG_ON(!flow->actions);
	return ops->ndo_swdev_flow_insert(dev, flow);
}
EXPORT_SYMBOL(swdev_flow_insert);

/**
 *	swdev_flow_remove - Remove a flow from switch
 *	@dev: port device
 *	@flow: flow descriptor
 *
 *	Remove a flow from switch this port is part of.
 */
int swdev_flow_remove(struct net_device *dev, const struct sw_flow *flow)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (!ops->ndo_swdev_flow_remove)
		return -EOPNOTSUPP;
	WARN_ON(!ops->ndo_swdev_get_id);
	BUG_ON(!flow->actions);
	return ops->ndo_swdev_flow_remove(dev, flow);
}
EXPORT_SYMBOL(swdev_flow_remove);
