/*
 * drivers/net/dummyswitch.c - Dummy switch device
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/etherdevice.h>
#include <linux/switchdev.h>

#include <net/rtnetlink.h>

struct dummyswport_priv {
	struct netdev_phys_item_id psid;
};

static netdev_tx_t dummyswport_start_xmit(struct sk_buff *skb,
					  struct net_device *dev)
{
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int dummyswport_swdev_get_id(struct net_device *dev,
				    struct netdev_phys_item_id *psid)
{
	struct dummyswport_priv *dsp = netdev_priv(dev);

	memcpy(psid, &dsp->psid, sizeof(*psid));
	return 0;
}

static int dummyswport_change_carrier(struct net_device *dev, bool new_carrier)
{
	if (new_carrier)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);
	return 0;
}

static const struct net_device_ops dummyswport_netdev_ops = {
	.ndo_start_xmit		= dummyswport_start_xmit,
	.ndo_swdev_get_id	= dummyswport_swdev_get_id,
	.ndo_change_carrier	= dummyswport_change_carrier,
};

static void dummyswport_setup(struct net_device *dev)
{
	ether_setup(dev);

	/* Initialize the device structure. */
	dev->netdev_ops = &dummyswport_netdev_ops;
	dev->destructor = free_netdev;

	/* Fill in device structure with ethernet-generic values. */
	dev->tx_queue_len = 0;
	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->features	|= NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_TSO;
	dev->features	|= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX;
	eth_hw_addr_random(dev);
}

static int dummyswport_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS])
		return -EINVAL;
	if (!data || !data[IFLA_DYMMYSWPORT_PHYS_SWITCH_ID])
		return -EINVAL;
	return 0;
}

static int dummyswport_newlink(struct net *src_net, struct net_device *dev,
			       struct nlattr *tb[], struct nlattr *data[])
{
	struct dummyswport_priv *dsp = netdev_priv(dev);
	int err;

	dsp->psid.id_len = nla_len(data[IFLA_DYMMYSWPORT_PHYS_SWITCH_ID]);
	memcpy(dsp->psid.id, nla_data(data[IFLA_DYMMYSWPORT_PHYS_SWITCH_ID]),
	       dsp->psid.id_len);

	err = register_netdevice(dev);
	if (err)
		return err;

	netif_carrier_on(dev);

	return 0;
}

static const struct nla_policy dummyswport_policy[IFLA_DUMMYSWPORT_MAX + 1] = {
	[IFLA_DYMMYSWPORT_PHYS_SWITCH_ID] = { .type = NLA_BINARY,
					      .len = MAX_PHYS_ITEM_ID_LEN },
};

static struct rtnl_link_ops dummyswport_link_ops __read_mostly = {
	.kind		= "dummyswport",
	.priv_size	= sizeof(struct dummyswport_priv),
	.setup		= dummyswport_setup,
	.validate	= dummyswport_validate,
	.newlink	= dummyswport_newlink,
	.policy		= dummyswport_policy,
	.maxtype	= IFLA_DUMMYSWPORT_MAX,
};


/*
 * Module init/exit
 */

static int __init dummysw_module_init(void)
{
	return rtnl_link_register(&dummyswport_link_ops);
}

static void __exit dummysw_module_exit(void)
{
	rtnl_link_unregister(&dummyswport_link_ops);
}

module_init(dummysw_module_init);
module_exit(dummysw_module_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jiri Pirko <jiri@resnulli.us>");
MODULE_DESCRIPTION("Dummy switch device");
MODULE_ALIAS_RTNL_LINK("dummyswport");
