/*
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/sw_flow.h>
#include <linux/switchdev.h>

#include "datapath.h"
#include "vport-netdev.h"

static int sw_flow_action_create(struct datapath *dp,
				 struct sw_flow_actions **p_actions,
				 struct ovs_flow_actions *acts)
{
	const struct nlattr *attr = acts->actions;
	int len = acts->actions_len;
	const struct nlattr *a;
	int rem;
	struct sw_flow_actions *actions;
	struct sw_flow_action *cur;
	size_t count = 0;
	int err;

	for (a = attr, rem = len; rem > 0; a = nla_next(a, &rem))
		count++;

	actions = kzalloc(sizeof(struct sw_flow_actions) +
			  sizeof(struct sw_flow_action) * count,
			  GFP_KERNEL);
	if (!actions)
		return -ENOMEM;
	actions->count = count;

	cur = actions->actions;
	for (a = attr, rem = len; rem > 0; a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			{
				struct vport *vport;

				vport = ovs_vport_ovsl_rcu(dp, nla_get_u32(a));
				if (vport->ops->type != OVS_VPORT_TYPE_NETDEV) {
					err = -EOPNOTSUPP;
					goto errout;
				}
				cur->type = SW_FLOW_ACTION_TYPE_OUTPUT;
				cur->output_dev = vport->ops->get_netdev(vport);
			}
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			{
				const struct ovs_action_push_vlan *vlan;

				vlan = nla_data(a);
				cur->type = SW_FLOW_ACTION_TYPE_VLAN_PUSH;
				cur->vlan.vlan_proto = vlan->vlan_tpid;
				cur->vlan.vlan_tci = vlan->vlan_tci;
			}
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			cur->type = SW_FLOW_ACTION_TYPE_VLAN_POP;
			break;

		default:
			err = -EOPNOTSUPP;
			goto errout;
		}
		cur++;
	}
	*p_actions = actions;
	return 0;

errout:
	kfree(actions);
	return err;
}

int ovs_hw_flow_insert(struct datapath *dp, struct ovs_flow *flow)
{
	struct sw_flow_actions *actions;
	struct vport *vport;
	struct net_device *dev;
	int err;

	BUG_ON(flow->flow.actions);

	err = sw_flow_action_create(dp, &actions, flow->sf_acts);
	if (err)
		return err;
	flow->flow.actions = actions;

	rcu_read_lock();
	list_for_each_entry_rcu(vport, &dp->swdev_rep_list, swdev_rep_list) {
		dev = vport->ops->get_netdev(vport);
		BUG_ON(!dev);
		err = swdev_flow_insert(dev, &flow->flow);
		if (err)
			break;
	}
	rcu_read_unlock();

	if (err) {
		kfree(actions);
		flow->flow.actions = NULL;
	}
	return err;
}

int ovs_hw_flow_remove(struct datapath *dp, struct ovs_flow *flow)
{
	struct vport *vport;
	struct net_device *dev;
	int err = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(vport, &dp->swdev_rep_list, swdev_rep_list) {
		dev = vport->ops->get_netdev(vport);
		BUG_ON(!dev);
		err = swdev_flow_remove(dev, &flow->flow);
		if (err)
			break;
	}
	rcu_read_unlock();
	kfree(flow->flow.actions);
	return err;
}

static struct vport *__find_vport_by_swdev_id(struct datapath *dp,
					      struct vport *vport)
{
	struct net_device *dev;
	struct vport *cur_vport;
	struct netdev_phys_item_id id;
	struct netdev_phys_item_id cur_id;
	int i;
	int err;

	dev = vport->ops->get_netdev(vport);
	if (!dev)
		return NULL;
	err = swdev_get_id(dev, &id);
	if (err)
		return NULL;

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		hlist_for_each_entry_rcu(cur_vport, &dp->ports[i],
					 dp_hash_node) {
			if (vport == cur_vport)
				continue;
			if (vport->ops->type != OVS_VPORT_TYPE_NETDEV)
				continue;
			dev = cur_vport->ops->get_netdev(cur_vport);
			if (!dev)
				continue;
			err = swdev_get_id(dev, &cur_id);
			if (err)
				continue;
			if (!memcmp(&id, &cur_id, sizeof(id)))
				return cur_vport;
		}
	}
	return NULL;
}

void ovs_hw_port_add(struct datapath *dp, struct vport *vport)
{
	/* The representative list contains always one port per switch dev id */
	if (!__find_vport_by_swdev_id(dp, vport))
		list_add_rcu(&vport->swdev_rep_list, &dp->swdev_rep_list);
}

void ovs_hw_port_del(struct datapath *dp, struct vport *vport)
{
	list_del_rcu(&vport->swdev_rep_list);
	vport =__find_vport_by_swdev_id(dp, vport);
	if (vport)
		list_add_rcu(&vport->swdev_rep_list, &dp->swdev_rep_list);
}
