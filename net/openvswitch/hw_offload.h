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

#ifndef HW_OFFLOAD_H
#define HW_OFFLOAD_H 1

#include "datapath.h"
#include "flow.h"

int ovs_hw_flow_insert(struct datapath *dp, struct ovs_flow *flow);
int ovs_hw_flow_remove(struct datapath *dp, struct ovs_flow *flow);
void ovs_hw_port_add(struct datapath *dp, struct vport *vport);
void ovs_hw_port_del(struct datapath *dp, struct vport *vport);

#endif
