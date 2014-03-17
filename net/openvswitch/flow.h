/*
 * Copyright (c) 2007-2013 Nicira, Inc.
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

#ifndef FLOW_H
#define FLOW_H 1

#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/flex_array.h>
#include <net/inet_ecn.h>
#include <linux/sw_flow.h>

struct sk_buff;

/* Used to memset sw_flow_key_ipv4_tunnel padding. */
#define OVS_TUNNEL_KEY_SIZE					\
	(offsetof(struct sw_flow_key_ipv4_tunnel, ipv4_ttl) +	\
	FIELD_SIZEOF(struct sw_flow_key_ipv4_tunnel, ipv4_ttl))

static inline void ovs_flow_tun_key_init(struct sw_flow_key_ipv4_tunnel *tun_key,
					 const struct iphdr *iph, __be64 tun_id,
					 __be16 tun_flags)
{
	tun_key->tun_id = tun_id;
	tun_key->ipv4_src = iph->saddr;
	tun_key->ipv4_dst = iph->daddr;
	tun_key->ipv4_tos = iph->tos;
	tun_key->ipv4_ttl = iph->ttl;
	tun_key->tun_flags = tun_flags;

	/* clear struct padding. */
	memset((unsigned char *) tun_key + OVS_TUNNEL_KEY_SIZE, 0,
	       sizeof(*tun_key) - OVS_TUNNEL_KEY_SIZE);
}

struct ovs_flow_mask {
	int ref_count;
	struct rcu_head rcu;
	struct list_head list;
	struct sw_flow_mask mask;
};

struct ovs_flow_match {
	struct sw_flow_key *key;
	struct sw_flow_key_range range;
	struct sw_flow_mask *mask;
};

struct ovs_flow_actions {
	struct rcu_head rcu;
	u32 actions_len;
	struct nlattr actions[];
};

struct flow_stats {
	u64 packet_count;		/* Number of packets matched. */
	u64 byte_count;			/* Number of bytes matched. */
	unsigned long used;		/* Last used time (in jiffies). */
	spinlock_t lock;		/* Lock for atomic stats update. */
	__be16 tcp_flags;		/* Union of seen TCP flags. */
};

struct ovs_flow {
	struct rcu_head rcu;
	struct hlist_node hash_node[2];
	u32 hash;
	int stats_last_writer;		/* NUMA-node id of the last writer on
					 * 'stats[0]'.
					 */
	struct sw_flow flow;
	struct ovs_flow_actions __rcu *sf_acts;
	struct flow_stats __rcu *stats[]; /* One for each NUMA node.  First one
					   * is allocated at flow creation time,
					   * the rest are allocated on demand
					   * while holding the 'stats[0].lock'.
					   */
};

struct arp_eth_header {
	__be16      ar_hrd;	/* format of hardware address   */
	__be16      ar_pro;	/* format of protocol address   */
	unsigned char   ar_hln;	/* length of hardware address   */
	unsigned char   ar_pln;	/* length of protocol address   */
	__be16      ar_op;	/* ARP opcode (command)     */

	/* Ethernet+IPv4 specific members. */
	unsigned char       ar_sha[ETH_ALEN];	/* sender hardware address  */
	unsigned char       ar_sip[4];		/* sender IP address        */
	unsigned char       ar_tha[ETH_ALEN];	/* target hardware address  */
	unsigned char       ar_tip[4];		/* target IP address        */
} __packed;

void ovs_flow_stats_update(struct ovs_flow *, struct sk_buff *);
void ovs_flow_stats_get(const struct ovs_flow *, struct ovs_flow_stats *,
			unsigned long *used, __be16 *tcp_flags);
void ovs_flow_stats_clear(struct ovs_flow *);
u64 ovs_flow_used_time(unsigned long flow_jiffies);

int ovs_flow_extract(struct sk_buff *, u16 in_port, struct sw_flow_key *);

#endif /* flow.h */
