/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

/**
 * @file network.h
 *
 * Provides functions for network configuration.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include "list.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>

#include <net/if.h>

/* Bionic misses this flag */
#ifndef IFF_DOWN
#define IFF_DOWN 0x0
#endif

/**
 * Set address of an network interface
 */
int
network_set_ip_addr_of_interface(const char *host_addr, uint32_t host_subnet, const char *host_if);

/**
 * Remove address config from an network interface
 */
int
network_remove_ip_addr_from_interface(const char *host_addr, uint32_t host_subnet, const char *host_if);

/**
 * Setup (or remove) default gateway.
 */
int
network_setup_default_route(const char *gateway, bool add);

/**
 * Setup (or remove) default gateway in routingtable with table_id
 * e.g. used for radio interface
 * (usuall this is table with ID 1022 for rmnet0)
 */
int
network_setup_default_route_table(const char *table_id, const char *gateway, bool add);

/**
 * Setup (or remove) local network route.
 */
int
network_setup_route(const char *net_dst, const char *dev, bool add);

/**
 * Setup (or remove) local network route in table with table_id
 */
int
network_setup_route_table(const char *table_id, const char *net_dst, const char *dev, bool add);

/**
 * Add (or remove) simple iptables rule.
 */
int
network_iptables(const char *table, const char *chain, const char *net_src, const char *jmp_target, bool add);

/**
 * Setup a localnet portforwarding
 */
int
network_setup_port_forwarding(const char *srcip, uint16_t srcport, const char *dstip, uint16_t dstport, bool enable);

/**
 * Enable or disable IP masquerading (forwarding) from given subnet.
 */
int
network_setup_masquerading(const char *subnet, bool enable);

/**
 * Free network interface for instance to be reusable after a container restart
 */
int
network_delete_link(const char *dev);

/**
 * Enable ip forwarding
 */
void
network_enable_ip_forwarding(void);

/**
 * This function brings the network interface ifi_name either ip or down,
 * using either the flag IFF_UP or IFF_DOWN
 * with a netlink message using the netlink socket.
 */
int
network_set_flag(const char *ifi_name, const uint32_t flag);

/**
 * Bring up the loopback interface and shrink its subnet.
 */
int
network_setup_loopback();

/*
 * This functions sets a new rule to do all lookups through routing table main
 * If paramter flush is set to true it also flushes any other rules before.
 */
int
network_routing_rules_set_all_main(bool flush);

/*
 * Moves a network interface from one namespace specified by pid to another
 */
int
network_move_link_ns(pid_t src_pid, pid_t dest_pid, const char *interface);

/*
 * Generates a list containing description lines of network links available in the namespace specified by the given pid
 */
int
network_list_link_ns(pid_t pid, list_t **link_list);

#endif /* NETWORK_H */
