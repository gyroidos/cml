/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 * @file network.h
 *
 * Provides functions for network configuration.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>
#include "list.h"

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
network_remove_ip_addr_from_interface(const char *host_addr, uint32_t host_subnet,
				      const char *host_if);

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
network_iptables(const char *table, const char *chain, const char *net_src, const char *jmp_target,
		 bool add);

/**
 * Setup a localnet portforwarding
 */
int
network_setup_port_forwarding(const char *srcip, uint16_t srcport, const char *dstip,
			      uint16_t dstport, bool enable);

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

/*
 * Generates a list containing names of all available physical network interfaces
 */
list_t *
network_get_physical_interfaces_new(void);

/**
 * Checks if an interface is an wifi interface using sysfs.
 */
bool
network_interface_is_wifi(const char *if_name);

/**
 * This function moves a wifi interface too the netns of pid.
 *
 * This is acomplished by looking up the corresponding phy interface
 * index. After that the request to move the phy interface to the netns
 * is handed over to the kernel using the nl82011 generic netlink interface.
 */
int
network_nl80211_move_ns(const char *if_name, const pid_t pid);

/**
 * This function moves a network interface to the netns of pid.
 *
 * This is acomplished by looking up the corresponding interface index.
 * After that the request to move the interface to the netns is
 * is handed over to the kernel using the rtnetlink interface.
 */
int
network_rtnet_move_ns(const char *ifi_name, const pid_t pid);

/**
 * This function renames a network interface from old_ifi_name to new_ifi_name
 * with a netlink message using the netlink socket.
 * @param old_ifi_name The old interface name.
 * @param new_ifi_name The new interface name.
 * @return 0 on success, -1 on error
 */
int
network_rename_ifi(const char *old_ifi_name, const char *new_ifi_name);

/**
 * Convert a String representing a mac address ,e.g., "00:11:22:33:44:55"
 * to the corresponding byte array.
 * @param mac_str String representing the mac
 * @param mac buffer for the resulting byte array
 * @return 0 on success, -1 on error
 */
int
network_str_to_mac_addr(const char *mac_str, uint8_t mac[6]);

/**
 * Constructs a String representation for a mac address.
 * @param mac array to be converted
 * @return The string representing the mac, NULL on error
 */
char *
network_mac_addr_to_str_new(uint8_t mac[6]);

/**
 * Walk through sysfs to find the if name, e.g., shown by ip addr, to the corresponding
 * hardware (mac) address.
 * @param mac array containing the mac address
 * @return The name of the interface
 */
char *
network_get_ifname_by_addr_new(uint8_t mac[6]);

/**
 * Get mac address for network interface given by name.
 * @param ifname network interface name
 * @param mac buffer for the resulting byte array
 * @return 0 on success, -1 on error
 */
int
network_get_mac_by_ifname(const char *ifname, uint8_t mac[6]);

/**
 * Create a Linux bridge device.
 */
int
network_create_bridge(const char *name);

/**
 * Set state of a Linux bridge to "up".
 */
int
network_bridge_set_up(const char *br_name);

/**
 * Add an interface to a Linux bridge.
 */
int
network_bridge_add_port(const char *br_name, const char *prt_name);

/**
 * Remove an interface from a Linux bridge.
 */
int
network_bridge_remove_port(const char *br_name);

/**
 * Delete a Linux bridge.
 */
int
network_delete_bridge(const char *name);

/**
 * Adds/Removes a rule to firewall to drop all input traffic on the
 * physical (bridge-port) interface netif.
 */
int
network_iptables_phys_deny(const char *chain, const char *netif, bool add);

/**
 * Adds/Removes a rule to firewall to allow input traffic of a client
 * by its mac address on the physical (bridge-port) interface netif.
 */
int
network_phys_allow_mac(const char *chain, const char *netif, uint8_t mac[6], bool add);

#endif /* NETWORK_H */
