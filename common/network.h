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

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>

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
 * Setup (or remove) local network route.
 */
int
network_setup_route(const char *net_dst, const char *dev, bool add);

/**
 * Add (or remove) simple iptables rule.
 */
int
network_iptables(const char *table, const char *chain, const char* net_src, const char *jmp_target, bool add);

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

#endif /* NETWORK_H */

