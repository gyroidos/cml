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
 * @file c_net.h
 *
 * This module is responsible for the network setup of containers. It
 * provides interfaces to such networking tasks that have to be executed
 * at the startup of containers. It is e.g. responsible for moving interfaces to different network namespaces,
 * or to set ipv4/gateway/mac addresses. It makes heavy usage of the netlink module.
 */
#ifndef C_NET_H
#define C_NET_H

#include "common/list.h"
#include "container.h"

/* Network structure with specific network settings */
typedef struct c_net c_net_t;

/**
 * Creates a new instances of the c_net structure, which should be done by a container
 */
c_net_t *
c_net_new(container_t *container, bool net_ns, list_t *vnet_cfg_list, list_t *nw_mv_name_list);

/**
 * Frees the struct
 */
void
c_net_free(c_net_t *net);

/**
 * Before clone, initialize c_net structure,
 * create a veth pair and configure the root ns veth
 */
int
c_net_start_pre_clone(c_net_t *net);

/**
 * After the clone, move the container veth into its namespace
 */
int
c_net_start_post_clone(c_net_t *net);

/**
 * In the container's namespace, the container veth is configured
 */
int
c_net_start_child(c_net_t *net);

/**
 * Reset the c_net structure and shut the interface down
 */
void
c_net_cleanup(c_net_t *net);

/*
 * return a new string with the containers ip address which is
 * set on the first network interfcace.
 * returns NULL if the container has no netns
 */
char *
c_net_get_ip_new(c_net_t *net);

/*
 * return a new string with the containers subnet which is
 * set on the first network interfcace.
 * returns NULL if the container has no netns
 */
char *
c_net_get_subnet_new(c_net_t *net);

/**
 * This function moves the network interface to the corresponding namespace,
 * specified by the pid (from root namespace to container namespace).
 * It transmits a netlink message using the netlink socket
 */
int
c_net_move_ifi(const char *ifi_name, const pid_t pid);

/**
 * This function removes the network interface from the corresponding namespace,
 * specified by the pid
 */
int
c_net_remove_ifi(const char *ifi_name, const pid_t pid);

/**
 * This funtion provides a list of conatiner_net_cfg_t* objects
 * which contain the name of an interface inside the container and the
 * corresponding interface name of the endpoint in the root network namespace.
 */
list_t *
c_net_get_interface_mapping_new(c_net_t *net);

#endif /* C_NET_H */
