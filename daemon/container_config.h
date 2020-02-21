/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

/**
 * @file container_config.h
 *
 * This container configuration module implements abstract settings
 * that represent the configuration of a container.
 * The configuration can be loaded and stored in a file
 * using protobuf.
 */

#ifndef C_CONFIG_H
#define C_CONFIG_H

#include "common/list.h"

#include "container.h"
#include "mount.h"

#include <stdint.h>
#include <stdbool.h>

typedef struct container_config container_config_t;

/**
 * Create a new container_config object which can be used to parse or write a
 * configuration to a given filename.
 *
 * @param filename Representation of the config on disk. Must NOT be NULL. If
 * the file exists it is used to initially fill the container_config object. 
 * @param buf Config buffer to initialize the config object. If the config
 * file at filename already exists, the config buffer supersedes the content
 * of the config file.
 * @param len Length of the given buf.
 * @return The new container_config_t object or NULL on an error.
 */
container_config_t *
container_config_new(const char *file, const uint8_t *buf, size_t len);

/**
 * Release the container_config_t object.
 */
void
container_config_free(container_config_t *config);

int
container_config_write(const container_config_t *config);

/*************************/
/* GETTER + SETTER       */
/*************************/

/**
 * Get the container name.
 */
const char *
container_config_get_name(const container_config_t *config);

/**
 * Set the container name.
 */
void
container_config_set_name(container_config_t *config, const char *name);

/**
 * Get the 'guest' operating system type.
 */
const char *
container_config_get_guestos(const container_config_t *config);

/**
 * Set the 'guest' operating system type.
 */
void
container_config_set_guestos(container_config_t *config, const char *operatingsystem);

/**
 * Get the configured maximum RAM amount the container may use.
 */
unsigned int
container_config_get_ram_limit(const container_config_t *config);

/**
 * Set the maximum RAM amount the container may use.
 */
void
container_config_set_ram_limit(container_config_t *config, unsigned int ram_limit);

void
container_config_fill_mount(const container_config_t *config, mount_t *mnt);
#if 0
uint64_t
container_config_get_storage_size(const container_config_t *config);

void
container_config_set_storage_size(container_config_t *config, uint64_t storage_size);
#endif

uint32_t
container_config_get_color(const container_config_t *config);

void
container_config_set_color(container_config_t *config, uint32_t color);

container_type_t
container_config_get_type(const container_config_t *config);

uint64_t
container_config_get_guestos_version(const container_config_t *config);

void
container_config_set_guestos_version(container_config_t *config, uint64_t guestos_version);

/**
 * Get the autostart flag which indicates whether the container
 * should be started automatially.
 */
bool
container_config_get_autostart(container_config_t *config);

/**
 * Get the autostart flag which indicates whether the container
 * should be started automatially.
 */
void
container_config_set_autostart(container_config_t *config, bool autostart);

/**
 * Indicates whether the container is allowed to initiate switches to other containers.
 */
bool
container_config_get_allow_container_switch(const container_config_t *config);

/**
 * Sets whether the container is allowed to initiate switches to other containers.
 */
void
container_config_set_allow_container_switch(container_config_t *config, bool container_switch);

/**
 * Indicates whether the container is allowed to be started automatically after a0.
 */
bool
container_config_get_allow_autostart(const container_config_t *config);

/**
 * Sets whether the container is allowed to be started automatically after a0.
 */
void
container_config_set_allow_autostart(container_config_t *config, bool allow_autostart);

/**
 * Provides the list of enabled features in the container's config file
 */
list_t *
container_config_get_feature_list_new(const container_config_t *config);

/**
 * Provides the list of network interfaces assigned to the container from the container's config file
 */

list_t *
container_config_get_net_ifaces_list_new(const container_config_t *config);

/**
 * Provides the list of hardware devices explicitely allowed for the container from the container's config file
 */

char **
container_config_get_dev_allow_list_new(const container_config_t *config);

/**
 * Provides the list of hardware devices exclusively assigned to the container from the container's config file
 */

char **
container_config_get_dev_assign_list_new(const container_config_t *config);

/**
 * Get the dns_server ip addr set for the container.
 */
const char *
container_config_get_dns_server(const container_config_t *config);

/**
 * Indicates whether the container has an own network namespace
 */
bool
container_config_has_netns(const container_config_t *config);

/**
 * Indicates whether the container has an own user namespace
 */
bool
container_config_has_userns(const container_config_t *config);

/**
 * Adds the given interface name to the list of network interfaces assigned to the container
 */
void
container_config_append_net_ifaces(const container_config_t *config, const char *iface);

/**
 * Removes the given interface name from the list of network interfaces assigned to the container
 */
void
container_config_remove_net_ifaces(const container_config_t *config, const char *iface);

/**
 * Reads the container config for vnet interfaces and returns a list of the
 * corresponding container_vnet_cfg structures.
 */
list_t *
container_config_get_vnet_cfg_list_new(const container_config_t *config);

/**
 * Reads the container config for usb devices and returns a list
 * of the corresponding uevent_usbdev_t structures.
 */
list_t *
container_config_get_usbdev_list_new(const container_config_t *config);

/**
 * Returns the container specific array used to appened to evn buffer on start
 */
char **
container_config_get_init_env(const container_config_t *cfg);

/**
 * Returns the size of init env array
 */
size_t
container_config_get_init_env_len(const container_config_t *cfg);

size_t
container_config_get_fifos_len(const container_config_t *config);

char **
container_config_get_fifos(const container_config_t *config);

#endif /* C_CONFIG_H */
