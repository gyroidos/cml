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
 * @file cmld.h
 *
 * This module is the central component of the container management layer daemon.
 * It initializes all other global modules and manages a list of all containers on
 * the device. Furthermore, it implements some glue code in cases where one module
 * want to access functionality of another module, i.e. call a function. For example,
 * the control module used by the command line client calls function of the cmld
 * module which then triggeres the responsible functionality in the other modules.
 */

#ifndef CMLD_H
#define CMLD_H

#include "container.h"
#include "control.h"

/**
 * Initialize the CMLD module.
 *
 * @param path The path of the CMLD configuration file.
 * @return 0 on success, -1 on error
 */
int
cmld_init(const char *path);

/**
 * Reloads all containers from storage path.
 *
 * @return 0 on success, -1 on error
 */
int
cmld_reload_containers(void);

/**
 * Create a container by cloning from another one.
 *
 * @param container The container object to clone from.
 * @return The newly cloned container.
 */
container_t *
cmld_container_create_clone(container_t *container);

/**
 * Create a container by providing a config buffer.
 *
 * @param config The config for the new container in form of a buffer.
 * @return The container of the newly created container.
 */
container_t *
cmld_container_create_from_config(const uint8_t *config, size_t config_len);

/**
 * Create a container from a config file.
 *
 * @param config_path Path to the config file.
 * @return The container of the newly created container.
 */
//container_t *
//cmld_container_create_from_file(char const *config_path);

int
cmld_container_destroy(container_t *container);

container_t *
cmld_containers_get_a0();

/**
 * Start a container if it is not already started
 *
 * @param container The container to be started.
 * @param key The key used to decrypt the containers images.
 * @return 0 if success, -1 otherwise.
 */
int
cmld_container_start(container_t *container, const char *key);

int
cmld_container_start_with_smartcard(control_t *control, container_t *container, const char *passwd);

int
cmld_get_control_gui_sock(void);

int
cmld_container_stop(container_t *container);

int
cmld_container_freeze(container_t *container);

int
cmld_container_unfreeze(container_t *container);

int
cmld_container_allow_audio(container_t *container);

int
cmld_container_deny_audio(container_t *container);

//bool
//cmld_container_exists(container_t *container);

//const char *
//cmld_container_getstate(container_t *container);

int
cmld_container_snapshot(container_t *container);

int
cmld_container_wipe(container_t *container);

void
cmld_wipe_device();

container_t *
cmld_container_get_by_uuid(uuid_t *uuid);

int
cmld_containers_stop();

/* state as parameter? */
//void
//cmld_containers_foreach(/*function, params*/);

//void
//cmld_containers_foreach_running();

//void
//cmld_containers_foreach_suspended();

int
cmld_containers_get_count();

container_t *
cmld_container_get_by_index(int index);

/**
 * Get the device UUID.
 */
const char *
cmld_get_device_uuid(void);

/**
 * Get the base URL for fetching updates (image files, etc.).
 */
const char *
cmld_get_device_update_base_url(void);

/**
 * Get the path where images that can be shared between containers are stored.
 */
const char *
cmld_get_shared_data_dir(void);

/**
 * Get the global wifi state of the device.
 */
bool
cmld_is_wifi_active(void);

/**
 * Get the global internet state of the device. Returns true if the device
 * has either mobile or wifi connectivity.
 */
bool
cmld_is_internet_active(void);

/**
 * Get the dns server set for the host interface in device config
 */
const char *
cmld_get_device_host_dns(void);

/**
 * Get the name of the (privileged) core container from the device config
 */
const char *
cmld_get_c0os(void);

/**
 * Change the pin of the device token.
 * The request is sent asynchronously through lower communication layer.
 *
 * @parma control link to control for responses
 * @param passwd old passphrase/pin
 * @param newpasswd new passphrase/pin which is to be set
 * @return 0 on message delivered to lower levels, -1 message delivery failed
 */
int
cmld_change_device_pin(control_t *control, const char *passwd, const char *newpasswd);

/**
 * Change the device cert during provisioning.
 * The request is sent asynchronously through lower communication layer.
 *
 * @parma control link to control for responses
 * @param cert buffer holding the device certificate
 * @param cert_len size of the certificate buffer
 */
void
cmld_push_device_cert(control_t *control, uint8_t *cert, size_t cert_len);

/**
 * Delete a GuestOS by given name
 * Try to delete the latest GuestOS by the given name. This Function silently
 * rejects attempts to delete the GuestOS of the management container c0.
 *
 * @param guestos_name name of the GuestOS which should be deleted
 */
void
cmld_guestos_delete(const char *guestos_name);

/**
 * Returns the list of currently available physical network interfaces
 * not occupied by an application container. Used to assign theses
 * interfaces to c0 in case of c0 uses a private network namespace.
 */
list_t *
cmld_get_netif_phys_list(void);

/**
 * Removes the interface from cmld's list of available physical network
 * interfaces. This is used during container config phases, where network
 * interfaces are assigned directly to a container. The remaining physical
 * interfaces are than assigned to the first privileged container with a
 * private network namespace (usually c0).
 *
 * @param if_name name of the interface which should be removed.
 * @return true if iface was available and removed, false otherwise.
 */
bool
cmld_netif_phys_remove_by_name(const char *if_name);

/**
 * Adds the given interface to cmld's list of available physical network
 * interfaces. This is used during runtime if a container releases its
 * assignment.
 *
 * @param if_name name of the interface which should be added.
 */
void
cmld_netif_phys_add_by_name(const char *if_name);

#endif /* CMLD_H */
