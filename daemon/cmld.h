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
#include "unit.h"
#include "control.h"

#ifndef DEFAULT_BASE_PATH
#define DEFAULT_BASE_PATH "/data/cml"
#endif
#ifndef DEFAULT_CONF_BASE_PATH
#define DEFAULT_CONF_BASE_PATH "/data/cml"
#endif
#ifndef LOGFILE_DIR
#define LOGFILE_DIR "/data/logs"
#endif

#define PROVISIONED_FILE_NAME "_cml_provisioned_"

#define CMLD_STORAGE_FREE_THRESHOLD 0.2 // 20% reserved space

#define UID_MAX 65536

/**
 * Enum represents different commands to control a container
 */
typedef enum { CMLD_CONTAINER_CTRL_START, CMLD_CONTAINER_CTRL_STOP } cmld_container_ctrl_t;

/**
 * Initialize the CMLD module.
 *
 * 1st stage initialization including startup of SCD
 *
 * @param path The path of the CMLD configuration file.
 * @return 0 on success, -1 on error
 */
int
cmld_init_stage_unit(const char *path);

/**
 * Notify cmld about unit state change during early init stage
 */
void
cmld_init_stage_unit_notify(unit_t *unit);

/**
 * Initialize the CMLD module.
 *
 * 2nd stage initialization which already needs SCD running
 * Triggered by SCD module
 *
 * @return 0 on success, -1 on error
 */
int
cmld_init_stage_container(void);

/**
 * Cleans up the CMLD module.
 */
void
cmld_cleanup(void);

/**
 * Adds an externaly generated container, e.g. by oci module
 */
void
cmld_containers_add(container_t *container);

/**
 * Reloads all containers from storage path.
 *
 * @return 0 on success, -1 on error
 */
int
cmld_reload_containers(void);

/**
 * Reloads the specified container
 *
 * @param uuid The uuid of the container
 * @param path  The path of the container
 * @return 0 on success, -1 on error
 */
container_t *
cmld_reload_container(const uuid_t *uuid, const char *path);

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
 * @param config_len Length of the given buf.
 * @param sig buffer containing the signature of the configuration
 * @param sig_len length of the given sig_buf
 * @param cert buffer containing the certificate of the configuration
 * @param cert_len length of the given cert_buf
 * @return The container of the newly created container.
 */
container_t *
cmld_container_create_from_config(const uint8_t *config, size_t config_len, uint8_t *sig,
				  size_t sig_len, uint8_t *cert, size_t cert_len);

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
cmld_containers_get_c0();

/**
 * Start a container if it is not already started
 * If the containers requires an encryption key it must be set before calling this method.
 *
 * @param container The container to be started.
 * @return 0 if success, -1 otherwise.
 */
int
cmld_container_start(container_t *container);

int
cmld_container_ctrl_with_smartcard(container_t *container, const char *passwd,
				   cmld_container_ctrl_t container_ctrl);

int
cmld_container_ctrl_with_input(container_t *container, cmld_container_ctrl_t container_ctrl,
			       void (*err_cb)(int error, void *data), void *err_cb_data);

void
cmld_container_ctrl_with_input_abort(void);

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
cmld_container_get_by_uuid(const uuid_t *uuid);

container_t *
cmld_container_get_by_uid(int uid);

container_t *
cmld_container_get_by_pid(int pid);

int
cmld_containers_stop(void (*on_all_stopped)(int), int value);

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

int
cmld_units_get_count(void);

unit_t *
cmld_unit_get_by_index(int index);

unit_t *
cmld_unit_get_by_uuid(const uuid_t *uuid);

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
 * Checks if cmld is running in hosted mode (e.g. on debian)
 */
bool
cmld_is_hostedmode_active(void);

/**
 * Checks if signed container configs are enabled.
 */
bool
cmld_uses_signed_configs(void);

bool
cmld_is_device_provisioned(void);

int
cmld_set_device_provisioned(void);

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
 * Change the pin of the token associated to a container.
 *
 * @param container whose token's pin should be changed
 * @param passwd old passphrase/pin
 * @param newpasswd new passphrase/pin which is to be set
 * @return 0 on message delivered to lower levels, -1 message delivery failed
 */
int
cmld_container_change_pin(container_t *container, const char *passwd, const char *newpasswd);

/**
 * Delete a GuestOS by given name
 * Try to delete the latest GuestOS by the given name. This Function silently
 * rejects attempts to delete the GuestOS of the management container c0.
 *
 * @param guestos_name name of the GuestOS which should be deleted
 * @return -1 on failure, 0 on success
 */
int
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
 * interfaces are then assigned to the first privileged container with a
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

/*
 * Reboot device by trying to gracfully stop or killing containers otherwise.
 */
void
cmld_reboot_device(void);
/**
 * This function updates the containers config on storage with the provided
 * protobuf config in buf. A reload is triggerd if the container is stopped
 * to update cmld's view. If the container is not in stopped state a manual
 * reload is necessary.
 */
int
cmld_update_config(container_t *container, uint8_t *buf, size_t buf_len, uint8_t *sig_buf,
		   size_t sig_len, uint8_t *cert_buf, size_t cert_len);

const char *
cmld_get_containers_dir(void);

const char *
cmld_get_wrapped_keys_dir(void);

/**
 * Adds a network interface to the container. If persistent is true, the config file will be modified accordingly
 */
int
cmld_container_add_net_iface(container_t *container, container_pnet_cfg_t *pnet_cfg,
			     bool persistent);

/**
 * Removes a network interface from the container. If persistent is true, the config file will be modified accordingly
 */
int
cmld_container_remove_net_iface(container_t *container, const char *iface, bool persistent);

/**
 * Returns the runtime path for cml's persistent data
 */
const char *
cmld_get_cmld_dir(void);

#endif /* CMLD_H */
