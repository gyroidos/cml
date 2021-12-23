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
 * @file container.h
 *
 * The container module represents a single container and offers an interface for managing it,
 * e.g. starting and stopping, suspending and resuming, etc.
 * Container instances can be created using a low-level constructor with all
 * specific parameters as well as using a high-level constructor which derives
 * the parameters from an abstract configuration string.
 * It furthermore provides the possibility to register observer functions as callbacks
 * which are called when the container's state changes. Container sub-modules
 * are called at certain key events during the execution of a container.
 */

#ifndef CONTAINER_H
#define CONTAINER_H

#include "common/uuid.h"
#include "common/list.h"

#include "guestos.h"

#include <sys/types.h>
#include <stdint.h>
#include <errno.h>

/**
 * Path for mapped service binary
 */
#define CSERVICE_TARGET "/sbin/cservice"

/**
 * Opaque container type.
 * (only used as pointer outside of the container module)
 */
typedef struct container container_t;

/**
 * Opaque container observer callback type.
 * (only used as pointer outside of the container module)
 */
typedef struct container_callback container_callback_t;

/**
 * Represents the type of a container. Could be either
 * CONTAINER_TYPE_CONTAINER for a namspaced os-level virtualized
 * or CONTAINER_TYPE_KVM for a full virtulized execution of the
 * child's init process.
 */
typedef enum {
	CONTAINER_TYPE_CONTAINER = 1,
	CONTAINER_TYPE_KVM,
} container_type_t;

/**
 * Represents the type of token which the container is associated with.
 * The token is used to i.a. wrap the container's disk encryption key.
 */
typedef enum {
	CONTAINER_TOKEN_TYPE_NONE = 1,
	CONTAINER_TOKEN_TYPE_SOFT,
	CONTAINER_TOKEN_TYPE_USB,
} container_token_type_t;

/**
 * Structure to define the configuration for a virtual network
 * interface in a container. It defines the name and if cmld
 * should configure it in its c_net submodule.
 */
typedef struct container_vnet_cfg {
	char *vnet_name;
	char *rootns_name;
	uint8_t vnet_mac[6];
	bool configure;
} container_vnet_cfg_t;

/**
 * Structure to define a phyiscal NIC that is accesible from inside a container.
 * The CML bridges or moves the physical IF into the container and enforces
 * filtering of layer 2 frames based on MAC adresses
 */
typedef struct container_pnet_cfg {
	char *pnet_name;
	bool mac_filter;
	list_t *mac_whitelist;
} container_pnet_cfg_t;

/**
 * Structure to define the configuration of the token associated with the container.
 */
typedef struct container_token_config {
	// the uuid of the token the container is associated with
	uuid_t *uuid;
	// the token's type
	container_token_type_t type;
	// the iSerial of the usbtoken reader
	char *serial;
	// indicates whether the scd has succesfully initialized the token structure
	bool is_init;
	// indicates whether the token has already been provisioned with a platform-bound authentication code
	bool is_paired_with_device;
	// the current DEVPATH of this token,
	// this is needed as the remove/unbind kernel uevents do not contain the USB_SERIAL_SHORT
	char *devpath;
} container_token_config_t;

/**
 * Represents the current container state.
 */
typedef enum {
	CONTAINER_STATE_STOPPED = 1,
	CONTAINER_STATE_STARTING,
	CONTAINER_STATE_BOOTING,
	CONTAINER_STATE_RUNNING,
	CONTAINER_STATE_FREEZING,
	CONTAINER_STATE_FROZEN,
	CONTAINER_STATE_ZOMBIE,
	CONTAINER_STATE_SHUTTING_DOWN,
	CONTAINER_STATE_SETUP,
	CONTAINER_STATE_REBOOTING
} container_state_t;

/**
 * Represents an error that happened during the start of a container.
 */
enum container_error {
	CONTAINER_ERROR = 1,
	CONTAINER_ERROR_VOL,
	CONTAINER_ERROR_INPUT,
	CONTAINER_ERROR_UEVENT,
	CONTAINER_ERROR_CGROUPS,
	CONTAINER_ERROR_NET,
	CONTAINER_ERROR_SERVICE,
	CONTAINER_ERROR_DEVNS,
	CONTAINER_ERROR_USER,
	CONTAINER_ERROR_FIFO,
	CONTAINER_ERROR_TIME,
	CONTAINER_ERROR_AUDIT,
	CONTAINER_ERROR_SMARTCARD
};

typedef struct container_module {
	const char *name;
	void *(*container_new)(container_t *container);
	void (*container_free)(void *data);
	int (*start_post_clone_early)(void *data);
	int (*start_child_early)(void *data);
	int (*start_pre_clone)(void *data);
	int (*start_post_clone)(void *data);
	int (*start_pre_exec)(void *data);
	int (*start_post_exec)(void *data);
	int (*start_child)(void *data);
	int (*start_pre_exec_child)(void *data);
	int (*stop)(void *data);
	void (*cleanup)(void *data, bool rebooting);
	int (*join_ns)(void *data);
} container_module_t;

void
container_register_module(container_module_t *mod);

/**
 * Low-level constructor that creates a new container instance
 * with the given parameters.
 *
 * TODO: Document parameters.
 * @return The new container instance.
 */
container_t *
container_new_internal(const uuid_t *uuid, const char *name, container_type_t type, bool ns_usr,
		       bool ns_net, const guestos_t *os, const char *config_filename,
		       const char *images_folder, mount_t *mnt, unsigned int ram_limit,
		       const char *cpus_allowed, uint32_t color, bool allow_autostart,
		       const char *dns_server, list_t *net_ifaces, char **allowed_devices,
		       char **assigned_devices, list_t *vnet_cfg_list, list_t *usbdev_list,
		       char **init_env, size_t init_env_len, list_t *fifo_list,
		       container_token_type_t ttype, bool usb_pin_entry);

/**
 * Creates a new container container object. There are three different cases
 * depending on the combination of the given parameters:
 *
 * TODO: Use doxygen style to document parameters
 * uuid && !config: In this case, a container with the given UUID must be already
 * present in the given store_path and is loaded from there.
 *
 * !uuid && config: In this case, the container does NOT yet exist and should be
 * created in the given store_path using the given config buffer and a random
 * UUID.
 *
 * uuid && config: In this case, the container does NOT yet exist and should be
 * created in the given store_path using the given config buffer and the given
 * UUID.
 *
 * Optionally sig, cert buffers and length paramters could be set to non zero/NULL
 * values for signature verification of the corresponding configuration contained
 * in config buffer.
 *
 *
 * @return The new container object or NULL if something went wrong.
 */
container_t *
container_new(const char *store_path, const uuid_t *existing_uuid, const uint8_t *config,
	      size_t config_len, uint8_t *sig, size_t sig_len, uint8_t *cert, size_t cert_len);

/*
container_t *
container_new_clone(container_t *container);
*/

/**
 * Free the container's key
*/
void
container_free_key(container_t *container);

/**
 * Free a container data structure. Does not remove the persistent parts of the container,
 * i.e. the configuration and the images.
 */
void
container_free(container_t *container);

/**
 * Returns the name of the container.
 */
const char *
container_get_name(const container_t *container);

/**
 * Returns the uuid of the container.
 */
const uuid_t *
container_get_uuid(const container_t *container);

/**
 * Return the partition table of the container.
 */
const mount_t *
container_get_mount(const container_t *container);

/**
 * Return the partition table of additional mounts for the
 * container's root in setup mode.
 */
const mount_t *
container_get_mount_setup(const container_t *container);

/**
 * Return the associated guest OS object for the container.
 */
const guestos_t *
container_get_os(const container_t *container);

/**
 * Return the directory where the container stores its images.
 */
const char *
container_get_images_dir(const container_t *container);

/**
 * Returns a string describing the container.
 */
const char *
container_get_description(const container_t *container);

/**
 * Gets the PID of the container's init process.
 */
pid_t
container_get_pid(const container_t *container);

/**
 * Returns the PID of the container's trustme service process
 * or -1 if the PID could not be determined.
 */
pid_t
container_get_service_pid(const container_t *container);

/*
 * Prevents Android's low memory killer (OOM killer) from
 * killing the trustme service running in this container.
 */
void
container_oom_protect_service(const container_t *container);

/*
 * Add process with given PID to cgroups of given container
 */
int
container_add_pid_to_cgroups(const container_t *container, pid_t pid);

/**
 * Registers the corresponding handler for container_device_allow
 */
void
container_register_add_pid_to_cgroups_handler(const char *mod_name,
					      int (*handler)(void *data, pid_t pid));

/*
 * Set capapilites for calling process as for given container's init
 */
int
container_set_cap_current_process(const container_t *container);

/**
 * Registers the corresponding handler for container_set_cap_current_process
 */
void
container_register_set_cap_current_process_handler(const char *mod_name,
						   int (*handler)(void *data));

/**
 * Gets the last exit_status of the container's init process.
 * Only valid if the container is stopped...
 */
int
container_get_exit_status(const container_t *container);

/**
 * Gets the (user defined) container color.
 *
 * @param container The container object.
 * @return The container color.
 */
uint32_t
container_get_color(const container_t *container);

/**
 * Gets the (user defined) container color as an RGB string.
 *
 * @param container The container object.
 * @return The container color as an RGB string.
 */
char *
container_get_color_rgb_string(const container_t *container);

/**
 * Get socket fd used to communicate with process executed in container context
 * by using the control run interface
 */
int
container_get_console_sock_cmld(const container_t *container, int session_fd);

/**
 * Registers the corresponding handler for container_get_console_sock_cmld
 */
void
container_register_get_console_sock_cmld_handler(const char *mod_name,
						 int (*handler)(void *data, int session_fd));

/**
 * Remove a container persistently from disk, i.e. remove its configuration and
 * wipe its images. This does not free the container object, this must be done
 * seperately by the module that called container_new in the first place.
 *
 * @param container The container to be destroyed.
 * @return 0 if ok, negative values indicate errors.
 */
int
container_destroy(container_t *container);

/**
 * Wipe a container. Removes the images but keeps the config in place.
 */
int
container_wipe(container_t *container);

/**
 * Write the current configuration of the container to its configuration file.
 */
int
container_write_config(container_t *container);

/**
 * Get the container config filename.
 */
const char *
container_get_config_filename(const container_t *container);

/**
 * Get the information if the container should be privileged. This affects how the container
 * is handled by the trustme-lsm and which capabilities are dropped.
 */
bool
container_is_privileged(const container_t *container);

/**
 * Get the information if the conatiner has encrypted volumes.
 */
bool
container_is_encrypted(const container_t *container);

/**
 * Registers the corresponding handler for container_is_encrypted
 */
void
container_register_is_encrypted_handler(const char *mod_name, bool (*handler)(void *data));

/**
 * Suspends the container before moving it into background
 */
int
container_suspend(container_t *container);

/**
 * Resumes the container.
 */
int
container_resume(container_t *container);

/**
 * Run a given command inside a container
 *
 * @return session id of the running session in the container, -1 on error
 */
int
container_run(const container_t *container, int create_pty, char *cmd, ssize_t argc, char **argv,
	      int session_fd);
/**
 * Registers the corresponding handler for container_run
 */
void
container_register_run_handler(const char *mod_name,
			       int (*handler)(void *data, int create_pty, char *cmd, ssize_t argc,
					      char **argv, int session_fd));

int
container_write_exec_input(const container_t *container, char *exec_input, int session_fd);

/**
 * Registers the corresponding handler for container_write_exec_input
 */
void
container_register_write_exec_input_handler(const char *mod_name,
					    int (*handler)(void *data, char *exec_input,
							   int session_fd));

/**
 * Start the given container using the given key to decrypt its filesystem
 * image(s).
 * This is the main function which sets up isolation mechnsims as part of
 * TSF.CML.Isolation
 *
 * @param container The container to be started.
 * @param key The key used for filesystem image decryption. Can be NULL.
 * @return 0 if the container start was successful. An negative integer to
 * indicate an error. The error is a negative container_error (e.g. CONTAINER_ERROR_VOL).
 * Note that the return value only gives information regarding the first
 * stage of the container start, i.e. before the child process begins with
 * its initialization. For information if the start was completely successful,
 * one should register a callback on the container state and check if the
 * container passes over to the state CONTAINER_STATE_BOOTING, which means
 * that all initialization done in the container module were successful and
 * the boot is now up to the guest OS.
 */
int
container_start(container_t *container); //, const char *key);

/**
 * Gracefully terminate the execution of a container. Gives the container the
 * chance to do a normal shutdown. May take some time to complete and sets the
 * container state to CONTAINER_STATE_SHUTTING_DOWN. Should be used in combination
 * with registering a callback on container state changes.
 */
int
container_stop(container_t *container);

/**
 * Forcefully terminate the execution of a container.
 */
void
container_kill(container_t *container);

/**
 * Register a unix socket which is bound into the container at the given path during
 * container start. The function **must** be called before starting the container
 * and the returned socket is guaranteed to be bound after the container is
 * started, i.e. listen/accept can be called on it.
 *
 *            \-._,, /"/
 *             "-/  l-'
 *               \  /\_
 *               | /\  \
 *              (_/  \  %----.__
 *                    \/ ___    \
 *                  ,'  /   '-.__|_
 *                  |   \'-.___    \
 *                   \__ '/   _/\_  '-.
 *                      \/   /-.  \_   \
 *                      /   |   \_  \   |
 *                     /   / \_   '-'   /
 *                    |    |   '-.___,-'
 *                  ,-'     \
 *                 /         "-._
 *                 |             '-._
 *                  \                \
 *                  | \               |-.
 *                  \  | /'-._,-|    /   \
 *                   | \ |      \    |    $
 *                   \ | /       |  /
 *                    | /         \ |
 *                    |/           |/
 *
 * @param container The container in which the socket will be bound.
 * @param path The path to which the socket will be bound inside the container.
 * @return On success, the newly created socket which will be bound into the
 * container during container start and which will be available to listen/accept
 * after that start. On error, -1 is returned.
 */
int
container_bind_socket_before_start(container_t *container, const char *path);

/**
 * Bind a unix socket into the **already started** container at the given path. The
 * function **must** be called **after** starting the container and the returned
 * socket is guaranteed to be bound when the function returns, i.e. listen/accept
 * can be called on it.
 *
 * @param container The container in which the socket is bound.
 * @param path The path to which the socket is bound inside the container.
 * @return The newly created and bound into the container socket which is immediately
 * ready to call listen+accept on.
 */
int
container_bind_socket_after_start(container_t *container, const char *path);

/**
 * Freeze a container.
 *
 * @return 0 if ok, negative values indicate errors.
 */
int
container_freeze(const container_t *container);

/**
 * Registers the corresponding handler for container_freeze
 */
void
container_register_freeze_handler(const char *mod_name, int (*handler)(void *data));

/**
 * Unfreeze a container.
 *
 * @return 0 if ok, negative values indicate errors.
 */
int
container_unfreeze(const container_t *container);

/**
 * Registers the corresponding handler for container_unfreeze
 */
void
container_register_unfreeze_handler(const char *mod_name, int (*handler)(void *data));

int
container_allow_audio(const container_t *container);

/**
 * Registers the corresponding handler for container_allow_audio
 */
void
container_register_allow_audio_handler(const char *mod_name, int (*handler)(void *data));

int
container_deny_audio(const container_t *container);

/**
 * Registers the corresponding handler for container_deny_audio
 */
void
container_register_deny_audio_handler(const char *mod_name, int (*handler)(void *data));

/**
 * TODO Document 'snapshot' function.
 */
int
container_snapshot(container_t *container);

/**
 * Update the state of the container and notify observers.
 *
 * @param container The container object.
 * @param state The updated state to set.
 */
void
container_set_state(container_t *container, container_state_t state);

/**
 * Returns the current state of the container.
 */
container_state_t
container_get_state(const container_t *container);

/**
 * Returns the previous state of the container.
 */
container_state_t
container_get_prev_state(const container_t *container);

/**
 * Returns the the type of the container.
 */
container_type_t
container_get_type(const container_t *container);

/**
 * Register a callback function which is always called when the container's
 * state changes.
 */
container_callback_t *
container_register_observer(container_t *container,
			    void (*cb)(container_t *, container_callback_t *, void *), void *data);

/**
 * Unregister observer callback.
 */
void
container_unregister_observer(container_t *container, container_callback_t *cb);

/**
 * Gets the container's key previously set by container_set_key or NULL if no key
 * has been set.
 */
const char *
container_get_key(const container_t *container);

/**
 * Sets the key for encrypted storage of the contaier.
 */
void
container_set_key(container_t *container, const char *key);

unsigned int
container_get_ram_limit(const container_t *container);

const char *
container_get_cpus_allowed(const container_t *container);

/***************************
 * Submodule Interfaces    *
 **************************/

void
container_set_imei(container_t *container, char *imei);

char *
container_get_imei(container_t *container);

void
container_set_mac_address(container_t *container, char *mac_address);

char *
container_get_mac_address(container_t *container);

void
container_set_phone_number(container_t *container, char *phone_number);

char *
container_get_phone_number(container_t *container);

bool
container_get_allow_autostart(container_t *container);

/*
 * Retrive the corresponding GuestOS which is running in this container
 */
const guestos_t *
container_get_guestos(const container_t *container);

/**
 * Returns the ip address currently set for container.
 */
const char *
container_get_dns_server(const container_t *container);

bool
container_has_netns(const container_t *container);

bool
container_has_userns(const container_t *container);

/**
 * Adds a network interface to the container. If persistent is true, the config file will be modified accordingly
 */
int
container_add_net_iface(container_t *container, container_pnet_cfg_t *pnet_cfg, bool persistent);

/**
 * Registers the corresponding handler for container_add_net_interface
 */
void
container_register_add_net_interface_handler(const char *mod_name,
					     int (*handler)(void *data,
							    container_pnet_cfg_t *pnet_cfg));

/**
 * Removes a network interface from the container. If persistent is true, the config file will be modified accordingly
 */
int
container_remove_net_iface(container_t *container, const char *iface, bool persistent);

/**
 * Registers the corresponding handler for container_remove_net_interface
 */
void
container_register_remove_net_interface_handler(const char *mod_name,
						int (*handler)(void *data, const char *iface));

const char **
container_get_dev_allow_list(const container_t *container);

const char **
container_get_dev_assign_list(const container_t *container);

time_t
container_get_uptime(const container_t *container);

/**
 * Registers the corresponding handler for container_get_uptime
 */
void
container_register_get_uptime_handler(const char *mod_name, time_t (*handler)(void *data));

time_t
container_get_creation_time(const container_t *container);

/**
 * Registers the corresponding handler for container_get_creation_time
 */
void
container_register_get_creation_time_handler(const char *mod_name, time_t (*handler)(void *data));

void
container_set_setup_mode(container_t *container, bool setup);

bool
container_has_setup_mode(const container_t *container);

int
container_setuid0(const container_t *container);

/**
 * Registers the corresponding handler for container_setuid0
 */
void
container_register_setuid0_handler(const char *mod_name, int (*handler)(void *data));

bool
container_get_sync_state(const container_t *container);

void
container_set_sync_state(container_t *container, bool state);

/**
 * Initialize a container_vnet_cfg_t data structure and allocate needed memory
 */
container_vnet_cfg_t *
container_vnet_cfg_new(const char *if_name, const char *rootns_name, const uint8_t mac[6],
		       bool configure);

/**
 * Free all memory used by a container_vnet_cfg_t data structure
 */
void
container_vnet_cfg_free(container_vnet_cfg_t *vnet_cfg);

/**
 * This function provides the container's runtime config
 * of veth interfaces in form of a container_vnet_cfg_t* list.
 * The elements contain the veth name inside the container and
 * the runtime generated interface name of the rootns endpoint.
 */
list_t *
container_get_vnet_runtime_cfg_new(const container_t *container);

/**
 * Registers the corresponding handler for container_get_vnet_runtime_cfg_new
 */
void
container_register_get_vnet_runtime_cfg_new_handler(const char *mod_name,
						    list_t *(*handler)(void *data));

/**
 * Initialize a container_pnet_cfg_t data structure and allocate needed memory.
 * @if_name may be either the name or the MAC of the phyiscal NIC
 */
container_pnet_cfg_t *
container_pnet_cfg_new(const char *if_name, bool mac_filter, list_t *mac_whitelist);

/**
 * Free all memory used by a container_pnet_cfg_t data structure, including
 * the internal mac_whitelist.
 */
void
container_pnet_cfg_free(container_pnet_cfg_t *pnet_cfg);

/**
 * Get the list of usb devices which are set in container config.
 */
list_t *
container_get_usbdev_list(const container_t *container);

/**
 * Allow device access by major, minor number of device.
 */
int
container_device_allow(const container_t *container, int major, int minor, bool assign);

/**
 * Registers the corresponding handler for container_device_allow
 */
void
container_register_device_allow_handler(const char *mod_name,
					int (*handler)(void *data, int major, int minor,
						       bool assign));

/**
 * Remove previously allowed device access by major, minor number of device.
 */
int
container_device_deny(const container_t *container, int major, int minor);

/**
 * Registers the corresponding handler for container_device_allow
 */
void
container_register_device_deny_handler(const char *mod_name,
				       int (*handler)(void *data, int major, int minor));

/**
 * Checks if the device specified by the major and minor is allowed in this container.
 */
bool
container_is_device_allowed(const container_t *container, int major, int minor);

/**
 * Registers the corresponding handler for container_device_allow
 */
void
container_register_is_device_allowed_handler(const char *mod_name,
					     bool (*handler)(void *data, int major, int minor));

/**
 * Prepares a mount for shifted uid and gids of directory/file for the container's userns.
 *
 * Needs to be called in rootns for each file system image which should be mounted
 * with shifted ids in child. This is also be used to shift single files in the
 * in uevent module for container allowed devices.
 */
int
container_shift_ids(const container_t *container, const char *path, bool is_root);

/**
 * Registers the corresponding handler for container_shift_ids
 */
void
container_register_shift_ids_handler(const char *mod_name,
				     int (*handler)(void *data, const char *path, bool is_root));

/**
 * Mounts all directories with shifted uid and gids inside the container's userns.
 *
 * Needs to be called before exec usually in a start_child handler.
 */
int
container_shift_mounts(const container_t *container);

/**
 * Registers the corresponding handler for container_shift_mounts
 */
void
container_register_shift_mounts_handler(const char *mod_name, int (*handler)(void *data));

/**
 * Returns the uid which is mapped to the root user inside the container
 *
 * if userns is enabled this would be a uid grater than 0.
 */
int
container_get_uid(const container_t *container);

/**
 * Registers the corresponding handler for container_get_uid
 */
void
container_register_get_uid_handler(const char *mod_name, int (*handler)(void *data));

/**
 * Returns the directory where the container's file system tree
 * is mounted in init mount namspace.
 */
char *
container_get_rootdir(const container_t *container);

/**
 * Registers the corresponding handler for container_get_rootdir
 */
void
container_register_get_rootdir_handler(const char *mod_name, char *(*handler)(void *data));

/**
 * Checks if the containers uuid is the all zero uuid which
 * is assigned to c0.
 *
 * This function can be used to check if the container is c0
 * even if the container is not yet fulle created.
 */
bool
container_uuid_is_c0id(const uuid_t *uuid);

/**
 * Returns the type of the token that is used with the container
 */
container_token_type_t
container_get_token_type(const container_t *container);

/**
 * Returns the i_serial number of the usb device that is the token reader
 */
char *
container_get_usbtoken_serial(const container_t *container);

/**
 * Returns the current devpath of the container's token or NULL if the reader is currently not attached
 */
char *
container_get_usbtoken_devpath(const container_t *container);

/**
 * Sets the current devpath of the container's token
 */
void
container_set_usbtoken_devpath(container_t *container, char *devpath);

/**
 * Sets the uuid of the token the container is associated with.
 */
void
container_set_token_uuid(container_t *container, const char *tuuid);

/**
 * Returns the uuid of the token the container is associated with.
 */
uuid_t *
container_get_token_uuid(const container_t *container);

/**
 * Sets the flag whether the token the container is associated with has been initialized in the scd.
 */
void
container_set_token_is_init(container_t *container, const bool is_init);

/**
 * Returns whether the token the container is associated with has been initialized in the scd.
 * If the container includes encrypted mounts it can only operate with the token being present in the scd.
 */
bool
container_get_token_is_init(const container_t *container);

/**
 * Sets the flag whether the token the container is associated with has been provisioned with a platform-bound
 * authentication code (== paired to the device).
 */
void
container_set_token_is_linked_to_device(container_t *container, const bool is_paired);

/**
 * Returns whether the token the container is associated with has been provisioned with a platform-bound
 * authentication code.
 * The token must be linked to the device prior to it being able to (un-)wrap encryption keys.
 */
bool
container_get_token_is_linked_to_device(const container_t *container);

/**
 * Executes a binary of a priviliegd container with cap_sys_time in root userns.
 */
int
container_exec_cap_systime(const container_t *container, char *const *argv);

/**
 * Registers the corresponding handler for container_exec_cap_systime
 */
void
container_register_exec_cap_systime_handler(const char *mod_name,
					    int (*handler)(void *data, char *const *argv));

/**
 * Returns whether the pin should be requested interactively via a usb pin reader during
 * container start
 */
bool
container_get_usb_pin_entry(const container_t *container);

/**
 * Returns the last ACK hash that has been received from this container
 */
const char *
container_audit_get_last_ack(const container_t *container);

/**
 * Registers the corresponding handler for container_audit_get_last_ack
 */
void
container_register_audit_get_last_ack_handler(const char *mod_name,
					      const char *(*handler)(void *data));

/**
 * Stores the last ACK hash that has been received for this container.
 */
int
container_audit_set_last_ack(const container_t *container, const char *last_ack);

/**
 * Registers the corresponding handler for container_audit_set_last_ack
 */
void
container_register_audit_set_last_ack_handler(const char *mod_name,
					      int (*handler)(void *data, const char *last_ack));

/**
 * Returns wether an ACK is currently being processed for this container
 */
bool
container_audit_get_processing_ack(const container_t *container);

/**
 * Registers the corresponding handler for container_audit_get_processing_ack
 */
void
container_register_audit_get_processing_ack_handler(const char *mod_name,
						    bool (*handler)(void *data));

/**
 * Stores if an ACK hash is currently being processed for this container
 */
int
container_audit_set_processing_ack(const container_t *container, bool processing_ack);

/**
 * Registers the corresponding handler for container_audit_set_processing_ack
 */
void
container_register_audit_set_processing_ack_handler(const char *mod_name,
						    int (*handler)(void *data,
								   bool processing_ack));

/**
 * Send audit record to container
 */
int
container_audit_record_notify(const container_t *container, uint64_t remaining_storage);

/**
 * Registers the corresponding handler for container_audit_record_notify
 */
void
container_register_audit_record_notify_handler(const char *mod_name,
					       int (*handler)(void *data,
							      uint64_t remaining_storage));

/**
 * Send audit event to container
 */
int
container_audit_record_send(const container_t *container, const uint8_t *buf, uint32_t buflen);

/**
 * Registers the corresponding handler for container_audit_record_send
 */
void
container_register_audit_record_send_handler(const char *mod_name,
					     int (*handler)(void *data, const uint8_t *buf,
							    uint32_t buflen));

int
container_audit_notify_complete(const container_t *container);

/**
 * Registers the corresponding handler for container_audit_notify_complete
 */
void
container_register_audit_notify_complete_handler(const char *mod_name, int (*handler)(void *data));

int
container_audit_set_loginuid(const container_t *container, uint32_t uid);

/**
 * Registers the corresponding handler for container_audit_set_loginuid
 */
void
container_register_audit_set_loginuid_handler(const char *mod_name,
					      int (*handler)(void *data, uint32_t uid));

uint32_t
container_audit_get_loginuid(const container_t *container);

/**
 * Registers the corresponding handler for container_audit_get_loginuid
 */
void
container_register_audit_get_loginuid_handler(const char *mod_name,
					      uint32_t (*handler)(void *data));

list_t *
container_get_pnet_cfg_list(const container_t *container);

list_t *
container_get_vnet_cfg_list(const container_t *container);

list_t *
container_get_fifo_list(const container_t *container);

int
container_start_with_smartcard(const container_t *container, int resp_fd, const char *pw);

int
container_stop_with_smartcard(const container_t *container, int resp_fd, const char *pw);

int
container_scd_token_add_block(const container_t *container);

int
container_scd_token_remove_block(const container_t *container);

int
container_scd_release_pairing(const container_t *container);

int
container_update_token_state(const container_t *container);

int
container_change_pin(const container_t *container, int resp_fd, const char *pw, const char *newpw);

int
container_remove_keyfile(const container_t *container);

void
container_register_start_with_smartcard_handler(const char *mod_name,
						int (*handler)(void *data, int resp_fd,
							       const char *pw));

void
container_register_stop_with_smartcard_handler(const char *mod_name,
					       int (*handler)(void *data, int resp_fd,
							      const char *pw));

void
container_register_scd_token_add_block_handler(const char *mod_name, int (*handler)(void *data));

void
container_register_scd_token_remove_block_handler(const char *mod_name, int (*handler)(void *data));

void
container_register_scd_release_pairing_handler(const char *mod_name, int (*handler)(void *data));

void
container_register_update_token_state_handler(const char *mod_name, int (*handler)(void *data));

void
container_register_change_pin_handler(const char *mod_name,
				      int (*handler)(void *data, int resp_fd, const char *pw,
						     const char *newpw));

void
container_register_remove_keyfile_handler(const char *mod_name, int (*handler)(void *data));


#endif /* CONTAINER_H */
