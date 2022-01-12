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

#include "container_module.h"

#include "common/uuid.h"
#include "common/list.h"

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

/**
 * Represents an error that happened during smartcard handling of a container.
 */
enum container_smartcard_error {
	CONTAINER_SMARTCARD_LOCK_FAILED = 1,
	CONTAINER_SMARTCARD_UNLOCK_FAILED,
	CONTAINER_SMARTCARD_PASSWD_WRONG,
	CONTAINER_SMARTCARD_LOCKED_TILL_REBOOT,
	CONTAINER_SMARTCARD_TOKEN_UNINITIALIZED,
	CONTAINER_SMARTCARD_TOKEN_UNPAIRED,
	CONTAINER_SMARTCARD_PAIRING_SECRET_FAILED,
	CONTAINER_SMARTCARD_WRAPPING_ERROR,
	CONTAINER_SMARTCARD_CHANGE_PIN_SUCCESSFUL,
	CONTAINER_SMARTCARD_CHANGE_PIN_FAILED,
	CONTAINER_SMARTCARD_CB_OK,
	CONTAINER_SMARTCARD_CB_FAILED,
};

typedef struct container_module {
	const char *name;
	void *(*container_new)(container_t *container);
	void (*container_free)(void *data);
	void (*container_destroy)(void *data);
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
container_new(const uuid_t *uuid, const char *name, container_type_t type, bool ns_usr, bool ns_net,
	      const void *os, const char *config_filename, const char *images_folder,
	      unsigned int ram_limit, const char *cpus_allowed, uint32_t color,
	      bool allow_autostart, const char *dns_server, list_t *net_ifaces,
	      char **allowed_devices, char **assigned_devices, list_t *vnet_cfg_list,
	      list_t *usbdev_list, const char *init, char **init_argv, char **init_env,
	      size_t init_env_len, list_t *fifo_list, container_token_type_t ttype,
	      bool usb_pin_entry);

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
CONTAINER_MODULE_WRAPPER_DECLARE(add_pid_to_cgroups, int, pid_t pid)

/*
 * Set capapilites for calling process as for given container's init
 */
CONTAINER_MODULE_WRAPPER_DECLARE(set_cap_current_process, int)

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
CONTAINER_MODULE_WRAPPER_DECLARE(get_console_sock_cmld, int, int session_fd)

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
CONTAINER_MODULE_WRAPPER_DECLARE(is_encrypted, bool)

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
CONTAINER_MODULE_WRAPPER_DECLARE(run, int, int create_pty, char *cmd, ssize_t argc, char **argv,
				 int session_fd)

/**
 * Registers the corresponding handler for container_write_exec_input
 */
CONTAINER_MODULE_WRAPPER_DECLARE(write_exec_input, int, char *exec_input, int session_fd)

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
CONTAINER_MODULE_WRAPPER_DECLARE(freeze, int)

/**
 * Unfreeze a container.
 *
 * @return 0 if ok, negative values indicate errors.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(unfreeze, int)

/**
 * Registers the corresponding handler for container_allow_audio
 */
CONTAINER_MODULE_WRAPPER_DECLARE(allow_audio, int)

/**
 * Registers the corresponding handler for container_deny_audio
 */
CONTAINER_MODULE_WRAPPER_DECLARE(deny_audio, int)

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

void
container_init_env_prepend(container_t *container, char **init_env, size_t init_env_len);

/***************************
 * Submodule Interfaces    *
 **************************/

bool
container_get_allow_autostart(container_t *container);

/*
 * Retrive the corresponding GuestOS (as generic object) which is running in this container
 */
const void *
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
 * Adds a network interface to the container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(add_net_interface, int, container_pnet_cfg_t *pnet_cfg)

/**
 * Removes a network interface from the container.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(remove_net_interface, int, const char *iface)

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

/**
 * Registers the corresponding handler for container_setuid0
 */
CONTAINER_MODULE_WRAPPER_DECLARE(setuid0, int)

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
CONTAINER_MODULE_WRAPPER_DECLARE(device_allow, int, int major, int minor, bool assign)

/**
 * Remove previously allowed device access by major, minor number of device.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(device_deny, int, int major, int minor)

/**
 * Checks if the device specified by the major and minor is allowed in this container.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(is_device_allowed, bool, int major, int minor)

/**
 * Prepares a mount for shifted uid and gids of directory/file for the container's userns.
 *
 * Needs to be called in rootns for each file system image which should be mounted
 * with shifted ids in child. This is also be used to shift single files in the
 * in uevent module for container allowed devices.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(shift_ids, int, const char *path, bool is_root)

/**
 * Mounts all directories with shifted uid and gids inside the container's userns.
 *
 * Needs to be called before exec usually in a start_child handler.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(shift_mounts, int)

/**
 * Returns the uid which is mapped to the root user inside the container
 *
 * if userns is enabled this would be a uid grater than 0.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(get_uid, int)

/**
 * Returns the directory where the container's file system tree
 * is mounted in init mount namspace.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(get_rootdir, char *)

/**
 * Returns a generic pointer to the mount table
 */
CONTAINER_MODULE_WRAPPER_DECLARE(get_mnt, void *)

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
 * Executes a binary of a priviliegd container with cap_sys_time in root userns.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(exec_cap_systime, int, char *const *argv)

/**
 * Returns whether the pin should be requested interactively via a usb pin reader during
 * container start
 */
bool
container_get_usb_pin_entry(const container_t *container);

/**
 * Returns the last ACK hash that has been received from this container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_get_last_ack, const char *)

/**
 * Stores the last ACK hash that has been received for this container.
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_set_last_ack, int, const char *last_ack)

/**
 * Returns wether an ACK is currently being processed for this container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_get_processing_ack, bool)

/**
 * Stores if an ACK hash is currently being processed for this container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_set_processing_ack, int, bool processing_ack)

/**
 * Send audit record to container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_record_notify, int, uint64_t remaining_storage)

/**
 * Send audit event to container
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_record_send, int, const uint8_t *buf, uint32_t buflen)

/**
 * Declares the corresponding handler for container_audit_notify_complete
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_notify_complete, int)

/**
 * Declares the corresponding handler for container_audit_set_loginuid
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_set_loginuid, int, uint32_t uid)

/**
 * Declares the corresponding handler for container_audit_get_loginuid
 */
CONTAINER_MODULE_WRAPPER_DECLARE(audit_get_loginuid, uint32_t)

list_t *
container_get_pnet_cfg_list(const container_t *container);

list_t *
container_get_vnet_cfg_list(const container_t *container);

list_t *
container_get_fifo_list(const container_t *container);

CONTAINER_MODULE_WRAPPER_DECLARE(ctrl_with_smartcard, int, int (*success_cb)(container_t *),
				 const char *pw)

CONTAINER_MODULE_WRAPPER_DECLARE(set_smartcard_error_cb, int, void (*err_cb)(int error, void *data),
				 void *cbdata)

CONTAINER_MODULE_WRAPPER_DECLARE(scd_release_pairing, int)

CONTAINER_MODULE_WRAPPER_DECLARE(change_pin, int, const char *pw, const char *newpw)

/**
 * Handles attachment of a container token.
 *
 * @return 0 if the given USB serial belongs to a container token and
 *	the attachment procedure could be performed properly, -1 otherwise
 */
CONTAINER_MODULE_WRAPPER_DECLARE(token_attach, int)

/**
 * Handles detachment of a container token.
 *
 * @return 0 if the given USB serial belongs to a container token and
 * 	the detachment procedure could be performed properly, -1 otherwise
 */
CONTAINER_MODULE_WRAPPER_DECLARE(token_detach, int)

CONTAINER_MODULE_WRAPPER_DECLARE(has_token_changed, bool, container_token_type_t type,
				 const char *serial)

#endif /* CONTAINER_H */
