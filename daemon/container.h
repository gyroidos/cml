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
	CONTAINER_STATE_SHUTTING_DOWN
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
	CONTAINER_ERROR_DEVNS
};

typedef enum {
	CONTAINER_CONNECTIVITY_OFFLINE = 1,
	CONTAINER_CONNECTIVITY_MOBILE_ONLY,
	CONTAINER_CONNECTIVITY_WIFI_ONLY,
	CONTAINER_CONNECTIVITY_MOBILE_AND_WIFI
} container_connectivity_t;


static inline bool
container_connectivity_wifi(container_connectivity_t connectivity)
{
	return (connectivity == CONTAINER_CONNECTIVITY_WIFI_ONLY
			|| connectivity == CONTAINER_CONNECTIVITY_MOBILE_AND_WIFI);
}

static inline bool
container_connectivity_mobile(container_connectivity_t connectivity)
{
	return (connectivity == CONTAINER_CONNECTIVITY_MOBILE_ONLY
			|| connectivity == CONTAINER_CONNECTIVITY_MOBILE_AND_WIFI);
}

static inline bool
container_connectivity_online(container_connectivity_t connectivity)
{
	return (connectivity != CONTAINER_CONNECTIVITY_OFFLINE);
}

/**
 * Low-level constructor that creates a new container instance
 * with the given parameters.
 *
 * TODO: Document parameters.
 * @return The new container instance.
 */
container_t *
container_new_internal(
	const uuid_t *uuid,
	const char *name,
	container_type_t type,
	bool ns_usr,
	bool ns_net,
	bool privileged,
	const guestos_t *os,
	const char *config_filename,
	const char *images_folder,
	mount_t *mnt,
	unsigned int ram_limit,
	uint32_t color,
	uint16_t adb_port,
	bool allow_autostart,
	list_t *feature_enabled,
	const char *dns_server,
	list_t *net_ifaces,
	char **allowed_devices,
	char **assigned_devices
);

/**
 * Creates a new container container object. There are three different cases
 * depending on the combination of the given parameters:
 *
 * TODO: Use doxygen style to document parameters
 * uuid && !config: In this case, a container with the given UUID must be already
 * present in the given store_path and is loaded from there.
 *
 * !uuid && config: In this case, the container does NOT yet exist and should be
 * created in the given store_path using the given config string and a random
 * UUID.
 *
 * uuid && config: In this case, the container does NOT yet exist and should be
 * created in the given store_path using the given config string and the given
 * UUID.
 *
 * @return The new container object or NULL if something went wrong.
 */
container_t *
container_new(const char *store_path, const uuid_t *uuid, const char *config, size_t config_len);

/*
container_t *
container_new_clone(container_t *container);
*/

/**
 * Free a container data structure. Does not remove the persistent parts of the container,
 * i.e. the configuration and the images.
 */
void
container_free(container_t *container);

/**
 * Returns the name of the container.
 */
const char*
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
 * Start the given container using the given key to decrypt its filesystem
 * image(s).
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
container_start(container_t *container);//, const char *key);

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
container_freeze(container_t *container);

/**
 * Unfreeze a container.
 *
 * @return 0 if ok, negative values indicate errors.
 */
int
container_unfreeze(container_t *container);

int
container_allow_audio(container_t *container);

int
container_deny_audio(container_t *container);

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
 * Returns the the type of the container.
 */
container_type_t
container_get_type(const container_t *container);

/**
 * Register a callback function which is always called when the container's
 * state changes.
 */
container_callback_t *
container_register_observer(
		container_t *container,
		void (*cb)(container_t *, container_callback_t *, void *),
		void *data);

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

int
container_set_ram_limit(container_t *container, unsigned int ram_limit);

/***************************
 * Submodule Interfaces    *
 **************************/

/**
 * Inject the given input event into this container.
 * TODO: Still used? Remove otherwise!
 */
//int
//container_inject_input_event(container_t *container /*, input event */);

void
container_set_connectivity(container_t *container, container_connectivity_t connectivity);

container_connectivity_t
container_get_connectivity(container_t *container);

void
container_set_airplane_mode(container_t *container, bool airplane_mode);

bool
container_get_airplane_mode(container_t *container);

void
container_set_screen_on(container_t *container, bool screen_on);

bool
container_is_screen_on(container_t *container);

void
container_set_wifi_user_enabled(container_t *container, bool enabled);

bool
container_get_wifi_user_enabled(container_t *container);

void
container_set_imei(container_t *container, char *imei);

char*
container_get_imei(container_t *container);

void
container_set_mac_address(container_t *container, char *mac_address);

char*
container_get_mac_address(container_t *container);

void
container_set_phone_number(container_t *container, char *phone_number);

char*
container_get_phone_number(container_t *container);

bool
container_get_allow_autostart(container_t *container);

/*
 * Retrive the corresponding GuestOS which is running in this container
 */
const guestos_t*
container_get_guestos(const container_t *container);

/*
 * Checks wether a feature is enabled or not for this container.
 *
 * fetaure can be a string out of the following set:
 *
 *    {
 *       "bluetooth",
 *       "camera",
 *       "gapps",
 *       "generic",
 *       "gps",
 *       "telephony",
 *       "fhgapps"
 *    }
 */
bool
container_is_feature_enabled(const container_t *container, const char *feature);

void
container_enable_bluetooth(container_t *conatiner);

void
container_enable_camera(container_t *conatiner);

void
container_enable_gps(container_t *conatiner);

void
container_enable_gapps(container_t *conatiner);

void
container_enable_fhgapps(container_t *conatiner);

void
container_enable_telephony(container_t *conatiner);

void
container_set_radio_ip(container_t *container, char *ip);

void
container_set_radio_dns(container_t *container, char *dns);

void
container_set_radio_gateway(container_t *container, char *gateway);

/**
 * Returns the ip address currently set for container.
 */
const char*
container_get_dns_server(const container_t *container);

bool
container_has_netns(const container_t *container);

/**
 * Returns the ip of the first interface set inside the container
 */
char *
container_get_first_ip_new(container_t *container);

/**
 * Returns the subnet of the first interface set inside the container
 */
char *
container_get_first_subnet_new(container_t *container);

/**
 * Adds a network interface to the container. If persistent is true, the config file will be modified accordingly
 */
int
container_add_net_iface(container_t *container, const char *iface, bool persistent);

/**
 * Removes a network interface from the container. If persistent is true, the config file will be modified accordingly
 */
int
container_remove_net_iface(container_t *container, const char *iface, bool persistent);

const char **container_get_dev_allow_list(const container_t *container);

const char **container_get_dev_assign_list(const container_t *container);

time_t
container_get_uptime(const container_t *container);

time_t
container_get_creation_time(const container_t *container);

#endif /* CONTAINER_H */
