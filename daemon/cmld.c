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

#ifdef DEBUG_BUILD
// prevent reboot in debug build
#define NO_REBOOT_ON_EXIT
#endif

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define _GNU_SOURCE

#include "cmld.h"

#include "common/macro.h"
#include "common/event.h"
#include "common/logf.h"
#include "common/list.h"
#include "common/file.h"
#include "common/sock.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/network.h"
#include "common/reboot.h"
#include "common/hex.h"
#include "a_b_update/a_b_update.h"
#include "mount.h"
#include "device_config.h"
#include "device_id.h"
#include "control.h"
#include "guestos_mgr.h"
#include "guestos.h"
#include "scd.h"
#include "tss.h"
#include "ksm.h"
#include "hotplug.h"
#include "time.h"
#include "lxcfs.h"
#include "audit.h"
#include "time.h"
#include "container_config.h"
#include "container.h"
#include "input.h"
#include "oci.h"
#include "crypto.h"

#include <inttypes.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>

// clang-format off
#ifndef CMLD_CONTROL_SOCKET
#define CMLD_CONTROL_SOCKET SOCK_PATH(control)
#endif // CMLD_CONTROL_SOCKET
#define CMLD_CONTROL_CONTAINER_SOCKET SOCK_PATH(control)
// clang-format on

#define CMLD_SUSPEND_TIMEOUT 5000

// files and directories in cmld's home path /data/cml
#define CMLD_PATH_DEVICE_CONF "device.conf"
#define CMLD_PATH_GUESTOS_DIR "operatingsystems"
#define CMLD_PATH_CONTAINERS_DIR "containers"
#define CMLD_PATH_CONTAINER_KEYS_DIR "keys"
#define CMLD_PATH_CONTAINER_TOKENS_DIR "tokens"
#define CMLD_PATH_DEVICE_ID CMLD_PATH_CONTAINER_TOKENS_DIR "/device_id.conf"
#define CMLD_PATH_SHARED_DATA_DIR "shared"

#define CMLD_WAKE_LOCK_STARTUP "ContainerStartup"

#define CMLD_KSM_AGGRESSIVE_TIME_AFTER_CONTAINER_BOOT 70000

/*
 * dummy key used for unencrypted c0 (legacy dm ondisk format)
 * and for reboots where the real key is already in kernel
 */
#define DUMMY_KEY                                                                                  \
	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

#define CMLD_C0_KEY_BUF_SIZE 256
#define CMLD_C0_KEY_LEN 32
#define CMLD_C0_UUID "00000000-0000-0000-0000-000000000000"

static const char *cmld_path = DEFAULT_BASE_PATH;
static const char *cmld_container_path = NULL;
static const char *cmld_wrapped_keys_path = NULL;

static list_t *cmld_containers_list = NULL; // usually first element is c0
static list_t *cmld_units_list = NULL;

static control_t *cmld_control_gui = NULL;
static control_t *cmld_control_cml = NULL;

static char *cmld_device_uuid = NULL;
static char *cmld_device_update_base_url = NULL;
static char *cmld_device_host_dns = NULL;
static char *cmld_c0os_name = NULL;

static char *cmld_shared_data_dir = NULL;

static list_t *cmld_netif_phys_list = NULL;

static bool cmld_hostedmode = false;
static bool cmld_signed_configs = false;

static bool cmld_device_provisioned = false;

static enum command cmld_device_reboot = POWER_OFF;

typedef enum {
	CMLD_INIT_STAGE_ZERO = 0,
	CMLD_INIT_STAGE_UNIT,
	CMLD_INIT_STAGE_CONTAINER,
} cmld_init_stage_t;

static cmld_init_stage_t cmld_init_stage = CMLD_INIT_STAGE_ZERO;

#ifdef OCI
// clang-format off
#define CMLD_OCI_CONTROL_SOCKET SOCK_PATH(oci-control)
// clang-format on
static oci_control_t *cmld_oci_control_cml = NULL;
#endif

/******************************************************************************/

static int
cmld_start_c0(container_t *new_c0);

static int
cmld_init_stage_container(void);

/******************************************************************************/

container_t *
cmld_containers_get_c0()
{
	uuid_t *c0_uuid = uuid_new(CMLD_C0_UUID);
	container_t *container = cmld_container_get_by_uuid(c0_uuid);
	uuid_free(c0_uuid);
	return container;
}

container_t *
cmld_container_get_c_root_netns()
{
	container_t *found = NULL;
	container_t *found_c0 = NULL;

	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *container = l->data;
		if (!container_has_netns(container)) {
			if (container == cmld_containers_get_c0()) {
				found_c0 = container;
			} else {
				// first container without netns which is not c0
				found = container;
				break;
			}
		}
	}
	return ((found) ? found : found_c0);
}

container_t *
cmld_container_get_by_uuid(const uuid_t *uuid)
{
	ASSERT(uuid);

	for (list_t *l = cmld_containers_list; l; l = l->next)
		if (uuid_equals(container_get_uuid(l->data), uuid))
			return l->data;

	return NULL;
}

container_t *
cmld_container_get_by_uid(int uid)
{
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *c = l->data;
		if ((uid >= container_get_uid(c)) && (uid < container_get_uid(c) + UID_MAX))
			return c;
	}
	return NULL;
}

container_t *
cmld_container_get_by_pid(int pid)
{
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *c = l->data;
		if (container_contains_pid(c, pid))
			return c;
	}
	return NULL;
}

static bool
cmld_containers_are_all_stopped(void)
{
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *c = l->data;
		if (container_get_state(c) != COMPARTMENT_STATE_STOPPED)
			return false;
		else
			continue;
	}
	return true;
}

typedef struct cmld_container_stop_data {
	void (*on_all_stopped)(int);
	int value;
} cmld_container_stop_data_t;

static void
cmld_container_stop_cb(container_t *container, container_callback_t *cb, void *data)
{
	cmld_container_stop_data_t *stop_data = data;

	ASSERT(container);
	ASSERT(cb);
	ASSERT(stop_data);

	/* skip if the container is not stopped */
	IF_FALSE_RETURN_TRACE(container_get_state(container) == COMPARTMENT_STATE_STOPPED);

	/* unregister observer */
	container_unregister_observer(container, cb);

	/* execute on_all_stopped, if all containers are stopped now */
	if (cmld_containers_are_all_stopped()) {
		INFO("all containers are stopped now, execution of on_all_stopped()");
		stop_data->on_all_stopped(stop_data->value);
		mem_free0(stop_data);
	}
}

int
cmld_containers_stop(void (*on_all_stopped)(int), int value)
{
	/* execute on_all_stopped, if all containers are stopped now */
	if (cmld_containers_are_all_stopped()) {
		INFO("all containers are stopped now, execution of on_all_stopped()");
		on_all_stopped(value);
		return 0;
	}

	cmld_container_stop_data_t *stop_data = mem_new0(cmld_container_stop_data_t, 1);
	stop_data->on_all_stopped = on_all_stopped;
	stop_data->value = value;

	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *container = l->data;
		if (cmld_container_stop(container) == 0) {
			/* Register observer to wait for completed container_stop */
			if (!container_register_observer(container, &cmld_container_stop_cb,
							 stop_data)) {
				DEBUG("Could not register stop callback");
				return -1;
			}
		}
	}
	return 0;
}

int
cmld_containers_get_count(void)
{
	return list_length(cmld_containers_list);
}

container_t *
cmld_container_get_by_index(int index)
{
	return list_nth_data(cmld_containers_list, index);
}

const char *
cmld_get_device_uuid(void)
{
	return cmld_device_uuid;
}

const char *
cmld_get_device_update_base_url(void)
{
	return cmld_device_update_base_url;
}

const char *
cmld_get_device_host_dns(void)
{
	return cmld_device_host_dns;
}

const char *
cmld_get_shared_data_dir(void)
{
	return cmld_shared_data_dir;
}

list_t *
cmld_get_netif_phys_list(void)
{
	return cmld_netif_phys_list;
}

bool
cmld_is_hostedmode_active(void)
{
	return cmld_hostedmode;
}

bool
cmld_uses_signed_configs(void)
{
	return cmld_signed_configs;
}

bool
cmld_is_device_provisioned(void)
{
	return cmld_device_provisioned;
}

int
cmld_set_device_provisioned(void)
{
	char *provisioned_file = mem_printf("%s/%s", DEFAULT_BASE_PATH, PROVISIONED_FILE_NAME);
	if (!file_exists(provisioned_file)) {
		if (file_touch(provisioned_file) != 0) {
			ERROR("Failed to create provisioned file");
			return -1;
		}
		// TODO does this fulfill the required access rights?
		uid_t uid = getuid();
		if (chown(provisioned_file, uid, uid)) {
			ERROR("Failed to chown provision-status-file to %d", uid);
			return -1;
		}
	}
	mem_free0(provisioned_file);

	cmld_device_provisioned = true;

	return 0;
}

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
 * @return The new container object or NULL if something went wrong.
 */
static container_t *
cmld_container_new(const char *store_path, const uuid_t *existing_uuid, const uint8_t *config,
		   size_t config_len, uint8_t *sig, size_t sig_len, uint8_t *cert, size_t cert_len)
{
	ASSERT(store_path);
	ASSERT(existing_uuid || config);

	const char *name;
	bool ns_usr;
	bool ns_net;
	const void *os;
	char *config_filename;
	char *images_dir;
	unsigned int ram_limit;
	const char *cpus_allowed;
	uint32_t color;
	uuid_t *uuid;
	uint64_t current_guestos_version;
	uint64_t new_guestos_version;
	bool allow_autostart;
	bool allow_system_time;
	list_t *allowed_module_list;
	char **allowed_devices;
	char **assigned_devices;
	const char *init;
	bool enable_xorg_compat;
	container_t *c = NULL;

	if (!existing_uuid) {
		uuid = uuid_new(NULL);
	} else {
		uuid = uuid_new(uuid_string(existing_uuid));
	}

	/* generate the container paths */
	config_filename = mem_printf("%s/%s.conf", store_path, uuid_string(uuid));
	images_dir = mem_printf("%s/%s", store_path, uuid_string(uuid));

	DEBUG("New containers config filename is %s", config_filename);
	DEBUG("New containers images directory is %s", images_dir);

	/********************************
	 * Translate High Level Config into low-level parameters for internal
	 * constructor */
	container_config_t *conf = container_config_new(config_filename, config, config_len, sig,
							sig_len, cert, cert_len);

	if (!conf) {
		WARN("Could not read config file %s", config_filename);
		goto out;
	}

	name = container_config_get_name(conf);

	const char *os_name = container_config_get_guestos(conf);

	DEBUG("New containers os name is %s", os_name);

	// if signed config files are used, always load
	// OS version specified in container config
	if (cmld_uses_signed_configs()) {
		os = guestos_mgr_get_by_version(os_name, container_config_get_guestos_version(conf),
						true);
	} else {
		os = guestos_mgr_get_latest_by_name(os_name, true);
	}

	if (!os) {
		WARN("Could not get GuestOS %s instance for container %s with version v%" PRIu64,
		     os_name, name, container_config_get_guestos_version(conf));
		goto out_config;
	}

	ram_limit = container_config_get_ram_limit(conf);
	DEBUG("New containers max ram is %" PRIu32 "", ram_limit);

	cpus_allowed = container_config_get_cpus_allowed(conf);
	DEBUG("New containers allowed cpu cores are %s", cpus_allowed ? cpus_allowed : "all");

	color = container_config_get_color(conf);

	allow_autostart = container_config_get_allow_autostart(conf);
	allow_system_time = container_config_get_allow_system_time(conf);

	current_guestos_version = container_config_get_guestos_version(conf);
	new_guestos_version = guestos_get_version(os);

	// can't update container config with enforced signatures
	if ((current_guestos_version < new_guestos_version) && !cmld_uses_signed_configs()) {
		INFO("Updating guestos version from %" PRIu64 " to %" PRIu64 " for container %s",
		     current_guestos_version, new_guestos_version, name);
		container_config_set_guestos_version(conf, new_guestos_version);
		INFO("guestos_version is now: %" PRIu64 "",
		     container_config_get_guestos_version(conf));
	} else if (current_guestos_version == new_guestos_version) {
		INFO("Keeping current guestos version %" PRIu64 " for container %s",
		     current_guestos_version, name);
	} else {
		WARN("The version of the found guestos (%" PRIu64 ") for container %s is to low",
		     new_guestos_version, name);
		WARN("Current version is %" PRIu64 "; Aborting...", current_guestos_version);
		goto out_config;
	}
	ns_usr = file_exists("/proc/self/ns/user") ? container_config_has_userns(conf) : false;
	ns_net = container_config_has_netns(conf);

	container_type_t type = container_config_get_type(conf);

	list_t *pnet_cfg_list = container_config_get_net_ifaces_list_new(conf);

	const char *dns_server = (container_config_get_dns_server(conf)) ?
					 container_config_get_dns_server(conf) :
					 cmld_get_device_host_dns();

	list_t *vnet_cfg_list = (ns_net && !container_uuid_is_c0id(uuid)) ?
					container_config_get_vnet_cfg_list_new(conf) :
					NULL;
	list_t *usbdev_list = container_config_get_usbdev_list_new(conf);

	allowed_module_list = container_config_get_module_allow_list_new(conf);
	allowed_devices = container_config_get_dev_allow_list_new(conf);
	assigned_devices = container_config_get_dev_assign_list_new(conf);

	// if init provided by guestos does not exists use mapped c_service as init
	init = file_exists(guestos_get_init(os)) ? guestos_get_init(os) : CSERVICE_TARGET;

	char **init_argv = guestos_get_init_argv_new(os);

	char **init_env = container_config_get_init_env(conf);
	size_t init_env_len = container_config_get_init_env_len(conf);

	// create FIFO list
	char **fifos = container_config_get_fifos(conf);
	list_t *fifo_list = NULL;

	for (size_t i = 0; i < container_config_get_fifos_len(conf); i++) {
		DEBUG("Adding FIFO \'%s\' to container's FIFO list", fifos[i]);

		fifo_list = list_append(fifo_list, mem_strdup(fifos[i]));
	}

	container_token_type_t ttype = container_config_get_token_type(conf);

	bool usb_pin_entry = container_config_get_usb_pin_entry(conf);

	enable_xorg_compat = container_config_get_enable_xorg_compat(conf);

	c = container_new(uuid, name, type, ns_usr, ns_net, os, config_filename, images_dir,
			  ram_limit, cpus_allowed, color, allow_autostart, allow_system_time,
			  dns_server, pnet_cfg_list, allowed_module_list, allowed_devices,
			  assigned_devices, vnet_cfg_list, usbdev_list, init, init_argv, init_env,
			  init_env_len, fifo_list, ttype, usb_pin_entry, enable_xorg_compat);
	if (c) {
		// overwrite image sizes of mount table
		container_config_fill_mount(conf, container_get_mnt(c));
		container_config_write(conf);
	}

out_config:
	container_config_free(conf);
out:
	uuid_free(uuid);
	mem_free0(images_dir);
	mem_free0(config_filename);
	return c;
}

void
cmld_containers_add(container_t *container)
{
	cmld_containers_list = list_append(cmld_containers_list, container);
}

/*
 * This callback handles config updates during container start/stop cycle
 */
static void
cmld_container_config_sync_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	IF_FALSE_RETURN(container_get_state(container) == COMPARTMENT_STATE_REBOOTING ||
			container_get_state(container) == COMPARTMENT_STATE_STOPPED);

	if (container_get_sync_state(container)) {
		DEBUG("Container %s already in sync", container_get_description(container));
		return;
	}

	// in error case reload may destroy container object thus dup uuid
	uuid_t *c_uuid = uuid_new(uuid_string(container_get_uuid(container)));

	container_unregister_observer(container, cb);
	DEBUG("Container is out of sync with its config. Reloading..");

	if (!cmld_reload_container(c_uuid, cmld_get_containers_dir())) {
		ERROR("Failed to reload container on config update");
		audit_log_event(c_uuid, FSA, CMLD, CONTAINER_MGMT, "reload", uuid_string(c_uuid),
				0);
		if (strncmp(uuid_string(c_uuid), CMLD_C0_UUID, strlen(CMLD_C0_UUID)))
			FATAL("Could not reload C0!");
	}

	mem_free0(c_uuid);
}

static void
cmld_container_delayed_free(void *data)
{
	ASSERT(data);

	container_t *container = data;
	container_free(container);
}

container_t *
cmld_reload_container(const uuid_t *uuid, const char *path)
{
	ASSERT(uuid);
	ASSERT(path);

	container_t *c = NULL, *c_current = NULL;

	// Will be destroyed on container_free
	uuid_t *uuid_tmp = uuid_new(uuid_string(uuid));

	c_current = cmld_container_get_by_uuid(uuid);
	if (c_current) {
		compartment_state_t state = container_get_state(c_current);
		if (state != COMPARTMENT_STATE_STOPPED) {
			DEBUG("Refusing to reload already created and not stopped container %s.",
			      container_get_name(c_current));
			c = c_current;
			goto cleanup;
		}
	}
	c = cmld_container_new(path, uuid_tmp, NULL, 0, NULL, 0, NULL, 0);
	if (!c) {
		WARN("Could not create new container object");
		c = c_current;
		goto cleanup;
	}

	if (c_current) {
		DEBUG("Removing outdated created container %s for config update",
		      container_get_name(c_current));

		cmld_containers_list = list_remove(cmld_containers_list, c_current);
		// delayed free to allow all observers to finish up
		container_finish_observers(c_current, cmld_container_delayed_free, c_current);
	}

	DEBUG("Loaded config for container %s", container_get_name(c));
	cmld_containers_list = list_append(cmld_containers_list, c);

	/*
	 * register observer for automatic config reload again
	 * CAUTION: This callback destroys the previous container object.
	 *          It must be the last observer in the observer list
	 */
	if (!container_register_observer(c, &cmld_container_config_sync_cb, NULL)) {
		WARN("Could not register container config sync observer callback for %s",
		     container_get_description(c));
	}

	container_set_sync_state(c, true);

cleanup:
	mem_free0(uuid_tmp);

	return c;
}

static int
cmld_load_containers_cb(const char *path, const char *name, UNUSED void *data)
{
	uuid_t *uuid = NULL;

	/* we should check for config files here, because the images
	 * might not be synced to the device from the mdm, but the config files
	 * should be always there
	 */
	size_t len = strlen(name);
	if (len < 5 || strcmp(name + len - 5, ".conf"))
		return 0;

	char *prefix = mem_strdup(name);
	prefix[len - 5] = '\0';

	int res = 0;
	char *dir = mem_printf("%s/%s", path, prefix);

	if (file_exists(dir) && !file_is_dir(dir)) {
		WARN("%s exists but is not a directory!", dir);
		goto cleanup;
	}

	uuid = uuid_new(prefix);
	if (!uuid) {
		WARN("Failed to retrieve uuid for container");
		goto cleanup;
	}

	if (cmld_reload_container((const uuid_t *)uuid, path) == NULL) {
		WARN("Failed to reload container");
		goto cleanup;
	}

	res = 1;

cleanup:
	if (uuid)
		uuid_free(uuid);
	mem_free0(dir);
	mem_free0(prefix);
	return res;
}

static int
cmld_load_containers(const char *path)
{
	if (dir_foreach(path, &cmld_load_containers_cb, NULL) < 0) {
		WARN("Could not open %s to load containers", path);
		return -1;
	}

	if (cmld_containers_get_count())
		return 0;

	WARN("No container configs found on storage");
	return 0;
}

int
cmld_reload_containers(void)
{
	int ret = -1;
	char *path = mem_printf("%s/%s", cmld_path, CMLD_PATH_CONTAINERS_DIR);
	ret = cmld_load_containers(path);

	mem_free0(path);
	return ret;
}

/**
 * Checks if a filename in the /data/logs directory contains
 * "1970" and renames the found files with a new timestamp
 */
void
cmld_rename_logfiles()
{
	DIR *directory = NULL;
	struct dirent *entry = NULL;

	directory = opendir(LOGFILE_DIR);
	if (directory != NULL) {
		while ((entry = readdir(directory)) != NULL) {
			if (strstr(entry->d_name, "197") != NULL) {
				DEBUG("Found file to rename %s", entry->d_name);
				char *filename_with_old_timestamp = mem_strdup(entry->d_name);
				char *filename = strtok(filename_with_old_timestamp, ".");
				if (filename == NULL) {
					ERROR("Could not tokenize logfile name %s", entry->d_name);
					continue;
				}
				char *filename_with_correct_timestamp =
					logf_file_new_name(filename);
				char *old_filename_with_path =
					mem_printf("%s/%s", LOGFILE_DIR, entry->d_name);
				char *new_filename_with_path = mem_printf(
					"%s/%s", LOGFILE_DIR, filename_with_correct_timestamp);
				if (rename(old_filename_with_path, new_filename_with_path))
					ERROR_ERRNO("Rename not successful %s -> %s",
						    old_filename_with_path, new_filename_with_path);
				else
					DEBUG("Rename successful %s -> %s", old_filename_with_path,
					      new_filename_with_path);
				mem_free0(filename_with_old_timestamp);
				mem_free0(filename_with_correct_timestamp);
				mem_free0(old_filename_with_path);
				mem_free0(new_filename_with_path);
			}
		}
		closedir(directory);
	} else
		ERROR("Couldn't open the directory %s", LOGFILE_DIR);
}

static void
cmld_container_boot_complete_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	ASSERT(container);
	ASSERT(cb);

	compartment_state_t state = container_get_state(container);
	if (state == COMPARTMENT_STATE_RUNNING) {
		container_oom_protect_service(container);
		// enable ipforwarding when the container in root netns has started
		if (!container_has_netns(container))
			network_enable_ip_forwarding();
		container_unregister_observer(container, cb);

		/* Make KSM aggressive to immmediately share as many pages as
		 * possible */
		ksm_set_aggressive_for(CMLD_KSM_AGGRESSIVE_TIME_AFTER_CONTAINER_BOOT);
	}
}

static void
cmld_init_control_cb(container_t *container, container_callback_t *cb, void *data)
{
	int *control_sock_p = data;

	compartment_state_t state = container_get_state(container);
	/* Check if the container got over the initial starting phase */
	if (state == COMPARTMENT_STATE_BOOTING || state == COMPARTMENT_STATE_RUNNING) {
		/* Initialize unpriv control interface on the socket previously bound into container */
		if (!control_new(control_sock_p[0], false)) {
			WARN("Could not create unpriv control socket for %s",
			     container_get_description(container));
		} else {
			INFO("Create unpriv control socket for %s",
			     container_get_description(container));
		}
#ifdef OCI
		if (!oci_control_new(control_sock_p[1])) {
			WARN("Could not create oci control socket for %s",
			     container_get_description(container));
		} else {
			INFO("Create oci control socket for %s",
			     container_get_description(container));
		}
#endif
		mem_free0(control_sock_p);
		container_unregister_observer(container, cb);
	}
	// TODO think about if this is unregistered correctly in corner cases...
}

/*
 * This callback handles internal reboot of container
 */
static void
cmld_reboot_container_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	if (container_get_state(container) == COMPARTMENT_STATE_REBOOTING ||
	    container_get_state(container) == COMPARTMENT_STATE_STOPPED) {
		container_unregister_observer(container, cb);
	}
	if (container_get_state(container) == COMPARTMENT_STATE_REBOOTING) {
		INFO("Rebooting container %s", container_get_description(container));
		container_set_key(container, DUMMY_KEY); // set dummy key for reboot
		if (cmld_container_start(container))
			WARN("Reboot of '%s' failed", container_get_description(container));
	}
}

/*
 * This callback handles audit events concerning container states
 */
static void
cmld_audit_compartment_state_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	switch (container_get_state(container)) {
	case COMPARTMENT_STATE_BOOTING:
		audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
				container == cmld_containers_get_c0() ? "c0-start" :
									"container-start",
				uuid_string(container_get_uuid(container)), 0);
		break;
	case COMPARTMENT_STATE_SHUTTING_DOWN:
		audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
				"shutting-down", uuid_string(container_get_uuid(container)), 0);
		break;
	case COMPARTMENT_STATE_STOPPED:
		if (container_get_prev_state(container) == COMPARTMENT_STATE_STARTING ||
		    container_get_prev_state(container) == COMPARTMENT_STATE_SETUP) {
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"container-start",
					uuid_string(container_get_uuid(container)), 0);
		} else {
			audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
					"container-stop",
					uuid_string(container_get_uuid(container)), 0);
		}
		container_unregister_observer(container, cb);
		break;
	case COMPARTMENT_STATE_REBOOTING:
		audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT, "reboot",
				uuid_string(container_get_uuid(container)), 0);
		container_unregister_observer(container, cb);
		break;
	default:;
	}
}

static void
cmld_container_register_observers(container_t *container)
{
	/* register callbacks which should be present while the container is running
	 * ATTENTION: All these callbacks MUST deregister themselves as soon as the container is stopped */
	if (!container_register_observer(container, &cmld_container_boot_complete_cb, NULL)) {
		ERROR("Could not register container boot complete observer callback for %s",
		      container_get_description(container));
	}

	const guestos_t *os = container_get_guestos(container);
	if (os && guestos_get_feature_install_guest(container_get_guestos(container))) {
		INFO("GuestOS allows to install new Guests => mapping control socket");
		int *control_sock_p = mem_new0(int, 2);
		control_sock_p[0] = container_bind_socket_before_start(
			container, CMLD_CONTROL_CONTAINER_SOCKET);
#ifdef OCI
		control_sock_p[1] =
			container_bind_socket_before_start(container, CMLD_OCI_CONTROL_SOCKET);
#endif

		if (!container_register_observer(container, &cmld_init_control_cb,
						 control_sock_p)) {
			WARN("Could not register observer init control callback for %s",
			     container_get_description(container));
		}
	}
	/* register an observer for auditing compartment state */
	if (!container_register_observer(container, &cmld_audit_compartment_state_cb, NULL)) {
		WARN("Could not register container audit state observer callback for %s",
		     container_get_description(container));
		audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
				"container-observer-error",
				uuid_string(container_get_uuid(container)), 0);
	}
	/* register an observer to capture the reboot command */
	if (!container_register_observer(container, &cmld_reboot_container_cb, NULL)) {
		WARN("Could not register container reboot observer callback for %s",
		     container_get_description(container));
	}
}

int
cmld_container_start(container_t *container)
{
	if (!container) {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_MGMT, "container-start-not-existing",
				NULL, 0);
		WARN("Container does not exists!");
		return -1;
	}

	if (container_is_startable(container)) {
		/* container is not running => start it */
		DEBUG("Container %s is not running => start it",
		      container_get_description(container));

		cmld_container_register_observers(container);

		// We only support "background-start"...
		const guestos_t *os = container_get_guestos(container);
		if (os && !guestos_get_feature_bg_booting(os)) {
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"container-start",
					uuid_string(container_get_uuid(container)), 0);
			WARN("Guest OS of the container %s does not support background booting",
			     container_get_description(container));
			return -1;
		}
		if (container_start(container)) {
			// audit event will be handled by observer
			WARN("Start of background container %s failed",
			     container_get_description(container));
			return -1;
		}
		time_register_clock_check();
	} else {
		// differentiate between a running container (which does not need to be started) and a 'broken' container state, that cannot be started
		if ((container_get_state(container) == COMPARTMENT_STATE_STARTING) ||
		    (container_get_state(container) == COMPARTMENT_STATE_RUNNING)) {
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"container-start-already-running",
					uuid_string(container_get_uuid(container)), 0);
		} else {
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"container-start",
					uuid_string(container_get_uuid(container)), 0);
			return -1;
		}
	}

	return 0;
}

int
cmld_container_change_pin(container_t *container, const char *passwd, const char *newpasswd)
{
	ASSERT(container);
	ASSERT(passwd);
	ASSERT(newpasswd);

	return container_change_pin(container, passwd, newpasswd);
}

void
cmld_container_ctrl_with_input_abort(void)
{
	input_clean_pin_entry();
}

typedef struct {
	container_t *container;
	cmld_container_ctrl_t container_ctrl;
	void (*err_cb)(int error, void *err_cb_data);
	void *err_cb_data;
} cmld_container_ctrl_with_input_cb_data_t;

static void
cmld_container_ctrl_with_input_cb(char *userinput, void *exec_cb_data)
{
	int ret;

	cmld_container_ctrl_with_input_cb_data_t *cb_data = exec_cb_data;
	ASSERT(cb_data);
	container_t *container = cb_data->container;
	cmld_container_ctrl_t container_ctrl = cb_data->container_ctrl;

	if (NULL == userinput) {
		ERROR("No userinput, either input reading failed or timed out!");
		ret = -1;
	} else {
		ret = cmld_container_ctrl_with_smartcard(container, userinput, container_ctrl);
	}

	if (cb_data->err_cb)
		cb_data->err_cb(ret, cb_data->err_cb_data);

	mem_free0(cb_data);
}
int
cmld_container_ctrl_with_input(container_t *container, cmld_container_ctrl_t container_ctrl,
			       void (*err_cb)(int error, void *data), void *err_cb_data)
{
	ASSERT(container);

	TRACE("Searching for USB pin reader for interactive pin entry");

	// Iterate through usb-dev list and look for USB_PIN_ENTRY device
	container_usbdev_t *usbdev_pinreader = NULL;
	for (list_t *l = container_get_usbdev_list(container); l; l = l->next) {
		container_usbdev_t *usbdev = (container_usbdev_t *)l->data;
		if (container_usbdev_get_type(usbdev) == CONTAINER_USBDEV_TYPE_PIN_ENTRY) {
			usbdev_pinreader = usbdev;
			break;
		}
	}

	IF_FALSE_RETVAL(usbdev_pinreader, -1);

	TRACE("Found USB pin reader. Device Serial: %s. Vendor:Product: %x:%x",
	      container_usbdev_get_i_serial(usbdev_pinreader),
	      container_usbdev_get_id_vendor(usbdev_pinreader),
	      container_usbdev_get_id_product(usbdev_pinreader));

	cmld_container_ctrl_with_input_cb_data_t *cb_data =
		mem_new0(cmld_container_ctrl_with_input_cb_data_t, 1);
	cb_data->container = container;
	cb_data->container_ctrl = container_ctrl;
	cb_data->err_cb = err_cb;
	cb_data->err_cb_data = err_cb_data;

	return input_read_exec(container_usbdev_get_id_vendor(usbdev_pinreader),
			       container_usbdev_get_id_product(usbdev_pinreader),
			       cmld_container_ctrl_with_input_cb, cb_data);
}

int
cmld_container_ctrl_with_smartcard(container_t *container, const char *passwd,
				   cmld_container_ctrl_t container_ctrl)
{
	ASSERT(container);
	ASSERT(passwd);

	if (container_ctrl == CMLD_CONTAINER_CTRL_START)
		return container_ctrl_with_smartcard(container, cmld_container_start, passwd);
	else if (container_ctrl == CMLD_CONTAINER_CTRL_STOP)
		return container_ctrl_with_smartcard(container, cmld_container_stop, passwd);

	ERROR("Unknown container control command %u", container_ctrl);
	return -2;
}

int
cmld_units_get_count(void)
{
	return list_length(cmld_units_list);
}

unit_t *
cmld_unit_get_by_index(int index)
{
	return list_nth_data(cmld_units_list, index);
}

unit_t *
cmld_unit_get_by_uuid(const uuid_t *uuid)
{
	ASSERT(uuid);

	for (list_t *l = cmld_units_list; l; l = l->next)
		if (uuid_equals(unit_get_uuid(l->data), uuid))
			return l->data;

	return NULL;
}

/******************************************************************************/

static void
cmld_init_c0_cb(container_t *container, container_callback_t *cb, void *data)
{
	int *control_sock_p = data;

	compartment_state_t state = container_get_state(container);
	/* Check if the container got over the initial starting phase */
	if (state == COMPARTMENT_STATE_BOOTING || state == COMPARTMENT_STATE_RUNNING) {
		/* Initialize control interface on the socket previously bound into c0 */
		cmld_control_gui = control_new(control_sock_p[0], true);
#ifdef OCI
		if (!oci_control_new(control_sock_p[1])) {
			WARN("Could not create oci control socket for %s",
			     container_get_description(container));
		} else {
			INFO("Create oci control socket for %s",
			     container_get_description(container));
		}
#endif
		mem_free0(control_sock_p);
		container_unregister_observer(container, cb);
	}
	// TODO think about if this is unregistered correctly in corner cases...
}

static void
cmld_c0_boot_complete_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	compartment_state_t state = container_get_state(container);
	if (state == COMPARTMENT_STATE_RUNNING) {
		DEBUG("c0 booted successfully!");
		container_oom_protect_service(container);
		cmld_rename_logfiles();
		container_unregister_observer(container, cb);

		// swap boot order
		a_b_update_set_boot_order();

		for (list_t *l = cmld_containers_list; l; l = l->next) {
			container_t *container = l->data;
			if (container_get_allow_autostart(container)) {
				INFO("Autostarting container %s in background",
				     container_get_name(container));
				cmld_container_start(container);
			}
		}
	}
}

static void
cmld_handle_device_shutdown(void)
{
#ifdef NO_REBOOT_ON_EXIT
	if (cmld_device_reboot == POWER_OFF) {
		DEBUG("Device shutdown: keep CML running, just exit cmld for debugging.");
		exit(0);
	}
#endif /* NO_REBOOT_ON_EXIT */

	reboot_reboot(cmld_device_reboot);
	// should never arrive here, but in case the shutdown fails somehow, we exit
	exit(0);
}

/**
 * This observer callback is attached to each container in order to check for other running containers.
 * It ensures that as soon as the last container went down, the device is shut down.
 */
static void
cmld_shutdown_container_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	compartment_state_t state = container_get_state(container);

	if (!(state == COMPARTMENT_STATE_STOPPED || state == COMPARTMENT_STATE_ZOMBIE)) {
		return;
	}

	container_unregister_observer(container, cb);

	DEBUG("Device shutdown: container %s went down, checking others before shutdown",
	      container_get_description(container));

	for (list_t *l = cmld_containers_list; l; l = l->next) {
		if (!(container_get_state(l->data) == COMPARTMENT_STATE_STOPPED ||
		      container_get_state(l->data) == COMPARTMENT_STATE_ZOMBIE)) {
			DEBUG("Device shutdown: There are still running containers, can't shut down");
			return;
		}
	}

	IF_TRUE_RETURN_TRACE(cmld_hostedmode);

	/* all containers are down, so shut down */
	DEBUG("Device shutdown: last container down; shutdown now");

	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT, "shutdown",
			uuid_string(container_get_uuid(container)), 0);

	cmld_handle_device_shutdown();
}

/**
 * This callback for c0 is used when c0 gets the shutdown command in order to
 * trigger the graceful shutdown of the other running containers
 */
static void
cmld_shutdown_c0_cb(container_t *c0, container_callback_t *cb, UNUSED void *data)
{
	compartment_state_t c0_state = container_get_state(c0);
	bool shutdown_now = true;

	/* only execute the callback if c0 goes down */
	if (!(c0_state == COMPARTMENT_STATE_SHUTTING_DOWN ||
	      c0_state == COMPARTMENT_STATE_STOPPED || c0_state == COMPARTMENT_STATE_ZOMBIE)) {
		return;
	}
	audit_log_event(container_get_uuid(c0), SSA, CMLD, CONTAINER_MGMT, "shutdown-c0-start",
			uuid_string(container_get_uuid(c0)), 0);

	DEBUG("Device shutdown: c0 went down or shutting down, checking others before shutdown");

	/* iterate over containers and check their status:
	 * - every container, which is not yet down gets an observer to inspect global containers' statuses
	 * - every container, which is furthermore not yet shutting down, is sent the shutdown command, which
	 *   needs not to be done for c0, as this observer callback call tells that it is either already
	 *   dead or in shutting down state
	 */
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		if (!(container_get_state(l->data) == COMPARTMENT_STATE_STOPPED ||
		      container_get_state(l->data) == COMPARTMENT_STATE_ZOMBIE)) {
			shutdown_now = false;
			if (!container_register_observer(l->data, &cmld_shutdown_container_cb,
							 NULL)) {
				ERROR("Could not register observer shutdown callback for %s",
				      container_get_description(l->data));
			}
			if (l->data != c0 &&
			    !(container_get_state(l->data) == COMPARTMENT_STATE_SHUTTING_DOWN)) {
				DEBUG("Device shutdown: There is another running container:%s. Shut it down first",
				      container_get_description(l->data));
				cmld_container_stop(l->data);
			}
		}
	}

	container_unregister_observer(c0, cb);

	if (shutdown_now && !cmld_hostedmode) {
		/* all containers are down, so shut down */
		DEBUG("Device shutdown: all containers already down; shutdown now");
		audit_log_event(container_get_uuid(c0), SSA, CMLD, CONTAINER_MGMT, "shutdown",
				uuid_string(container_get_uuid(c0)), 0);

		cmld_handle_device_shutdown();
	}
}

/*
 * This callback handles internal reboot of c0
 */
static void
cmld_reboot_c0_cb(container_t *c0, container_callback_t *cb, UNUSED void *data)
{
	if (container_get_state(c0) == COMPARTMENT_STATE_REBOOTING ||
	    container_get_state(c0) == COMPARTMENT_STATE_STOPPED) {
		container_unregister_observer(c0, cb);
	}
	if (container_get_state(c0) == COMPARTMENT_STATE_REBOOTING) {
		INFO("Rebooting container %s", container_get_description(c0));
		if (cmld_start_c0(c0))
			WARN("Reboot of '%s' failed", container_get_description(c0));
	}
}

static int
cmld_init_c0(const char *path, const char *c0os)
{
	IF_TRUE_RETVAL_TRACE(cmld_hostedmode, 0);

	/* Get the c0 guestos */
	guestos_t *c0_os = guestos_mgr_get_latest_by_name(c0os, true);

	uuid_t *c0_uuid = uuid_new("00000000-0000-0000-0000-000000000000");
	char *c0_config_file =
		mem_printf("%s/%s", path, "00000000-0000-0000-0000-000000000000.conf");
	if (file_exists(c0_config_file)) {
		// let do load_containers() do the rest
		INFO("Load c0 config from file %s", c0_config_file);
		goto out;
	}

	char *c0_images_folder = mem_printf("%s/%s", path, "00000000-0000-0000-0000-000000000000");
	unsigned int c0_ram_limit = 1024;
	bool c0_ns_net = true;

	const char *init =
		file_exists(guestos_get_init(c0_os)) ? guestos_get_init(c0_os) : CSERVICE_TARGET;
	char **init_argv = guestos_get_init_argv_new(c0_os);

	container_t *new_c0 =
		container_new(c0_uuid, "c0", CONTAINER_TYPE_CONTAINER, false, c0_ns_net, c0_os,
			      NULL, c0_images_folder, c0_ram_limit, NULL, 0xffffff00, false, false,
			      cmld_get_device_host_dns(), NULL, NULL, NULL, NULL, NULL, NULL, init,
			      init_argv, NULL, 0, NULL, CONTAINER_TOKEN_TYPE_NONE, false, false);

	/* store c0 as first element of the cmld_containers_list */
	cmld_containers_list = list_prepend(cmld_containers_list, new_c0);

	mem_free0(c0_images_folder);

out:
	uuid_free(c0_uuid);
	mem_free0(c0_config_file);

	return 0;
}

static int
cmld_set_key_c0(container_t *new_c0)
{
	int ret = -1;

	int c0_key_len;
	char *c0_key, *c0_ascii_key;

	char *c0_key_file = mem_printf("%s/%s.key", cmld_get_wrapped_keys_dir(), CMLD_C0_UUID);
	if (file_exists(c0_key_file)) {
		c0_key = mem_alloc0(CMLD_C0_KEY_BUF_SIZE);
		c0_key_len = file_read(c0_key_file, c0_key, CMLD_C0_KEY_BUF_SIZE);
		if (c0_key_len < CMLD_C0_KEY_LEN) {
			ERROR("Failed to read key from %s for c0", c0_key_file);
			goto out;
		}
	} else {
		if (container_images_dir_contains_image(new_c0)) {
			// set legacy mode where we used the dummy key for c0
			c0_key_len = strlen(DUMMY_KEY) / 2;
			c0_key = mem_alloc0(c0_key_len);
			if (convert_hex_to_bin(DUMMY_KEY, strlen(DUMMY_KEY), (uint8_t *)c0_key,
					       c0_key_len) < 0) {
				ERROR("Failed to generate key for c0 (using legacy DUMMY_KEY)");
				goto out;
			}
		} else {
			// for new images we use a random key for integrity protection of c0
			c0_key_len = CMLD_C0_KEY_LEN;
			c0_key = mem_alloc0(c0_key_len);
			int bytes_read = crypto_random_get_bytes((uint8_t *)c0_key, c0_key_len);
			if (bytes_read != c0_key_len) {
				ERROR("Failed to generate key for c0");
				goto out;
			}
		}

		int bytes_written = file_write(c0_key_file, c0_key, c0_key_len);
		if (bytes_written != c0_key_len) {
			ERROR("Failed to write c0 key to file, bytes written: %d", bytes_written);
			goto out;
		}
	}

	c0_ascii_key = convert_bin_to_hex_new((uint8_t *)c0_key, c0_key_len);
	container_set_key(new_c0, c0_ascii_key);

	mem_memset0(c0_key, c0_key_len);
	mem_memset0(c0_ascii_key, strlen(c0_ascii_key));
	mem_free0(c0_ascii_key);

	ret = 0;

out:
	if (c0_key)
		mem_free0(c0_key);
	mem_free0(c0_key_file);

	return ret;
}

static int
cmld_start_c0(container_t *new_c0)
{
	IF_TRUE_RETVAL_TRACE(cmld_hostedmode, 0);

	INFO("Starting management container %s...", container_get_description(new_c0));

	int *control_sock_p = mem_new0(int, 2);
	control_sock_p[0] =
		container_bind_socket_before_start(new_c0, CMLD_CONTROL_CONTAINER_SOCKET);
#ifdef OCI
	control_sock_p[1] = container_bind_socket_before_start(new_c0, CMLD_OCI_CONTROL_SOCKET);
#endif

	if (!container_register_observer(new_c0, &cmld_init_c0_cb, control_sock_p)) {
		WARN("Could not register observer init callback on c0");
		return -1;
	}
	if (!container_register_observer(new_c0, &cmld_c0_boot_complete_cb, NULL)) {
		WARN("Could not register observer boot complete callback on c0");
		return -1;
	}

	IF_TRUE_RETVAL_ERROR(cmld_set_key_c0(new_c0), -1);

	if (container_start(new_c0)) {
		audit_log_event(container_get_uuid(new_c0), FSA, CMLD, CONTAINER_MGMT, "c0-start",
				uuid_string(container_get_uuid(new_c0)), 0);
		FATAL("Could not start management container");
	}

	/* register an observer to capture the shutdown command for the special container c0 */
	if (!container_register_observer(new_c0, &cmld_shutdown_c0_cb, NULL)) {
		WARN("Could not register observer shutdown callback for c0");

		audit_log_event(container_get_uuid(new_c0), FSA, CMLD, CONTAINER_MGMT, "c0-start",
				uuid_string(container_get_uuid(new_c0)), 0);
		return -1;
	}
	/* register an observer to capture the reboot command for the special container c0 */
	if (!container_register_observer(new_c0, &cmld_reboot_c0_cb, NULL)) {
		WARN("Could not register observer reboot callback for c0");
		audit_log_event(container_get_uuid(new_c0), FSA, CMLD, CONTAINER_MGMT, "c0-start",
				uuid_string(container_get_uuid(new_c0)), 0);
		return -1;
	}
	/* register an observer for auditing compartment state */
	if (!container_register_observer(new_c0, &cmld_audit_compartment_state_cb, NULL)) {
		WARN("Could not register container audit state observer callback for %s",
		     container_get_description(new_c0));
		audit_log_event(container_get_uuid(new_c0), FSA, CMLD, CONTAINER_MGMT, "c0-start",
				uuid_string(container_get_uuid(new_c0)), 0);
		return -1;
	}
	/* check that time is in trusted range after start */
	time_register_clock_check();

	return 0;
}

static void
cmld_tune_network(const char *host_addr, uint32_t host_subnet, const char *host_if,
		  const char *host_gateway, const char *host_dns)
{
	// allow exclusive moving of network interfaces to containers
	cmld_netif_phys_list = network_get_physical_interfaces_new();

	IF_TRUE_RETURN_TRACE(cmld_hostedmode);

	/*
	 * Increase the max socket send buffer size which is used for all types of
	 * connections. In particular, this is required by the TrustmeService in
	 * order to send moderately large messages (e.g. wallpaper data) over the
	 * unix domain socket to the cmld without blocking for several seconds.
	 */
	if (file_printf("/proc/sys/net/core/wmem_max", "%d", 1024 * 1024) < 0)
		WARN("Could not increase max OS send buffer size");

	/* configure loopback interface of root network namespace */
	network_setup_loopback();

	/* configure resolver of root network namespace */
	if (-1 == file_printf("/etc/resolv.conf", "nameserver %s", host_dns))
		WARN("Could not setup dns server for CML");

	DEBUG("Trying to configure eth0");
	//network_set_ip_addr_of_interface("10.0.2.15", 24, "eth0");
	network_set_ip_addr_of_interface(host_addr, host_subnet, host_if);
	network_setup_default_route(host_gateway, true);
	network_enable_ip_forwarding();
}

static void
cmld_init_stage_reached(cmld_init_stage_t stage)
{
	// skip if a completed stage is reached again, e.g., due to an unit restart
	if (cmld_init_stage >= stage)
		return;

	switch (stage) {
	case CMLD_INIT_STAGE_UNIT:
		INFO("CMLD_INIT_STAGE_UNIT completed.");
		cmld_init_stage = stage;
		cmld_init_stage_container();
		break;
	case CMLD_INIT_STAGE_CONTAINER:
		INFO("CMLD_INIT_STAGE_CONTAINER completed.");
		cmld_init_stage = stage;
		break;
	default:
		return;
	}
}

int
cmld_init_stage_unit(const char *path)
{
	if (cmld_init_stage > CMLD_INIT_STAGE_ZERO) {
		TRACE("cmld init stage UNIT already done. Skip.");
		return 0;
	}

	INFO("Storage path is %s", path);
	cmld_path = path;
	cmld_container_path = mem_printf("%s/%s", cmld_path, CMLD_PATH_CONTAINERS_DIR);

	// ensure data directory in CML is root owned
	struct stat s;
	if (!stat(cmld_path, &s) && s.st_uid != 0) {
		if (dir_chown_folder(cmld_path, 0, 0) < 0) {
			FATAL("Could not chown %s to root:root failed.", cmld_path);
		}
	}

	if (prctl(PR_SET_CHILD_SUBREAPER, 1))
		FATAL("Could not setup cmld as child subreaper!");

	if (mount_private_tmp())
		FATAL("Could not setup private tmp!");

	/* Currently the given path is used by the config module to generate the
	 * paths and it must therefore be ensured that it exists before loading
	 * the config file. */
	if (mkdir(path, 0755) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir base path %s", path);

	char *device_path =
		a_b_update_get_path_new(DEFAULT_CONF_BASE_PATH "/" CMLD_PATH_DEVICE_CONF);
	INFO("device.conf path is %s", device_path);
	device_config_t *device_config = device_config_new(device_path);
	mem_free0(device_path);

	// set hostedmode, which disables some configuration
	cmld_hostedmode = device_config_get_hostedmode(device_config);

	if (mount_remount_root_ro() < 0 && !cmld_hostedmode)
		FATAL("Could not remount rootfs read-only");

	if (mount_debugfs() < 0)
		WARN("Could not mount debugfs (already mounted?)");
	else
		INFO("mounted debugfs");

	if (!cmld_hostedmode)
		a_b_update_init();

	// init audit and set max audit log file size
	if (audit_init(device_config_get_audit_size(device_config)) < 0)
		WARN("Could not init audit module");
	else
		INFO("audit initialized.");

	if (time_init() < 0)
		FATAL("Could not init time module");
	INFO("time initialized.");

	char *btime = mem_printf("%lld", (long long)time_cml(NULL));
	audit_log_event(NULL, SSA, CMLD, GENERIC, "boot-time", NULL, 2, "time", btime);
	mem_free0(btime);

	if (scd_init() < 0)
		FATAL("Could not init scd module");
	INFO("scd initialized.");
	if (atexit(&scd_cleanup))
		WARN("Could not register on exit cleanup method 'scd_cleanup()'");

	if (device_config_get_tpm_enabled(device_config)) {
		if (tss_init() < 0) {
			FATAL("Failed to initialize TSS / TPM 2.0 and tpm2d");
		} else {
			INFO("tss initialized.");
			if (atexit(&tss_cleanup))
				WARN("could not register on exit cleanup method 'tss_cleanup()'");
		}
	}

	device_config_free(device_config);

	return 0;
}

static int
cmld_init_stage_container(void)
{
	if (cmld_init_stage > CMLD_INIT_STAGE_UNIT) {
		TRACE("cmld init stage CONTAINER already done. Skip.");
		return 0;
	}

	// set device uuid from device_id configuration file (initially generated by scd)
	char *device_id_path = mem_printf("%s/%s", cmld_path, CMLD_PATH_DEVICE_ID);
	device_id_t *device_id = device_id_new(device_id_path);
	cmld_device_uuid = mem_strdup(device_id_get_uuid(device_id));
	mem_free0(device_id_path);

	char *device_path =
		a_b_update_get_path_new(DEFAULT_CONF_BASE_PATH "/" CMLD_PATH_DEVICE_CONF);
	INFO("device.conf path is %s", device_path);
	device_config_t *device_config = device_config_new(device_path);
	mem_free0(device_path);

	// activate signature checking of container configs if enabled
	cmld_signed_configs = device_config_get_signed_configs(device_config);

	cmld_tune_network(device_config_get_host_addr(device_config),
			  device_config_get_host_subnet(device_config),
			  device_config_get_host_if(device_config),
			  device_config_get_host_gateway(device_config),
			  device_config_get_host_dns(device_config));

	cmld_shared_data_dir = mem_printf("%s/%s", cmld_path, CMLD_PATH_SHARED_DATA_DIR);
	if (mkdir(cmld_shared_data_dir, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir shared data directory %s", cmld_shared_data_dir);

	const char *update_base_url = device_config_get_update_base_url(device_config);
	cmld_device_update_base_url = update_base_url ? mem_strdup(update_base_url) : NULL;

	const char *host_dns = device_config_get_host_dns(device_config);
	cmld_device_host_dns = host_dns ? mem_strdup(host_dns) : NULL;

	const char *c0os_name = device_config_get_c0os(device_config);
	cmld_c0os_name = c0os_name ? mem_strdup(c0os_name) : NULL;

	if (hotplug_init() < 0)
		FATAL("Could not init hotplug module");
	INFO("hotplug initialized.");
	if (atexit(&hotplug_cleanup))
		WARN("Could not register on exit cleanup method 'hotplug_cleanup()'");

	if (ksm_init() < 0)
		WARN("Could not init ksm module");
	else
		INFO("ksm initialized.");

	if (lxcfs_init() < 0) {
		WARN("Plattform does not support LXCFS");
	} else {
		INFO("lxcfs initialized.");
		if (atexit(&lxcfs_cleanup))
			WARN("could not register on exit cleanup method 'lxcfs_cleanup()'");
	}

	// Read the provision-status-file to set provisioned flag of control structs accordingly
	char *provisioned_file = mem_printf("%s/%s", DEFAULT_BASE_PATH, PROVISIONED_FILE_NAME);
	if (file_exists(provisioned_file)) {
		DEBUG("Device is already provisioned");
		cmld_device_provisioned = true;
	} else {
		DEBUG("Device is not yet provisioned and provision-status-file does not yet exist");
	}
	mem_free0(provisioned_file);

	/* the control module sets up a local or remote socket, registers a
	 * callback (via event_) and parses incoming commands
	 * and calls the corresponding function in the cmld module,
	 * e.g. cmld_switch_container */
	if (dir_mkdir_p(CMLD_SOCKET_DIR, 0755) < 0) {
		FATAL("Could not create directory for cmld_cli control socket");
	}
	cmld_control_cml = control_local_new(CMLD_CONTROL_SOCKET);
	if (!cmld_control_cml) {
		FATAL("Could not init cmld_cli control socket");
	}
	INFO("created control socket.");

#ifdef OCI
	cmld_oci_control_cml = oci_control_local_new(CMLD_OCI_CONTROL_SOCKET);
	if (!cmld_oci_control_cml) {
		FATAL("Could not init cmld_oci control socket");
	}
	INFO("created oci control socket.");
#endif

	char *guestos_path = mem_printf("%s/%s", cmld_path, CMLD_PATH_GUESTOS_DIR);
	bool allow_locally_signed = device_config_get_locally_signed_images(device_config);
	if (guestos_mgr_init(guestos_path, allow_locally_signed) < 0 && !cmld_hostedmode)
		FATAL("Could not load guest operating systems");
	mem_free0(guestos_path);
	INFO("guestos initialized.");
	guestos_mgr_update_images();

	char *containers_path = mem_printf("%s/%s", cmld_path, CMLD_PATH_CONTAINERS_DIR);
	if (mkdir(containers_path, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir containers directory %s", containers_path);

	cmld_wrapped_keys_path = mem_printf("%s/%s", cmld_path, CMLD_PATH_CONTAINER_KEYS_DIR);
	if (mkdir(cmld_wrapped_keys_path, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir container keys directory %s", containers_path);

	if (cmld_init_c0(containers_path, device_config_get_c0os(device_config)) < 0)
		FATAL("Could not init c0");

	if (cmld_load_containers(containers_path) < 0)
		FATAL("Could not load containers");

	// check for unused superseded GuestOSes and remove them
	guestos_mgr_purge_obsolete();

	if (cmld_start_c0(cmld_containers_get_c0()) < 0)
		FATAL("Could not start c0");

	mem_free0(containers_path);

	device_config_free(device_config);
	device_id_free(device_id);

	// set init stage CONTAINER completed
	cmld_init_stage_reached(CMLD_INIT_STAGE_CONTAINER);
	return 0;
}

void
cmld_init_stage_unit_notify(unit_t *unit)
{
	if (!list_find(cmld_units_list, unit))
		cmld_units_list = list_append(cmld_units_list, unit);

	bool units_pending = false;
	for (list_t *l = cmld_units_list; l; l = l->next) {
		unit_t *u = l->data;
		if (unit_get_state(u) != COMPARTMENT_STATE_RUNNING) {
			units_pending = true;
			break;
		}
	}

	DEBUG("Unit notify: unit '%s' is pending %s", unit_get_name(unit),
	      units_pending ? "true" : "false");

	if (units_pending)
		return;

	// set init stage UNIT completed
	cmld_init_stage_reached(CMLD_INIT_STAGE_UNIT);
}

container_t *
cmld_container_create_clone(container_t *container)
{
	ASSERT(container);
	ASSERT(0); // TODO
	return NULL;
}

/**
 * Checks if a network interface is explicitly assigned to a container.
 */
static bool
cmld_is_interface_in_config(container_t *container, const char *if_name)
{
	ASSERT(container);
	ASSERT(if_name);

	for (list_t *l = container_get_pnet_cfg_list(container); l; l = l->next) {
		container_pnet_cfg_t *cfg = l->data;
		if (strcmp(cfg->pnet_name, if_name) == 0)
			return true;
	}
	return false;
}

container_t *
cmld_container_create_from_config(const uint8_t *config, size_t config_len, uint8_t *sig,
				  size_t sig_len, uint8_t *cert, size_t cert_len)
{
	ASSERT(config);
	ASSERT(config_len);
	char *path = mem_printf("%s/%s", cmld_path, CMLD_PATH_CONTAINERS_DIR);
	IF_NULL_RETVAL(path, NULL);

	container_t *c =
		cmld_container_new(path, NULL, config, config_len, sig, sig_len, cert, cert_len);

	if (c) {
		// check if enough disk space is available
		mount_t *mnt_table = container_get_mnt(c);
		off_t disk_space_required = mount_get_disk_usage_container(mnt_table);
		IF_TRUE_GOTO_ERROR(disk_space_required < 0, err);

		IF_FALSE_GOTO_ERROR(file_disk_space_available(path, disk_space_required,
							      CMLD_STORAGE_FREE_THRESHOLD),
				    err);

		cmld_containers_list = list_append(cmld_containers_list, c);
		/*
		 * register an observer for automatic config reload
		 * CAUTION: This callback destroys the previous container object.
		 *          It must be the last observer in the observer list
		 */
		if (!container_register_observer(c, &cmld_container_config_sync_cb, NULL)) {
			WARN("Could not register container config sync observer callback for %s",
			     container_get_description(c));
		}

		//Remove interfaces immediately from core container, if they are explicitly assigned to a service container.
		container_t *c0 = cmld_containers_get_c0();
		if (c0 && c0 != c && container_is_stoppable(c0)) {
			for (list_t *l = container_get_pnet_cfg_list(c); l; l = l->next) {
				container_pnet_cfg_t *cfg = l->data;
				if (cmld_is_interface_in_config(c0, cfg->pnet_name))
					continue;
				INFO("Container created. Removing former implicitly assigned interface %s from core container",
				     cfg->pnet_name);
				container_remove_net_interface(c0, cfg->pnet_name);
			}
		}

		audit_log_event(container_get_uuid(c), SSA, CMLD, CONTAINER_MGMT,
				"container-create", uuid_string(container_get_uuid(c)), 0);
		INFO("Created container %s (uuid=%s).", container_get_name(c),
		     uuid_string(container_get_uuid(c)));
	} else {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_MGMT, "container-create", NULL, 0);
		WARN("Could not create new container object from config");
	}
	mem_free0(path);
	return c;
err:
	container_free(c);
	mem_free0(path);
	return NULL;
}

static void
cmld_container_destroy_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	ASSERT(container);

	/* skip if the container is not stopped */
	IF_FALSE_RETURN_TRACE(container_get_state(container) == COMPARTMENT_STATE_STOPPED);

	/* unregister observer */
	if (cb)
		container_unregister_observer(container, cb);

	//Move interfaces which are no longer explicitly assigned to a service container to core container.
	container_t *c0 = cmld_containers_get_c0();
	if (c0 && container_is_stoppable(c0)) {
		list_t *pnet_list = container_get_pnet_cfg_list(container);
		for (list_t *l = pnet_list; l; l = l->next) {
			container_pnet_cfg_t *cfg = l->data;
			INFO("Container removed. Moving former explicitly assigned interface %s to core container",
			     cfg->pnet_name);
			container_pnet_cfg_t *c0_cfg =
				container_pnet_cfg_new(cfg->pnet_name, false, NULL);
			if (container_add_net_interface(c0, c0_cfg) < 0) {
				WARN("Failed to add interface %s to core container",
				     cfg->pnet_name);
				container_pnet_cfg_free(c0_cfg);
			}
			//On success c_net_add_interface takes ownership of c0_cfg
		}
	}

	/* destroy the container */
	if (container_destroy(container) < 0) {
		audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
				"container-remove", uuid_string(container_get_uuid(container)), 0);
		ERROR("Could not destroy container");
		container_set_state(container, COMPARTMENT_STATE_ZOMBIE);
		return;
	}

	/* cleanup container */
	cmld_containers_list = list_remove(cmld_containers_list, container);
	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
			"container-remove", uuid_string(container_get_uuid(container)), 0);

	if (cb) {
		// delayed free to allow all observers to finish up
		container_finish_observers(container, cmld_container_delayed_free, container);
	} else {
		container_free(container);
	}
}

int
cmld_container_destroy(container_t *container)
{
	ASSERT(container);

	// don't delete management container c0!
	container_t *c0 = cmld_containers_get_c0();
	IF_TRUE_RETVAL(c0 == container, -1);

	if (container_get_state(container) != COMPARTMENT_STATE_STOPPED) {
		container_kill(container);

		/* Register observer to wait for completed container_stop */
		if (!container_register_observer(container, &cmld_container_destroy_cb, NULL)) {
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"container-remove",
					uuid_string(container_get_uuid(container)), 0);
			DEBUG("Could not register destroy callback");
			return -1;
		}
	} else {
		/* Container is already stopped call cb directly */
		cmld_container_destroy_cb(container, NULL, NULL);
	}

	return 0;
}

int
cmld_container_stop(container_t *container)
{
	ASSERT(container);

	DEBUG("Trying to stop container %s", container_get_description(container));

	// check if the container is in a stoppable state
	// otherwise the container_stop command is regarded
	// as failed
	if (!container_is_stoppable(container)) {
		WARN("Container is not stoppable. Aborting");
		audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
				"container-stop", uuid_string(container_get_uuid(container)), 0);
		return -1;
	}

	int ret = container_stop(container);
	if (ret < 0) {
		char *argv[] = { "halt", NULL };
		if (container_run(container, false, argv[0], 1, argv, -1)) {
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"request-clean-shutdown",
					uuid_string(container_get_uuid(container)), 0);
			DEBUG("Some modules could not be stopped successfully, killing container.");
			container_kill(container);
			audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
					"force-stop", uuid_string(container_get_uuid(container)),
					0);
			return 0;
		}
		return -1;
	}

	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
			"request-clean-shutdown", uuid_string(container_get_uuid(container)), 0);

	return 0;
}

int
cmld_container_freeze(container_t *container)
{
	ASSERT(container);

	return container_freeze(container);
}

int
cmld_container_unfreeze(container_t *container)
{
	ASSERT(container);

	return container_unfreeze(container);
}

int
cmld_container_allow_audio(container_t *container)
{
	ASSERT(container);

	return container_allow_audio(container);
}

int
cmld_container_deny_audio(container_t *container)
{
	ASSERT(container);

	return container_deny_audio(container);
}

int
cmld_container_snapshot(container_t *container)
{
	ASSERT(container);
	WARN("Container snapshot is not implemented, yet");
	return 0;
}

int
cmld_container_wipe(container_t *container)
{
	ASSERT(container);

	/* remove wrapped key */
	char *key_file = mem_printf("%s/%s.key", cmld_get_wrapped_keys_dir(),
				    uuid_string(container_get_uuid(container)));
	if (file_exists(key_file))
		unlink(key_file);

	mem_free0(key_file);
	return container_wipe(container);
}

void
cmld_wipe_device()
{
	dir_delete_folder(cmld_path, CMLD_PATH_GUESTOS_DIR);
	dir_delete_folder(cmld_path, CMLD_PATH_CONTAINERS_DIR);
	dir_delete_folder(cmld_path, CMLD_PATH_CONTAINER_KEYS_DIR);
	dir_delete_folder(cmld_path, CMLD_PATH_CONTAINER_TOKENS_DIR);
	dir_delete_folder(LOGFILE_DIR, "");
	if (!cmld_hostedmode)
		reboot_reboot(POWER_OFF);
}

const char *
cmld_get_c0os(void)
{
	return cmld_c0os_name;
}

int
cmld_guestos_delete(const char *guestos_name)
{
	guestos_t *os = guestos_mgr_get_latest_by_name(guestos_name, false);
	IF_NULL_RETVAL(os, -1);

	// do not delete gustos of managment container c0
	container_t *c0 = cmld_containers_get_c0();
	IF_TRUE_RETVAL(os == container_get_guestos(c0), -1);

	return guestos_mgr_delete(os);
}

bool
cmld_netif_phys_remove_by_name(const char *if_name)
{
	IF_NULL_RETVAL(if_name, false);

	list_t *found = NULL;
	for (list_t *l = cmld_netif_phys_list; l; l = l->next) {
		char *cmld_if_name = l->data;
		if (0 == strcmp(if_name, cmld_if_name)) {
			found = l;
			mem_free0(cmld_if_name);
			break;
		}
	}
	if (found) {
		INFO("Removing '%s' from global available physical netifs", if_name);
		cmld_netif_phys_list = list_unlink(cmld_netif_phys_list, found);
		return true;
	}
	return false;
}

void
cmld_netif_phys_add_by_name(const char *if_name)
{
	IF_NULL_RETURN(if_name);

	/* Only track interfaces that are actually present in root ns.
	 * This prevents races where an interface transiently passes
	 * through root ns (e.g. during reclaim core container -> root -> service container)
	 * and a deferred event tries to re-add it after it has
	 * already been moved to a container's netns.
	 */
	char *sysfs_path = mem_printf("/sys/class/net/%s", if_name);
	if (!file_exists(sysfs_path)) {
		DEBUG("Not adding '%s' to available phys netifs (not in root ns)", if_name);
		mem_free0(sysfs_path);
		return;
	}
	mem_free0(sysfs_path);

	INFO("Adding '%s' to global available physical netifs", if_name);

	for (list_t *l = cmld_netif_phys_list; l; l = l->next) {
		char *cmld_if_name = l->data;
		if (0 == strcmp(if_name, cmld_if_name)) {
			return;
		}
	}
	cmld_netif_phys_list = list_append(cmld_netif_phys_list, mem_strdup(if_name));
}

void
cmld_cleanup(void)
{
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *container = l->data;
		container_free(container);
	}
	list_delete(cmld_containers_list);

	list_delete(cmld_units_list);

	if (cmld_control_gui)
		control_free(cmld_control_gui);
	if (cmld_control_cml)
		control_free(cmld_control_cml);

	if (cmld_device_uuid)
		mem_free0(cmld_device_uuid);
	if (cmld_device_update_base_url)
		mem_free0(cmld_device_update_base_url);
	if (cmld_device_host_dns)
		mem_free0(cmld_device_host_dns);
	if (cmld_c0os_name)
		mem_free0(cmld_c0os_name);
	if (cmld_shared_data_dir)
		mem_free0(cmld_shared_data_dir);

	for (list_t *l = cmld_netif_phys_list; l; l = l->next) {
		char *name = l->data;
		mem_free0(name);
	}
	list_delete(cmld_netif_phys_list);
}

void
cmld_reboot_device(void)
{
	// just set internal state variable and let container shutdown callbacks
	// handle the actual reboot, after all containers are down
	cmld_device_reboot = REBOOT;

	container_t *c0 = cmld_containers_get_c0();
	IF_NULL_RETURN(c0);

	// stopping c0 also stops other containers.
	cmld_container_stop(c0);
}

/**
 * Checks if a network interface (by kernel name) is explicitly assigned to any
 * container. Config entries may be kernel names or MACs, so both are compared.
 */
bool
cmld_is_netif_assigned(const char *if_name)
{
	IF_NULL_RETVAL(if_name, false);

	uint8_t if_mac[6];
	bool have_mac = (network_get_mac_by_ifname(if_name, if_mac) == 0);

	for (int i = 0; i < cmld_containers_get_count(); i++) {
		container_t *c = cmld_container_get_by_index(i);

		for (list_t *l = container_get_pnet_cfg_list(c); l; l = l->next) {
			container_pnet_cfg_t *cfg = l->data;
			// Direct name match
			if (strcmp(cfg->pnet_name, if_name) == 0)
				return true;
			// MAC match: config entry is a MAC string, compare with iface's MAC
			if (have_mac) {
				uint8_t cfg_mac[6];
				if (network_str_to_mac_addr(cfg->pnet_name, cfg_mac) != -1 &&
				    memcmp(if_mac, cfg_mac, 6) == 0)
					return true;
			}
		}
	}
	return false;
}

/**
 * Synchronize network interfaces after config update.
 * Interfaces ADDED to config: remove from core container if implicit, add to service container if running
 * Interfaces REMOVED from config: remove from service container, return to core container as implicit
 */
static int
cmld_sync_container_net_ifaces(container_t *container, list_t *new_pnet_cfg_list)
{
	ASSERT(container);

	list_t *current_list = container_get_pnet_cfg_list(container);
	container_t *core_container = cmld_containers_get_c0();
	bool core_container_is_up = core_container && container_is_stoppable(core_container);
	bool service_container_is_up = container_is_stoppable(container);

	/* Find interfaces REMOVED from config (in current but not in new).
	 * These become unassigned and should move to core container as implicit.
	 */
	for (list_t *l = current_list; l; l = l->next) {
		container_pnet_cfg_t *cfg = l->data;
		bool found = false;
		for (list_t *n = new_pnet_cfg_list; n; n = n->next) {
			container_pnet_cfg_t *new_cfg = n->data;
			if (strcmp(cfg->pnet_name, new_cfg->pnet_name) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			INFO("Interface %s removed from config, now unassigned (implicit to core container)",
			     cfg->pnet_name);

			// Remove from service container (if running) or it's already in root ns
			if (service_container_is_up) {
				container_remove_net_interface(container, cfg->pnet_name);
			}

			// Add to core container as implicit (if running)
			if (core_container_is_up) {
				container_pnet_cfg_t *c0_cfg =
					container_pnet_cfg_new(cfg->pnet_name, false, NULL);
				if (container_add_net_interface(core_container, c0_cfg) < 0)
					container_pnet_cfg_free(c0_cfg);
			}
		}
	}

	/* Find interfaces ADDED to config (in new but not in current).
	 * These become assigned and should be removed from core container (only if implicit).
	 */
	for (list_t *l = new_pnet_cfg_list; l; l = l->next) {
		container_pnet_cfg_t *new_cfg = l->data;
		bool found = false;
		for (list_t *c = current_list; c; c = c->next) {
			container_pnet_cfg_t *cfg = c->data;
			if (strcmp(cfg->pnet_name, new_cfg->pnet_name) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			/* Check if interface is explicitly assigned to core container */
			if (core_container &&
			    cmld_is_interface_in_config(core_container, new_cfg->pnet_name)) {
				WARN("Interface %s is explicitly assigned to core container, "
				     "cannot assign to service container",
				     new_cfg->pnet_name);
				continue;
			}

			INFO("Interface %s added to config, now assigned to service container",
			     new_cfg->pnet_name);

			/* Remove from core container first (if running) - it was implicit */
			if (core_container_is_up) {
				container_remove_net_interface(core_container, new_cfg->pnet_name);
			}

			/* Add to service container (if running), otherwise it stays in root ns */
			if (service_container_is_up) {
				container_add_net_interface(container, new_cfg);
			}
		}
	}
	return 0;
}

static bool
cmld_container_has_token_changed(container_t *container, container_config_t *conf)
{
	ASSERT(container);

	return container_has_token_changed(container, container_config_get_token_type(conf),
					   container_config_get_usbtoken_serial(conf));
}

int
cmld_update_config(container_t *container, uint8_t *buf, size_t buf_len, uint8_t *sig_buf,
		   size_t sig_len, uint8_t *cert_buf, size_t cert_len)
{
	ASSERT(container);
	int ret = -1;
	container_config_t *conf =
		container_config_new(container_get_config_filename(container), buf, buf_len,
				     sig_buf, sig_len, cert_buf, cert_len);

	IF_FALSE_RETVAL_DEBUG(conf, -1);

	// Check if new config needs additional disk space
	mount_t *mnt_table_new = mount_new();
	guestos_fill_mount(container_get_guestos(container), mnt_table_new);
	guestos_fill_mount_setup(container_get_guestos(container), mnt_table_new);
	container_config_fill_mount(conf, mnt_table_new);
	off_t new_disk_usage = mount_get_disk_usage_container(mnt_table_new);
	off_t current_disk_usage = mount_get_disk_usage_container(container_get_mnt(container));
	if (new_disk_usage > current_disk_usage) {
		IF_FALSE_GOTO_ERROR(file_disk_space_available(container_get_images_dir(container),
							      new_disk_usage - current_disk_usage,
							      CMLD_STORAGE_FREE_THRESHOLD),
				    out);
	}

	ret = container_config_write(conf);
	container_set_sync_state(container, false);

	// Sync network interfaces based on config changes
	list_t *new_pnet_cfg_list = container_config_get_net_ifaces_list_new(conf);
	if (cmld_sync_container_net_ifaces(container, new_pnet_cfg_list) < 0) {
		WARN("Failed to sync network interfaces for %s", container_get_name(container));
	}
	for (list_t *l = new_pnet_cfg_list; l; l = l->next) {
		container_pnet_cfg_free(l->data);
	}
	list_delete(new_pnet_cfg_list);

	// Wipe container if USB token serial changed
	if (cmld_container_has_token_changed(container, conf)) {
		if (container_wipe(container)) {
			ERROR("Failed to wipe user data. Setting container state to ZOMBIE");
			container_set_state(container, COMPARTMENT_STATE_ZOMBIE);
		}
		if ((container_get_token_type(container) == CONTAINER_TOKEN_TYPE_USB) &&
		    container_scd_release_pairing(container)) {
			ERROR("Failed to remove token paired file. Setting container state to ZOMBIE");
			container_set_state(container, COMPARTMENT_STATE_ZOMBIE);
		}
	}
out:
	mount_free(mnt_table_new);
	container_config_free(conf);
	return ret;
}

const char *
cmld_get_containers_dir(void)
{
	return cmld_container_path;
}

const char *
cmld_get_wrapped_keys_dir(void)
{
	return cmld_wrapped_keys_path;
}

int
cmld_container_add_net_iface(container_t *container, container_pnet_cfg_t *pnet_cfg,
			     bool persistent)
{
	ASSERT(container);
	IF_NULL_RETVAL(pnet_cfg, -1);

	int res = 0;
	container_t *c0 = cmld_containers_get_c0();
	bool c0_is_up = c0 ? container_is_stoppable(c0) : false;

	if (c0_is_up) {
		if (c0 == container) {
			// if interface should be added to c0 just add it.
			res = container_add_net_interface(container, pnet_cfg);
			return res;
		}

		/* if c0 is running the interface is occupied by c0, thus we have
		 * to take it back to cml first.
		 */
		res = container_remove_net_interface(c0, pnet_cfg->pnet_name);
	}

	res |= container_add_net_interface(container, pnet_cfg);
	if (res || !persistent)
		return res;

	container_config_t *conf = container_config_new(container_get_config_filename(container),
							NULL, 0, NULL, 0, NULL, 0);
	container_config_append_net_ifaces(conf, pnet_cfg->pnet_name);
	container_config_write(conf);
	container_config_free(conf);
	return 0;
}

int
cmld_container_remove_net_iface(container_t *container, const char *iface, bool persistent)
{
	ASSERT(container);
	int res = container_remove_net_interface(container, iface);
	if (res || !persistent)
		return res;

	container_config_t *conf = container_config_new(container_get_config_filename(container),
							NULL, 0, NULL, 0, NULL, 0);
	container_config_remove_net_ifaces(conf, iface);
	container_config_write(conf);
	container_config_free(conf);
	return 0;
}

const char *
cmld_get_cmld_dir(void)
{
	return cmld_path;
}
