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

// uncomment to prevent reboot
#define TRUSTME_DEBUG

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
#include "hardware.h"
#include "mount.h"
#include "device_config.h"
#include "control.h"
#include "guestos_mgr.h"
#include "guestos.h"
#include "smartcard.h"
#include "tss.h"
#include "ksm.h"
#include "uevent.h"
#include "time.h"
#include "lxcfs.h"
#include "audit.h"
#include "time.h"

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>

// clang-format off
#define CMLD_CONTROL_SOCKET SOCK_PATH(control)
// clang-format on

#define CMLD_SUSPEND_TIMEOUT 5000

// files and directories in cmld's home path /data/cml
#define CMLD_PATH_DEVICE_CONF "device.conf"
#define CMLD_PATH_USERS_DIR "users"
#define CMLD_PATH_GUESTOS_DIR "operatingsystems"
#define CMLD_PATH_CONTAINERS_DIR "containers"
#define CMLD_PATH_CONTAINER_KEYS_DIR "keys"
#define CMLD_PATH_CONTAINER_TOKENS_DIR "tokens"
#define CMLD_PATH_SHARED_DATA_DIR "shared"

#define CMLD_WAKE_LOCK_STARTUP "ContainerStartup"

#define CMLD_KSM_AGGRESSIVE_TIME_AFTER_CONTAINER_BOOT 70000

/*
 * dummy key used for unecnrypted c0 and for reboots where the real key
 * is already in kernel
 */
#define DUMMY_KEY                                                                                  \
	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

static const char *cmld_path = DEFAULT_BASE_PATH;

static list_t *cmld_containers_list = NULL; // usually first element is c0

static control_t *cmld_control_mdm = NULL;
static control_t *cmld_control_gui = NULL;
static control_t *cmld_control_cml = NULL;

static smartcard_t *cmld_smartcard = NULL;

static container_connectivity_t cmld_connectivity = CONTAINER_CONNECTIVITY_OFFLINE;

static char *cmld_device_uuid = NULL;
static char *cmld_device_update_base_url = NULL;
static char *cmld_device_host_dns = NULL;
static char *cmld_c0os_name = NULL;

static char *cmld_shared_data_dir = NULL;

static list_t *cmld_netif_phys_list = NULL;

static bool cmld_hostedmode = false;
static bool cmld_signed_configs = false;

static bool cmld_device_provisioned = false;

/******************************************************************************/

static int
cmld_start_c0(container_t *new_c0);

/******************************************************************************/

container_t *
cmld_containers_get_c0()
{
	uuid_t *c0_uuid = uuid_new("00000000-0000-0000-0000-000000000000");
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
cmld_container_get_by_token_serial(const char *serial)
{
	IF_NULL_RETVAL_TRACE(serial, NULL);

	TRACE("Looking for container with token serial %s", serial);

	for (list_t *l = cmld_containers_list; l; l = l->next) {
		if (CONTAINER_TOKEN_TYPE_USB != container_get_token_type(l->data))
			continue;

		char *s = container_get_usbtoken_serial(l->data);

		if (s && !strcmp(s, serial))
			return l->data;
	}

	return NULL;
}

container_t *
cmld_container_get_by_devpath(const char *devpath)
{
	ASSERT(devpath);

	TRACE("Looking for container with token devpath %s", devpath);

	for (list_t *l = cmld_containers_list; l; l = l->next) {
		if (CONTAINER_TOKEN_TYPE_USB != container_get_token_type(l->data))
			continue;

		char *p = container_get_usbtoken_devpath(l->data);

		if (p && !strcmp(p, devpath))
			return l->data;
	}

	return NULL;
}

#define UID_MAX 65535
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

static bool
cmld_containers_are_all_stopped(void)
{
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *c = l->data;
		if (container_get_state(c) != CONTAINER_STATE_STOPPED)
			return false;
		else
			continue;
	}
	return true;
}

typedef struct cmld_container_stop_data {
	void (*on_all_stopped)(void);
} cmld_container_stop_data_t;

static void
cmld_container_stop_cb(container_t *container, container_callback_t *cb, void *data)
{
	cmld_container_stop_data_t *stop_data = data;

	ASSERT(container);
	ASSERT(cb);
	ASSERT(stop_data);

	/* skip if the container is not stopped */
	IF_FALSE_RETURN_TRACE(container_get_state(container) == CONTAINER_STATE_STOPPED);

	/* unregister observer */
	container_unregister_observer(container, cb);

	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
			"container-stopped", uuid_string(container_get_uuid(container)), 0);

	/* execute on_all_stopped, if all containers are stopped now */
	if (cmld_containers_are_all_stopped()) {
		INFO("all containers are stopped now, execution of on_all_stopped()");
		stop_data->on_all_stopped();
	}
}

int
cmld_containers_stop(void (*on_all_stopped)(void))
{
	/* execute on_all_stopped, if all containers are stopped now */
	if (cmld_containers_are_all_stopped()) {
		INFO("all containers are stopped now, execution of on_all_stopped()");
		on_all_stopped();
		return 0;
	}

	cmld_container_stop_data_t *stop_data = mem_new0(cmld_container_stop_data_t, 1);
	stop_data->on_all_stopped = on_all_stopped;

	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *container = l->data;
		if (container_get_state(container) != CONTAINER_STATE_STOPPED) {
			container_stop(container);
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
cmld_is_wifi_active(void)
{
	return container_connectivity_wifi(cmld_connectivity);
}

bool
cmld_is_internet_active(void)
{
	return container_connectivity_online(cmld_connectivity);
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

void
cmld_set_device_provisioned(void)
{
	cmld_device_provisioned = true;

	char *provisioned_file = mem_printf("%s/%s", DEFAULT_BASE_PATH, PROVISIONED_FILE_NAME);
	if (!file_exists(provisioned_file)) {
		if (file_touch(provisioned_file) != 0) {
			FATAL("Failed to create provisioned file");
			// TODO does this fulfill the required access rights??
			uid_t uid = getuid();
			if (chown(provisioned_file, uid, uid)) {
				FATAL("Failed to chown provision-status-file to %d", uid);
			}
		}
	}
}

/**
 * Requests the SCD to initialize a token associated to a container and queries whether that
 * token has been provisioned with a platform-bound authentication code.
 */
static int
cmld_container_token_init(container_t *container)
{
	ASSERT(container);

	// container is configured to not use a token at all
	if (CONTAINER_TOKEN_TYPE_NONE == container_get_token_type(container)) {
		container_set_token_is_init(container, false);
		DEBUG("Container %s is configured to use no token to hold encryption keys",
		      uuid_string(container_get_uuid(container)));
		return 0;
	}

	if (smartcard_scd_token_add_block(container) != 0) {
		ERROR("Requesting SCD to init token failed");
		return -1;
	}

	DEBUG("Initialized token for container %s", container_get_name(container));

	smartcard_update_token_state(container);

	return 0;
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
	if (uuid) {
		container_t *c = cmld_container_get_by_uuid(uuid);
		if (c) {
			container_state_t state = container_get_state(c);
			if (state != CONTAINER_STATE_STOPPED) {
				DEBUG("Not loading %s for already created and not stopped container %s.",
				      name, container_get_name(c));
				goto cleanup;
			}
			DEBUG("Removing outdated created container %s for config update",
			      container_get_name(c));
			cmld_containers_list = list_remove(cmld_containers_list, c);
			container_free(c);
		}
		c = container_new(path, uuid, NULL, 0, NULL, 0, NULL, 0);
		if (c) {
			DEBUG("Loaded config for container %s from %s", container_get_name(c),
			      name);
			cmld_container_token_init(c);
			cmld_containers_list = list_append(cmld_containers_list, c);
			res = 1;
			goto cleanup;
		}
	}
	WARN("Could not create new container object from %s", name);

cleanup:
	if (uuid)
		uuid_free(uuid);
	mem_free(dir);
	mem_free(prefix);
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

	mem_free(path);
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
				mem_free(filename_with_old_timestamp);
				mem_free(filename_with_correct_timestamp);
				mem_free(old_filename_with_path);
				mem_free(new_filename_with_path);
			}
		}
		closedir(directory);
	} else
		ERROR("Couldn't open the directory %s", LOGFILE_DIR);
}

/**
 * This function is called every time the state of the wifi connection changes from
 * offline to online and vice versa.
 */
static void
cmld_wifi_change_cb(bool active)
{
	/* TODO insert stuff that depends on wifi */
	if (active) {
		INFO("Global wifi activated");

		INFO("Triggering guestos updates and image downloads");
		guestos_mgr_update_images();
	} else {
		INFO("Global wifi deactivated");
	}
}

/**
 * This function is called every time the state of the mobile connection changes from
 * offline to online and vice versa.
 */
static void
cmld_mobile_change_cb(bool active)
{
	/* TODO insert stuff that depends on mobile */
	if (active) {
		INFO("Global mobile data activated");
		/* setup route over c0 with rild */
		container_t *c0 = cmld_containers_get_c0();
		char *c0_ipaddr = container_get_first_ip_new(c0);
		char *c0_subnet = container_get_first_subnet_new(c0);
		network_setup_route_table(hardware_get_routing_table_radio(), c0_subnet,
					  hardware_get_radio_ifname(), true);
		network_setup_default_route_table(hardware_get_routing_table_radio(), c0_ipaddr,
						  true);
		mem_free(c0_ipaddr);
		mem_free(c0_subnet);
	} else {
		INFO("Global mobile data deactivated");
	}
}

/**
 * This function is called every time the state of the global connection changes from
 * offline to online and vice versa.
 */
static void
cmld_online_change_cb(bool active)
{
	/* connect the MDM dynamically */
	if (active) {
		INFO("Global internet (wifi or mobile) activated");
		if (!control_remote_connecting(cmld_control_mdm)) {
			/* If not already in progress, try to connect MDM */
			INFO("Trying to connect to MDM");
			control_remote_connect(cmld_control_mdm);
		}
	} else {
		INFO("Global internet (wifi or mobile) deactivated");

		INFO("Disconnecting MDM");
		control_remote_disconnect(cmld_control_mdm);
	}
}

static void
cmld_container_boot_complete_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	ASSERT(container);
	ASSERT(cb);

	container_state_t state = container_get_state(container);
	if (state == CONTAINER_STATE_RUNNING) {
		container_oom_protect_service(container);
		// enable ipforwarding when the container in root netns has started
		if (!container_has_netns(container))
			network_enable_ip_forwarding();
		// fixup device nodes in userns by triggering uevent forwarding of coldboot events
		if (container_has_userns(container))
			uevent_udev_trigger_coldboot(container);
		container_unregister_observer(container, cb);

		DEBUG("Freeing key of container %s", container_get_name(container));
		container_free_key(container);

		/* Make KSM aggressive to immmediately share as many pages as
		 * possible */
		ksm_set_aggressive_for(CMLD_KSM_AGGRESSIVE_TIME_AFTER_CONTAINER_BOOT);
	}
}

static void
cmld_connectivity_rootns_cb(container_t *c_root_netns, UNUSED container_callback_t *cb,
			    UNUSED void *data)
{
	container_connectivity_t conn = container_get_connectivity(c_root_netns);

	if ((container_get_state(c_root_netns) == CONTAINER_STATE_STOPPED) ||
	    (container_get_state(c_root_netns) == CONTAINER_STATE_REBOOTING)) {
		DEBUG("Container %s stopped/rebooting, unregistering connectivity c_root_netns callback",
		      container_get_description(c_root_netns));
		container_unregister_observer(c_root_netns, cb);
	}

	/* check if anything has changed and return if not */
	if (cmld_connectivity == conn)
		return;

	container_connectivity_t old_conn = cmld_connectivity;
	cmld_connectivity = conn;

	DEBUG("Global connectivity changed from %d to %d", old_conn, cmld_connectivity);

	/* detect changes in connection state and call the respective callbacks */
	if (container_connectivity_wifi(cmld_connectivity) !=
	    container_connectivity_wifi(old_conn)) {
		/* wifi connectivity has changed */
		cmld_wifi_change_cb(container_connectivity_wifi(cmld_connectivity));
	}
	if (container_connectivity_mobile(cmld_connectivity) !=
	    container_connectivity_mobile(old_conn)) {
		/* mobile connectivity has changed */
		cmld_mobile_change_cb(container_connectivity_mobile(cmld_connectivity));
	}
	if (container_connectivity_online(cmld_connectivity) !=
	    container_connectivity_online(old_conn)) {
		/* internet connectivity has changed */
		cmld_online_change_cb(container_connectivity_online(cmld_connectivity));
	}

	///* set the connectivity in aX containers to the global state */
	//for (list_t *l = cmld_containers_list; l; l = l->next) {
	//	container_t *container = l->data;
	//	if (container != c_root_netns) {
	//		container_set_connectivity(container, conn);
	//	}
	//}
}

//static void
//cmld_connectivity_aX_cb(container_t *aX, container_callback_t *cb, UNUSED void *data)
//{
//	if (container_get_state(aX) == CONTAINER_STATE_STOPPED) {
//		DEBUG("Container %s stopped, unregistering connectivity aX callback",
//				container_get_description(aX));
//		container_unregister_observer(aX, cb);
//	}
//
//	if (cmld_connectivity == container_get_connectivity(aX))
//		return;
//
//	DEBUG("Setting global connectivity %d in container %s", cmld_connectivity, container_get_description(aX));
//
//	container_set_connectivity(aX, cmld_connectivity);
//}

static void
cmld_init_control_cb(container_t *container, container_callback_t *cb, void *data)
{
	int *control_sock_p = data;

	container_state_t state = container_get_state(container);
	/* Check if the container got over the initial starting phase */
	if (state == CONTAINER_STATE_BOOTING || state == CONTAINER_STATE_RUNNING) {
		/* Initialize unpriv control interface on the socket previously bound into container */
		if (!control_new(*control_sock_p, false)) {
			WARN("Could not create unpriv control socket for %s",
			     container_get_description(container));
		} else {
			INFO("Create unpriv control socket for %s",
			     container_get_description(container));
		}
		mem_free(control_sock_p);
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
	if (container_get_state(container) == CONTAINER_STATE_REBOOTING) {
		INFO("Rebooting container %s", container_get_description(container));
		container_set_key(container, DUMMY_KEY); // set dummy key for reboot
		if (cmld_container_start(container))
			WARN("Reboot of '%s' failed", container_get_description(container));
		container_unregister_observer(container, cb);
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
	// first container without netns 'c_root_netns' is responsible for global cannectivity
	if (container == cmld_container_get_c_root_netns()) {
		INFO("Container %s is sharing root network namespace, connect global connectivity observers!",
		     container_get_description(container));

		if (!container_register_observer(container, &cmld_connectivity_rootns_cb, NULL)) {
			ERROR("Could not register connectivity observer callback for %s",
			      container_get_description(container));
		}
	}

	if (guestos_get_feature_install_guest(container_get_os(container))) {
		INFO("GuestOS allows to install new Guests => mapping control socket");
		int *control_sock_p = mem_new0(int, 1);
		*control_sock_p =
			container_bind_socket_before_start(container, CMLD_CONTROL_SOCKET);

		if (!container_register_observer(container, &cmld_init_control_cb,
						 control_sock_p)) {
			WARN("Could not register observer init control callback for %s",
			     container_get_description(container));
		}
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

	if ((container_get_state(container) == CONTAINER_STATE_STOPPED) ||
	    (container_get_state(container) == CONTAINER_STATE_REBOOTING)) {
		/* container is not running => start it */
		DEBUG("Container %s is not running => start it",
		      container_get_description(container));

		cmld_container_register_observers(container);

		// We only support "background-start"...
		if (!guestos_get_feature_bg_booting(container_get_guestos(container))) {
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"container-start",
					uuid_string(container_get_uuid(container)), 0);
			WARN("Guest OS of the container %s does not support background booting",
			     container_get_description(container));
			return -1;
		}
		if (container_start(container)) {
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"container-start",
					uuid_string(container_get_uuid(container)), 0);
			WARN("Start of background container %s failed",
			     container_get_description(container));
			return -1;
		}
		time_register_clock_check();
	} else {
		audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
				"container-start-already-running",
				uuid_string(container_get_uuid(container)), 0);
		DEBUG("Container %s has been already started",
		      container_get_description(container));
	}

	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT, "container-start",
			uuid_string(container_get_uuid(container)), 0);
	return 0;
}

int
cmld_container_change_pin(control_t *control, container_t *container, const char *passwd,
			  const char *newpasswd)
{
	ASSERT(container);
	ASSERT(control);
	ASSERT(passwd);
	ASSERT(newpasswd);

	int rc = smartcard_container_change_pin(cmld_smartcard, control, container, passwd,
						newpasswd);

	if (!rc)
		audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
				"container-change-pin", uuid_string(container_get_uuid(container)),
				0);
	else
		audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
				"container-change-pin", uuid_string(container_get_uuid(container)),
				0);

	return rc;
}

int
cmld_container_ctrl_with_smartcard(control_t *control, container_t *container, const char *passwd,
				   cmld_container_ctrl_t container_ctrl)
{
	ASSERT(container);
	ASSERT(control);
	ASSERT(passwd);

	return smartcard_container_ctrl_handler(cmld_smartcard, control, container, passwd,
						container_ctrl);
}

void
cmld_push_device_cert(control_t *control, uint8_t *cert, size_t cert_len)
{
	smartcard_push_cert(cmld_smartcard, control, cert, cert_len);
}

int
cmld_get_control_gui_sock(void)
{
	return control_get_client_sock(cmld_control_gui);
}

/******************************************************************************/

static void
cmld_init_c0_cb(container_t *container, container_callback_t *cb, void *data)
{
	int *control_sock_p = data;

	container_state_t state = container_get_state(container);
	/* Check if the container got over the initial starting phase */
	if (state == CONTAINER_STATE_BOOTING || state == CONTAINER_STATE_RUNNING) {
		/* Initialize control interface on the socket previously bound into c0 */
		cmld_control_gui = control_new(*control_sock_p, true);
		mem_free(control_sock_p);
		container_unregister_observer(container, cb);
	}
	// TODO think about if this is unregistered correctly in corner cases...
}

static void
cmld_c0_boot_complete_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	container_state_t state = container_get_state(container);
	if (state == CONTAINER_STATE_RUNNING) {
		DEBUG("c0 booted successfully!");
		container_oom_protect_service(container);
		cmld_rename_logfiles();
		// fixup device nodes in userns by triggering uevent forwarding of coldboot events
		if (container_has_userns(container))
			uevent_udev_trigger_coldboot(container);
		container_unregister_observer(container, cb);

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

/**
 * This observer callback is attached to each container in order to check for other running containers.
 * It ensures that as soon as the last container went down, the device is shut down.
 */
static void
cmld_shutdown_container_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	container_state_t state = container_get_state(container);

	if (!(state == CONTAINER_STATE_STOPPED || state == CONTAINER_STATE_ZOMBIE)) {
		return;
	}

	container_unregister_observer(container, cb);

	DEBUG("Device shutdown: container %s went down, checking others before shutdown",
	      container_get_description(container));

	for (list_t *l = cmld_containers_list; l; l = l->next) {
		if (!(container_get_state(l->data) == CONTAINER_STATE_STOPPED ||
		      container_get_state(l->data) == CONTAINER_STATE_ZOMBIE)) {
			DEBUG("Device shutdown: There are still running containers, can't shut down");
			return;
		}
	}

	IF_TRUE_RETURN_TRACE(cmld_hostedmode);

	/* all containers are down, so shut down */
	DEBUG("Device shutdown: last container down; shutdown now");

	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT, "shutdown",
			uuid_string(container_get_uuid(container)), 0);

#ifndef TRUSTME_DEBUG
	reboot_reboot(POWER_OFF);
	// should never arrive here, but in case the shutdown fails somehow, we exit
	exit(0);
#endif /* TRUSTME_DEBUG */
}

/**
 * This callback for c0 is used when c0 gets the shutdown command in order to
 * trigger the graceful shutdown of the other running containers
 */
static void
cmld_shutdown_c0_cb(container_t *c0, container_callback_t *cb, UNUSED void *data)
{
	container_state_t c0_state = container_get_state(c0);
	bool shutdown_now = true;

	/* only execute the callback if c0 goes down */
	if (!(c0_state == CONTAINER_STATE_SHUTTING_DOWN || c0_state == CONTAINER_STATE_STOPPED ||
	      c0_state == CONTAINER_STATE_ZOMBIE)) {
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
		if (!(container_get_state(l->data) == CONTAINER_STATE_STOPPED ||
		      container_get_state(l->data) == CONTAINER_STATE_ZOMBIE)) {
			shutdown_now = false;
			if (!container_register_observer(l->data, &cmld_shutdown_container_cb,
							 NULL)) {
				ERROR("Could not register observer shutdown callback for %s",
				      container_get_description(l->data));
			}
			if (l->data != c0 &&
			    !(container_get_state(l->data) == CONTAINER_STATE_SHUTTING_DOWN)) {
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
#ifndef TRUSTME_DEBUG
		reboot_reboot(POWER_OFF);
		// should never arrive here, but in case the shutdown fails somehow, we exit
		exit(0);
#endif /* TRUSTME_DEBUG */
	}
}

/*
 * This callback handles internal reboot of c0
 */
static void
cmld_reboot_c0_cb(container_t *c0, container_callback_t *cb, UNUSED void *data)
{
	if (container_get_state(c0) == CONTAINER_STATE_REBOOTING) {
		INFO("Rebooting container %s", container_get_description(c0));
		if (cmld_start_c0(c0))
			WARN("Reboot of '%s' failed", container_get_description(c0));
		container_unregister_observer(c0, cb);
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
	mount_t *c0_mnt = mount_new();
	guestos_fill_mount(c0_os, c0_mnt);
	unsigned int c0_ram_limit = 1024;
	bool c0_ns_net = true;
	bool privileged = true;

	container_t *new_c0 =
		container_new_internal(c0_uuid, "c0", CONTAINER_TYPE_CONTAINER, false, c0_ns_net,
				       privileged, c0_os, NULL, c0_images_folder, c0_mnt,
				       c0_ram_limit, NULL, 0xffffff00, false, NULL,
				       cmld_get_device_host_dns(), NULL, NULL, NULL, NULL, NULL,
				       NULL, 0, NULL, CONTAINER_TOKEN_TYPE_NONE, false);

	/* store c0 as first element of the cmld_containers_list */
	cmld_containers_list = list_prepend(cmld_containers_list, new_c0);

	mem_free(c0_images_folder);

out:
	uuid_free(c0_uuid);
	mem_free(c0_config_file);

	return 0;
}

static int
cmld_start_c0(container_t *new_c0)
{
	IF_TRUE_RETVAL_TRACE(cmld_hostedmode, 0);

	INFO("Starting management container %s...", container_get_description(new_c0));

	int *control_sock_p = mem_new0(int, 1);
	*control_sock_p = container_bind_socket_before_start(new_c0, CMLD_CONTROL_SOCKET);

	if (!container_register_observer(new_c0, &cmld_init_c0_cb, control_sock_p)) {
		WARN("Could not register observer init callback on c0");
		return -1;
	}
	if (!container_register_observer(new_c0, &cmld_c0_boot_complete_cb, NULL)) {
		WARN("Could not register observer boot complete callback on c0");
		return -1;
	}

	container_set_key(new_c0, DUMMY_KEY);
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

	audit_log_event(container_get_uuid(new_c0), SSA, CMLD, CONTAINER_MGMT, "c0-start",
			uuid_string(container_get_uuid(new_c0)), 0);
	return 0;
}

static void
cmld_tune_network(const char *host_addr, uint32_t host_subnet, const char *host_if,
		  const char *host_gateway, const char *host_dns)
{
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

	cmld_netif_phys_list = network_get_physical_interfaces_new();

	/* configure resolver of root network namespace */
	if (-1 == file_printf("/etc/resolv.conf", "nameserver %s", host_dns))
		WARN("Could not setup dns server for CML");

	DEBUG("Trying to configure eth0");
	//network_set_ip_addr_of_interface("10.0.2.15", 24, "eth0");
	network_set_ip_addr_of_interface(host_addr, host_subnet, host_if);
	network_setup_default_route(host_gateway, true);
	network_enable_ip_forwarding();
}

int
cmld_init(const char *path)
{
	INFO("Storage path is %s", path);
	cmld_path = path;

	if (mount_private_tmp())
		FATAL("Could not setup private tmp!");

	/* Currently the given path is used by the config module to generate the
	 * paths and it must therefore be ensured that it exists before loading
	 * the config file. */
	if (mkdir(path, 0755) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir base path %s", path);

	char *users_path = mem_printf("%s/%s", path, CMLD_PATH_USERS_DIR);
	if (mkdir(users_path, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir users directory %s", users_path);
	mem_free(users_path);

	const char *device_path = DEFAULT_CONF_BASE_PATH "/" CMLD_PATH_DEVICE_CONF;
	device_config_t *device_config = device_config_new(device_path);

	// set hostedmode, which disables some configuration
	cmld_hostedmode = device_config_get_hostedmode(device_config);

	// activate signature checking of container configs if enabled
	cmld_signed_configs = device_config_get_signed_configs(device_config);

	cmld_tune_network(device_config_get_host_addr(device_config),
			  device_config_get_host_subnet(device_config),
			  device_config_get_host_if(device_config),
			  device_config_get_host_gateway(device_config),
			  device_config_get_host_dns(device_config));

	cmld_shared_data_dir = mem_printf("%s/%s", path, CMLD_PATH_SHARED_DATA_DIR);
	if (mkdir(cmld_shared_data_dir, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir shared data directory %s", cmld_shared_data_dir);

	// Store uuid from device config. TODO: free?
	cmld_device_uuid = mem_strdup(device_config_get_uuid(device_config));

	const char *update_base_url = device_config_get_update_base_url(device_config);
	cmld_device_update_base_url = update_base_url ? mem_strdup(update_base_url) : NULL;

	const char *host_dns = device_config_get_host_dns(device_config);
	cmld_device_host_dns = host_dns ? mem_strdup(host_dns) : NULL;

	const char *c0os_name = device_config_get_c0os(device_config);
	cmld_c0os_name = c0os_name ? mem_strdup(c0os_name) : NULL;

	if (mount_remount_root_ro() < 0 && !cmld_hostedmode)
		FATAL("Could not remount rootfs read-only");

	if (mount_debugfs() < 0)
		WARN("Could not mount debugfs (already mounted?)");
	else
		INFO("mounted debugfs");

	// init audit and set max audit log file size
	if (audit_init(device_config_get_audit_size(device_config)) < 0)
		WARN("Could not init audit module");
	else
		INFO("audit initialized.");

	if (time_init() < 0)
		FATAL("Could not init time module");
	INFO("time initialized.");

	char *btime = mem_printf("%ld", time_cml(NULL));
	audit_log_event(NULL, SSA, CMLD, GENERIC, "boot-time", NULL, 2, "time", btime);
	mem_free(btime);

	if (uevent_init() < 0)
		FATAL("Could not init uevent module");
	INFO("uevent initialized.");

	if (ksm_init() < 0)
		WARN("Could not init ksm module");
	else
		INFO("ksm initialized.");

	if (device_config_get_tpm_enabled(device_config)) {
		if (tss_init() < 0)
			FATAL("Failed to initialize TSS / TPM 2.0 and tpm2d");
		else
			INFO("tss initialized.");
	}

	if (lxcfs_init() < 0)
		WARN("Plattform does not support LXCFS");
	else
		INFO("lxcfs initialized.");

	// Read the provision-status-file to set provisioned flag of control structs accordingly
	char *provisioned_file = mem_printf("%s/%s", DEFAULT_BASE_PATH, PROVISIONED_FILE_NAME);
	if (file_exists(provisioned_file)) {
		DEBUG("Device is already provisioned");
		cmld_device_provisioned = true;
	} else {
		DEBUG("Device is not yet provisioned and provision-status-file does not yet exist");
	}

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

	// TODO: we should implement a callback for inet connectivity and
	// reconnect the MDM socket automatically
	const char *mdm_node = device_config_get_mdm_node(device_config);
	const char *mdm_service = device_config_get_mdm_service(device_config);
	INFO("got MDM node and service %s and %s.", mdm_node, mdm_service);
	if (mdm_node && mdm_service) {
		cmld_control_mdm = control_remote_new(mdm_node, mdm_service);
		if (!cmld_control_mdm) {
			WARN_ERRNO("Could not init MDM control socket");
		}
	} else {
		WARN("Could not get a valid MDM configuration from config file");
	}

	char *tokens_path = mem_printf("%s/%s", path, CMLD_PATH_CONTAINER_KEYS_DIR);
	cmld_smartcard = smartcard_new(tokens_path);
	mem_free(tokens_path);

	char *guestos_path = mem_printf("%s/%s", path, CMLD_PATH_GUESTOS_DIR);
	bool allow_locally_signed = device_config_get_locally_signed_images(device_config);
	if (guestos_mgr_init(guestos_path, allow_locally_signed) < 0 && !cmld_hostedmode)
		FATAL("Could not load guest operating systems");
	mem_free(guestos_path);
	INFO("guestos initialized.");
	guestos_mgr_update_images();

	char *containers_path = mem_printf("%s/%s", path, CMLD_PATH_CONTAINERS_DIR);
	if (mkdir(containers_path, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir containers directory %s", containers_path);

	char *keys_path = mem_printf("%s/%s", path, CMLD_PATH_CONTAINER_KEYS_DIR);
	if (mkdir(containers_path, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir container keys directory %s", containers_path);
	mem_free(keys_path);

	if (cmld_smartcard == NULL)
		FATAL("Could not connect to smartcard daemon");
	else
		INFO("Connected to smartcard daemon");

	if (cmld_init_c0(containers_path, device_config_get_c0os(device_config)) < 0)
		FATAL("Could not init c0");

	if (cmld_load_containers(containers_path) < 0)
		FATAL("Could not load containers");

	if (cmld_start_c0(cmld_containers_get_c0()) < 0)
		FATAL("Could not start c0");

	mem_free(containers_path);

	device_config_free(device_config);
	return 0;
}

container_t *
cmld_container_create_clone(container_t *container)
{
	ASSERT(container);
	ASSERT(0); // TODO
	return NULL;
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
		container_new(path, NULL, config, config_len, sig, sig_len, cert, cert_len);
	if (c) {
		if (0 != cmld_container_token_init(c)) {
			audit_log_event(container_get_uuid(c), FSA, CMLD, CONTAINER_MGMT,
					"container-create-token-uninit",
					uuid_string(container_get_uuid(c)), 0);
			ERROR("Could not initialize token associated with container %s (uuid=%s). Aborting creation",
			      container_get_name(c), uuid_string(container_get_uuid(c)));
			cmld_container_destroy(c);
			c = NULL;
		} else {
			cmld_containers_list = list_append(cmld_containers_list, c);
			audit_log_event(container_get_uuid(c), SSA, CMLD, CONTAINER_MGMT,
					"container-create", uuid_string(container_get_uuid(c)), 0);
			INFO("Created container %s (uuid=%s).", container_get_name(c),
			     uuid_string(container_get_uuid(c)));
		}
	} else {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_MGMT, "container-create", NULL, 0);
		WARN("Could not create new container object from config");
	}
	mem_free(path);
	return c;
}

static void
cmld_container_destroy_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	ASSERT(container);

	/* skip if the container is not stopped */
	IF_FALSE_RETURN_TRACE(container_get_state(container) == CONTAINER_STATE_STOPPED);

	/* unregister observer */
	if (cb)
		container_unregister_observer(container, cb);

	if (container_get_token_is_init(container)) {
		smartcard_scd_token_remove_block(container);
	}

	/* remove keyfile */
	if (0 != smartcard_remove_keyfile(cmld_smartcard, container)) {
		ERROR("Failed to remove keyfile. Continuing to remove container anyway.");
		audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
				"container-remove-keyfile",
				uuid_string(container_get_uuid(container)), 0);
	} else {
		audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
				"container-remove-keyfile",
				uuid_string(container_get_uuid(container)), 0);
	}

	/* destroy the container */
	if (container_destroy(container) < 0) {
		audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
				"container-remove", uuid_string(container_get_uuid(container)), 0);
		ERROR("Could not destroy container");
		container_set_state(container, CONTAINER_STATE_ZOMBIE);
		return;
	}

	/* cleanup container */
	cmld_containers_list = list_remove(cmld_containers_list, container);
	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
			"container-remove", uuid_string(container_get_uuid(container)), 0);
	container_free(container);
}

int
cmld_container_destroy(container_t *container)
{
	ASSERT(container);

	// don't delete management container c0!
	container_t *c0 = cmld_containers_get_c0();
	IF_TRUE_RETVAL(c0 == container, -1);

	if (container_get_state(container) != CONTAINER_STATE_STOPPED) {
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

	if (!((container_get_state(container) == CONTAINER_STATE_RUNNING) ||
	      (container_get_state(container) == CONTAINER_STATE_SETUP))) {
		ERROR("Container %s not running, unable to stop",
		      container_get_description(container));

		audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
				"container-stop-failed", uuid_string(container_get_uuid(container)),
				0);
		return -1;
	}

	return container_stop(container);
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
	ASSERT(0);
	return 0;
}

int
cmld_container_wipe(container_t *container)
{
	ASSERT(container);

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

void
cmld_guestos_delete(const char *guestos_name)
{
	guestos_t *os = guestos_mgr_get_latest_by_name(guestos_name, false);
	IF_NULL_RETURN(os);

	// do not delete gustos of managment container c0
	container_t *c0 = cmld_containers_get_c0();
	IF_TRUE_RETURN(os == container_get_guestos(c0));

	guestos_mgr_delete(os);
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
			mem_free(cmld_if_name);
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
	INFO("Adding '%s' to global available physical netifs", if_name);

	for (list_t *l = cmld_netif_phys_list; l; l = l->next) {
		char *cmld_if_name = l->data;
		if (0 == strcmp(if_name, cmld_if_name)) {
			return;
		}
	}
	cmld_netif_phys_list = list_append(cmld_netif_phys_list, mem_strdup(if_name));
}

#define PROC_FSES "/proc/filesystems"
bool
cmld_is_shiftfs_supported(void)
{
	char *fses = file_read_new(PROC_FSES, 2048);
	bool ret = strstr(fses, "shiftfs") ? true : false;
	mem_free(fses);
	return ret;
}

int
cmld_token_attach(const char *serial, char *devpath)
{
	IF_NULL_RETVAL_TRACE(serial, -1);
	IF_NULL_RETVAL_TRACE(devpath, -1);

	container_t *container = cmld_container_get_by_token_serial(serial);

	IF_NULL_RETVAL_TRACE(container, -1);

	TRACE("Handling attachment of token with serial %s at %s", serial, devpath);

	container_set_usbtoken_devpath(container, mem_strdup(devpath));

	// initialize the USB token
	int block_return = cmld_container_token_init(container);

	if (block_return) {
		DEBUG("Failed to initialize token, already initialized?");
	}

	return 0;
}

int
cmld_token_detach(char *devpath)
{
	IF_NULL_RETVAL_TRACE(devpath, -1);

	container_t *container = cmld_container_get_by_devpath(devpath);

	IF_NULL_RETVAL_TRACE(container, -1);

	DEBUG("Handling detachment of token at %s", devpath);

	container_set_usbtoken_devpath(container, NULL);

	DEBUG("Stopping Container");
	if (cmld_container_stop(container)) {
		ERROR("Could not stop container after token detachment.");
	}

	if (smartcard_scd_token_remove_block(container)) {
		ERROR("Failed to notify scd about token detachment");
	}

	return 0;
}

void
cmld_cleanup(void)
{
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *container = l->data;
		container_free(container);
	}
	list_delete(cmld_containers_list);

	if (cmld_control_mdm)
		control_free(cmld_control_mdm);
	if (cmld_control_gui)
		control_free(cmld_control_gui);
	if (cmld_control_cml)
		control_free(cmld_control_cml);

	if (cmld_smartcard)
		smartcard_free(cmld_smartcard);

	mem_free(cmld_device_uuid);
	mem_free(cmld_device_update_base_url);
	mem_free(cmld_device_host_dns);
	mem_free(cmld_c0os_name);
	mem_free(cmld_shared_data_dir);

	for (list_t *l = cmld_netif_phys_list; l; l = l->next) {
		char *name = l->data;
		mem_free(name);
	}
	list_delete(cmld_netif_phys_list);
}
