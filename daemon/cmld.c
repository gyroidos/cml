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

// uncomment to prevent reboot
//#define TRUSTME_DEBUG

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
#include "display.h"
#include "hardware.h"
#include "mount.h"
#include "power.h"
#include "device_config.h"
#include "control.h"
#include "input.h"
#include "guestos_mgr.h"
#include "guestos.h"
#include "smartcard.h"
#include "ksm.h"

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include <cutils/properties.h>
#include <cutils/android_reboot.h>

#define CMLD_CONTROL_SOCKET SOCK_PATH(control)

#define CMLD_SUSPEND_TIMEOUT 5000

// files and directories in cmld's home path /data/cml
#define CMLD_PATH_DEVICE_CONF		"device.conf"
#define CMLD_PATH_USERS_DIR		"users"
#define CMLD_PATH_GUESTOS_DIR		"operatingsystems"
#define CMLD_PATH_CONTAINERS_DIR	"containers"
#define CMLD_PATH_CONTAINER_KEYS_DIR    "keys"
#define CMLD_PATH_CONTAINER_TOKENS_DIR    "tokens"
#define CMLD_PATH_SHARED_DATA_DIR	"shared"

#define CMLD_WAKE_LOCK_STARTUP           "ContainerStartup"

#define CMLD_KSM_AGGRESSIVE_TIME_AFTER_CONTAINER_BOOT 70000

#define LOGFILE_DIR "/data/logs"

// TODO think about using an own variable for a0
//static container_t *cmld_a0 = NULL;
static const char* cmld_path = "/data/cml";

static list_t *cmld_containers_list = NULL; // first element is a0

static control_t *cmld_control_mdm = NULL;
static control_t *cmld_control_gui = NULL;
static control_t *cmld_control_cml = NULL;

static smartcard_t *cmld_smartcard = NULL;

static container_callback_t *cmld_foreground_observer = NULL;

static container_connectivity_t cmld_connectivity = CONTAINER_CONNECTIVITY_OFFLINE;
static bool cmld_airplane_mode = false;

static bool cmld_switching_enabled = true;

static bool cmld_display_on = true;

/* If there is a container waiting to be resumed it will be stored in
 * this variable. It makes sense to make this global, since there is
 * always only exactly ONE container to be resumed next */
static container_t *cmld_container_to_resume = NULL;

struct cmld_switch_state {
	container_t *container; /**< The container running before */
	event_timer_t *timer;
	display_sleep_t *display_sleep;
	bool timed_out;
	bool display_suspended;
};

static struct cmld_switch_state *cmld_switch_state = NULL;

static char *cmld_device_uuid = NULL;
static char *cmld_device_update_base_url = NULL;
static char *cmld_device_host_dns = NULL;

static int cmld_should_led_blink = 0;

static char *cmld_shared_data_dir = NULL;

static void
cmld_display_sleep_cb(UNUSED void *data);

/******************************************************************************/

container_t *
cmld_containers_get_a0()
{
	//return a0;
	return list_nth_data(cmld_containers_list, 0);
}

const char *
cmld_container_get_telephony_name()
{
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *container = l->data;
		if (container_is_feature_enabled(container, "telephony"))
			return container_get_name(container);
	}
	return NULL;
}

container_t *
cmld_container_get_c_root_netns()
{
	container_t *found = NULL;
	container_t *found_a0 = NULL;

	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *container = l->data;
		if (!container_has_netns(container)) {
			if (container == cmld_containers_get_a0()) {
				found_a0 = container;
			} else {
				// first container without netns which is not a0
				found = container;
				break;
			}
		}
	}
	return ((found)? found : found_a0);
}

container_t *
cmld_container_get_by_uuid(uuid_t *uuid)
{
	ASSERT(uuid);

	for (list_t *l = cmld_containers_list; l; l = l->next)
		if (uuid_equals(container_get_uuid(l->data), uuid))
			return l->data;

	return NULL;
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

static int
cmld_load_containers_cb(const char *path, const char *name, UNUSED void *data)
{
	/* we should check for config files here, because the images
	 * might not be synced to the device from the mdm, but the config files
	 * should be always there
	 */
	size_t len = strlen(name);
	if (len < 5 || strcmp(name + len - 5, ".conf"))
		return 0;

	char *prefix = mem_strdup(name);
	prefix[len-5] = '\0';

	int res = 0;
	char *dir = mem_printf("%s/%s", path, prefix);

	if (file_exists(dir) && !file_is_dir(dir)) {
		WARN("%s exists but is not a directory!", dir);
		goto cleanup;
	}

	uuid_t *uuid = uuid_new(prefix);
	if (uuid) {
		container_t *c = container_new(path, uuid, NULL, 0);
		mem_free(uuid);
		if (c) {
			DEBUG("Loaded existing container %s from %s", container_get_name(c), name);
			cmld_containers_list = list_append(cmld_containers_list, c);
			res = 1;
			goto cleanup;
		}
	}
	WARN("Could not create new container object from %s", name);

cleanup:
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

container_t *
cmld_containers_get_foreground(void)
{
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		if (container_is_active(l->data)) {
			return l->data;
		}
	}

	return NULL;
}

static void
cmld_containers_disable_switching()
{
	if (cmld_switching_enabled) {
		DEBUG("Container switching disabled");
		cmld_switching_enabled = false;
		// Do not allow system going to deep sleep while starting the container
		hardware_suspend_block(CMLD_WAKE_LOCK_STARTUP, sizeof(CMLD_WAKE_LOCK_STARTUP));
	}
}

static void
cmld_containers_disable_switching_and_pb()
{
	cmld_containers_disable_switching();
	input_pb_injecting_disable();
}

static void
cmld_containers_enable_switching()
{
	if (!cmld_switching_enabled) {
		DEBUG("Container switching enabled");
		hardware_suspend_unblock(CMLD_WAKE_LOCK_STARTUP, sizeof(CMLD_WAKE_LOCK_STARTUP));
		cmld_switching_enabled = true;
	}
}

static void
cmld_containers_enable_switching_and_pb()
{
	cmld_containers_enable_switching();
	input_pb_injecting_enable();
}

static container_t *container_with_active_call = NULL;

/**
 * Checks if a filename in the /data/logs directory contains
 * "1970" and renames the found files with a new timestamp
 */
void
cmld_rename_logfiles() {

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
				char *filename_with_correct_timestamp = logf_file_new_name(filename);
				char *old_filename_with_path = mem_printf("%s/%s", LOGFILE_DIR, entry->d_name);
				char *new_filename_with_path = mem_printf("%s/%s", LOGFILE_DIR, filename_with_correct_timestamp);
				if (rename(old_filename_with_path, new_filename_with_path))
					ERROR_ERRNO("Rename not successful %s -> %s", old_filename_with_path, new_filename_with_path);
				else
					DEBUG("Rename successful %s -> %s", old_filename_with_path, new_filename_with_path);
				mem_free(filename_with_old_timestamp);
				mem_free(filename_with_correct_timestamp);
				mem_free(old_filename_with_path);
				mem_free(new_filename_with_path);
			}
		}
		closedir(directory);
	}
	else
		ERROR("Couldn't open the directory %s", LOGFILE_DIR);

}

static void
cmld_foreground_observer_cb(container_t *container, UNUSED container_callback_t *cb, UNUSED void *data)
{
	DEBUG("Foreground observer callback called");

	/* display turned on? */
	if (container_is_screen_on(container) && !cmld_display_on) {
		/* if the LED debugging is not active we want to switch off the LED if
		 * the foreground container turns of the display */
		if (!cmld_should_led_blink && !hardware_is_led_on()) {
			DEBUG("Setting LED to color: %08x", container_get_color(container));
			hardware_set_led(container_get_color(container), true);
		}
		cmld_display_on = true;
	/* display turned off? */
	} else if (!container_is_screen_on(container) && cmld_display_on) {
		if (!cmld_should_led_blink && hardware_is_led_on()) {
			DEBUG("Disabling LED");
			hardware_set_led(0, true);
		}
		cmld_display_on = false;
	}

	if (container_get_state(container) == CONTAINER_STATE_BOOTING
			&& cmld_containers_get_foreground() != container) {
		DEBUG("Container now booting, switching it in foreground.");
		if (container_set_active(container) < 0)
			WARN("Set active failed for container %s", container_get_description(container));
	} else if (container_get_state(container) == CONTAINER_STATE_STOPPED
			&& cmld_containers_get_a0() != container) {
		DEBUG("Foreground container stopped, trying to switch back to a0");
		/* Make sure switching is enabled; this is important if the container is stopped without ever
		 * reaching the RUNNING state */
		cmld_containers_enable_switching_and_pb();
		if (cmld_container_switch_to_a0() < 0)
			WARN("Could not switch to a0");
	} else if (container_get_state(container) == CONTAINER_STATE_RUNNING
			&& !cmld_switching_enabled && !container_with_active_call) {
		DEBUG("Container booted up successfully, re-enabling switching");
		cmld_containers_enable_switching_and_pb();

		/* Make KSM aggressive to immmediately share as many pages as
		 * possible */
		ksm_set_aggressive_for(CMLD_KSM_AGGRESSIVE_TIME_AFTER_CONTAINER_BOOT);
	}
}

static void
cmld_container_notification_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	DEBUG("Calling container notification callback");

	container_t *fg = cmld_containers_get_foreground();

	if (container_has_base_notification(container)
	    && container_allows_notification(container, container == fg,
					     container_get_name(container))) {
		INFO("Container %s allowed to send base notification",
		     container_get_name(container));
		container_send_notification_from_cmld(container);
	}

	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *target = l->data;
		if (target != container && container_get_state(target) == CONTAINER_STATE_RUNNING) {
			//TODO this conditions should not be determined by
			//the container name which is not unique
			if (container_allows_notification(container, container == fg, container_get_name(target))) {
				INFO("Container %s allowed to send notification"
				     " to %s", container_get_name(container),
				     container_get_name(target));
				container_send_notification_to_target(container, target);
			}
		}
	}
	container_cleanup_notification(container);

	if (container_get_state(container) == CONTAINER_STATE_STOPPED) {
		DEBUG("Container %s stopped, unregistering event callback",
				container_get_description(container));
		container_unregister_observer(container, cb);
	}
}

static void
cmld_container_switch_to_container_cb(container_t *container, UNUSED container_callback_t *cb, UNUSED void *data)
{
	uuid_t *target = container_get_switch_to_container(container);
	if (target) {
		DEBUG("Request from container %s to switch to %s, switching...", container_get_description(container), uuid_string(target));
		if (cmld_container_switch(cmld_container_get_by_uuid(target)) < 0)
			ERROR("Could not switch to %s as requested by container %s", uuid_string(target), container_get_description(container));
		container_set_switch_to_container(container, NULL);
	}
}

static void
cmld_container_call_active_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	static container_t *container_switched_from = NULL;

	if (container_get_state(container) == CONTAINER_STATE_STOPPED) {
		DEBUG("Container %s stopped, unregistering call_active callback",
				container_get_description(container));
		container_unregister_observer(container, cb);
	}

	if (container_is_call_active(container)) {
		// TODO security check: uuid_equals(container_get_uuid(container), DeviceConfig.telephony_uuid)
		container_t *fg = cmld_containers_get_foreground();
		if (container != fg) {
			DEBUG("Active call in container %s, trying to switch to it", container_get_description(container));
			if (cmld_container_switch(container) < 0) {
				ERROR("Couldn't switch to container %s", container_get_description(container));
				return;
			}
			container_switched_from = fg;
		}
		container_with_active_call = container;
		cmld_containers_disable_switching();
	}
	else if (container_with_active_call == container) {
		cmld_containers_enable_switching();
		DEBUG("Call ended");
		if (container_switched_from) {
			DEBUG("Switching back to container %s", container_get_description(container_switched_from));
			if (cmld_container_switch(container_switched_from) < 0) {
				ERROR("Couldn't switch to container %s", container_get_description(container));
				// We don't return here in order to reenable switching.
			}
			container_switched_from = NULL;
		}
		container_with_active_call = NULL;
	}
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
		/* setup route over a0 with rild */
		container_t *a0 = cmld_containers_get_a0();
		char* a0_ipaddr = container_get_first_ip_new(a0);
		char* a0_subnet = container_get_first_subnet_new(a0);
		network_setup_route_table(hardware_get_routing_table_radio(),
				a0_subnet, hardware_get_radio_ifname(), true);
		network_setup_default_route_table(hardware_get_routing_table_radio(),
				a0_ipaddr, true);
		mem_free(a0_ipaddr);
		mem_free(a0_subnet);
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
		container_unregister_observer(container, cb);
	}
}

static void
cmld_connectivity_rootns_cb(container_t *c_root_netns, UNUSED container_callback_t *cb, UNUSED void *data)
{
	container_connectivity_t conn = container_get_connectivity(c_root_netns);

	if (container_get_state(c_root_netns) == CONTAINER_STATE_STOPPED) {
		DEBUG("Container %s stopped, unregistering connectivity c_root_netns callback",
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
	if (container_connectivity_wifi(cmld_connectivity) != container_connectivity_wifi(old_conn)) {
		/* wifi connectivity has changed */
		cmld_wifi_change_cb(container_connectivity_wifi(cmld_connectivity));
	}
	if (container_connectivity_mobile(cmld_connectivity) != container_connectivity_mobile(old_conn)) {
		/* mobile connectivity has changed */
		cmld_mobile_change_cb(container_connectivity_mobile(cmld_connectivity));
	}
	if (container_connectivity_online(cmld_connectivity) != container_connectivity_online(old_conn)) {
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
cmld_airplane_mode_rootns_cb(container_t *c_root_netns, UNUSED container_callback_t *cb, UNUSED void *data)
{
	bool mode = container_get_airplane_mode(c_root_netns);

	/* check if anything has changed and return if not */
	if (cmld_airplane_mode == mode)
		return;

	bool old_mode = cmld_airplane_mode;
	cmld_airplane_mode = mode;

	DEBUG("Global airplane mode changed from %d to %d", old_mode, cmld_airplane_mode);

	/* set the airplane mode in aX containers to the global state */
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		container_t *container = l->data;
		if (container != c_root_netns) {
			container_set_airplane_mode(container, mode);
		}
	}
}

static void
cmld_airplane_mode_aX_cb(container_t *aX, container_callback_t *cb, UNUSED void *data)
{
	if (container_get_state(aX) == CONTAINER_STATE_STOPPED) {
		DEBUG("Container %s stopped, unregistering airplane_mode aX callback",
				container_get_description(aX));
		container_unregister_observer(aX, cb);
	}

	if (cmld_airplane_mode == container_get_airplane_mode(aX))
		return;

	DEBUG("Setting global airplane mode %d in container %s", cmld_airplane_mode, container_get_description(aX));

	container_set_airplane_mode(aX, cmld_airplane_mode);
}

static void
cmld_container_start_finish()
{
	// we want to start/resume the new container,
	// so first clean up the cmld_switch_state...

	if (cmld_switch_state) {
		if (cmld_switch_state->timer) {
			if (!cmld_switch_state->timed_out)
				event_remove_timer(cmld_switch_state->timer);
			event_timer_free(cmld_switch_state->timer);
		}

		if (!cmld_switch_state->display_suspended)
			display_unregister_sleep_oneshot_cb(cmld_switch_state->display_sleep);

		mem_free(cmld_switch_state);
		cmld_switch_state = NULL;
	}

	// now start/resume the new container - if one is waiting to be resumed

	container_t *container = cmld_container_to_resume;
	if (!container) {
		cmld_containers_disable_switching_and_pb();
		return;
	}

	ASSERT(!cmld_foreground_observer);
	cmld_foreground_observer = container_register_observer(container, &cmld_foreground_observer_cb, NULL);
	if (!cmld_foreground_observer) {
		WARN("Could not register foreground watcher callback on container %s", container_get_description(container));
	}

	if (container_get_state(container) == CONTAINER_STATE_STOPPED) {
		/* container is not running => start it */
		DEBUG("Container %s is not running => start it", container_get_description(container));

		/* register callbacks which should be present while the container is running
		 * ATTENTION: All these callbacks MUST deregister themselves as soon as the container is stopped */
		if (!container_register_observer(container, &cmld_container_notification_cb, NULL)) {
			ERROR("Could not register container event observer callback for %s",
					container_get_description(container));
		}
		if (!container_register_observer(container, &cmld_container_switch_to_container_cb, NULL)) {
			ERROR("Could not register container event observer callback for %s",
					container_get_description(container));
		}
		if (!container_register_observer(container, &cmld_container_call_active_cb, NULL)) {
			ERROR("Could not register container event observer callback for %s",
					container_get_description(container));
		}
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

			if (!container_register_observer(container, &cmld_airplane_mode_rootns_cb, NULL)) {
				ERROR("Could not register airplane_mode observer callback for %s",
						container_get_description(container));
			}
		} else {
			if (!container_register_observer(container, &cmld_airplane_mode_aX_cb, NULL)) {
				ERROR("Could not register airplane mode observer callback for %s",
						container_get_description(container));
			}
		}

		if (container_start(container))
			WARN("Start failed for container %s", container_get_description(container));

		/* Note that the container is set active in the cmld_foreground_observer_cb as soon as it has
		 * the state CONTAINER_STATE_BOOTING */
		/* disable switching until the container has booted up (see cmld_foreground_observer_cb) */
		DEBUG("Disabling container switching for container startup");
		cmld_containers_disable_switching_and_pb();
		/* Note that the time the container has to boot up is limited by the startup implementation
		 * in container.c. It should therefore be safe to disable the switching here without jeopardizing
		 * the rest of the system, as the container is killed as soon as the timeout is hit, which
		 * triggers the cmld_foreground_observer_cb which in turn re-enables switching. */
	} else {
		if (container_set_active(container) < 0)
			WARN("Set active failed for container %s", container_get_description(container));
		if (container_resume(container) < 0)
			WARN("Resume failed for container %s", container_get_description(container));
		cmld_containers_enable_switching_and_pb();
	}

	hardware_set_led(container_get_color(container), !cmld_should_led_blink);

	/* Reset the waiting container variable */
	cmld_container_to_resume = NULL;
}


/* This function starts/resumes the container pointed to by cmld_container_to_resume.
 * It is called by cmld_fb_sleep_cb and by timers set in cmld_container_start */
static void
cmld_container_start_check_suspend()
{
	if (!cmld_switch_state->timed_out) {
		if (!cmld_switch_state->display_suspended) {
			DEBUG("Still waiting to start/resume next container...");
			return;
		} else {
			if (display_is_on()) {
				DEBUG("Display still on, re-send suspend request to active container");
				cmld_switch_state->display_suspended = false;
				if (container_suspend(cmld_switch_state->container) < 0)
					WARN("Could not suspend foreground container");
				DEBUG("re-registering display sleep callback...");
				display_unregister_sleep_oneshot_cb(cmld_switch_state->display_sleep);
				cmld_switch_state->display_sleep =
					display_register_sleep_oneshot_cb(&cmld_display_sleep_cb, NULL);
				if (!cmld_switch_state->display_sleep)
					FATAL("Could not register display sleep callback");
				return;
			} else {
				DEBUG("Can start/resume next container now...");
			}
		}
	} else { // timeout...
		if (!cmld_switch_state->display_suspended)
			WARN("Waiting for display suspend timed out");
		WARN("Waiting for container going to background timed out, continuing anyway...");
	}

	cmld_container_start_finish();
}


static void
cmld_display_sleep_cb(UNUSED void *data)
{
	DEBUG("Display should be suspended now");

	cmld_display_on = false;

	cmld_switch_state->display_suspended = true;
	cmld_container_start_check_suspend();
}

static void
cmld_container_suspend_timeout_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	DEBUG("Timeout for suspending foreground container...");
	cmld_switch_state->timed_out = true;
	cmld_container_start_check_suspend();
}

int
cmld_container_start(container_t *container, const char *key, bool no_switch)
{
	if (!container) {
		WARN("Container does not exists!");
		return -1;
	}

	if (key) {
		DEBUG("Setting container key for startup");
		container_set_key(container, key);
	}

	// i think we should never support a thing like "background-starting" since it
	// introduces so many problems...
	// If we still want to support this in the future, have a look at container.c where
	// the container is set active when starting which is contradicting to a "background-start"...
	if (no_switch) {
		if (!guestos_get_feature_bg_booting(container_get_guestos(container))) {
			WARN("Guest OS of the container %s does not support background booting", container_get_description(container));
			return -1;
		}
		if (container_start(container)) {
			WARN("Start of background container %s failed", container_get_description(container));
			return -1;
		}
		return 0;
	}

	if (!cmld_switching_enabled) {
		WARN("Switching is currently disabled (foreground booting a container?)");
		return -1;
	}

	/* do not allow power state changes while switching */
	cmld_containers_disable_switching_and_pb();

	/* set global variable to indicate that the given container should be resumed next */
	cmld_container_to_resume = container;

	/* unregister foreground observer */
	if (cmld_foreground_observer) {
		for (list_t *l = cmld_containers_list; l; l = l->next) {
			container_unregister_observer(l->data, cmld_foreground_observer);
		}
		cmld_foreground_observer = NULL;
	}

	container_t *fg = cmld_containers_get_foreground();
	if(!fg) {
		DEBUG("No foreground container found, switching/starting container %s right away",
				container_get_description(container));
		cmld_container_start_finish();
		return 0;
	}

	if (fg == container) {
		DEBUG("Switching to fg container? Just resuming it...");
		cmld_container_start_finish();
		return 0;
	}

	DEBUG("Suspending foreground container %s", container_get_description(fg));
	if (container_suspend(fg) < 0)
		WARN("Could not suspend foreground container");

	/* allocate a cmld_switch_state data structure */
	/* if there is already a cmld_switch_state do nothing */
	if (cmld_switch_state)
		return 0;

	cmld_switch_state = mem_new0(struct cmld_switch_state, 1);
	cmld_switch_state->container = fg;

	DEBUG("Registering timeout for container suspend...");
	cmld_switch_state->timer = event_timer_new(CMLD_SUSPEND_TIMEOUT, 1, &cmld_container_suspend_timeout_cb, NULL);
	event_add_timer(cmld_switch_state->timer);

	if (display_is_on()) {
		DEBUG("Registering display sleep callback...");
		cmld_switch_state->display_sleep = display_register_sleep_oneshot_cb(&cmld_display_sleep_cb, NULL);
		if (!cmld_switch_state->display_sleep)
			FATAL("Could not register display sleep callback");
	} else {
		DEBUG("Display is already suspended");
		cmld_switch_state->display_suspended = true;
	}

	cmld_container_start_check_suspend();
	return 0;
}

int
cmld_container_start_with_smartcard(container_t *container, const char *passwd, bool no_switch)
{
	ASSERT(container);
	ASSERT(passwd);

	return smartcard_container_start_handler(cmld_smartcard, container, passwd, no_switch);
}

int
cmld_get_control_gui_sock(void)
{
	return control_get_client_sock(cmld_control_gui);
}

// TODO: should we merge switch and start?
int
cmld_container_switch(container_t *container)
{
	ASSERT(container);

	DEBUG("Trying to switch to container %s", container_get_description(container));

	if (container_get_state(container) != CONTAINER_STATE_RUNNING) {
		ERROR("Container %s not running, start first", container_get_description(container));
		return -1;
	}

	return cmld_container_start(container, NULL, false);
}

int
cmld_container_switch_to_a0()
{
	return cmld_container_switch(cmld_containers_get_a0());
}

/******************************************************************************/

// TODO: how should we encrypt a0?
#define A0_KEY "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

static void
cmld_init_a0_cb(container_t *container, container_callback_t *cb, void *data)
{
	int *control_sock_p = data;

	container_state_t state = container_get_state(container);
	/* Check if the container got over the initial starting phase */
	if (state == CONTAINER_STATE_BOOTING || state == CONTAINER_STATE_RUNNING) {
		/* Initialize control interface on the socket previously bound into a0 */
		cmld_control_gui = control_new(*control_sock_p);
		mem_free(control_sock_p);
		container_unregister_observer(container, cb);
	}
	// TODO think about if this is unregistered correctly in corner cases...
}

static void
cmld_a0_boot_complete_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	container_state_t state = container_get_state(container);
	if (state == CONTAINER_STATE_RUNNING) {
		DEBUG("a0 booted successfully!");
		container_oom_protect_service(container);
		cmld_rename_logfiles();
		container_unregister_observer(container, cb);

		for (list_t *l = cmld_containers_list; l; l = l->next) {
			container_t *container = l->data;
			if (container_get_allow_autostart(container)) {
				INFO("Autostarting container %s in background", container_get_name(container));
				cmld_container_start(container, NULL, true);
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

	/* all containers are down, so shut down */
	DEBUG("Device shutdown: last container down; shutdown now");

	#ifndef TRUSTME_DEBUG
	android_reboot(ANDROID_RB_POWEROFF, 0, 0);
	// should never arrive here, but in case the shutdown fails somehow, we exit
	exit(0);
	#endif /* TRUSTME_DEBUG */
}

/**
 * This callback for a0 is used when a0 gets the shutdown command in order to
 * trigger the graceful shutdown of the other running containers
 */
static void
cmld_shutdown_a0_cb(container_t *a0, container_callback_t *cb, UNUSED void *data) {

	container_state_t a0_state = container_get_state(a0);
	bool shutdown_now = true;

	/* only execute the callback if a0 goes down */
	if (!(a0_state == CONTAINER_STATE_SHUTTING_DOWN || a0_state == CONTAINER_STATE_STOPPED ||
		    a0_state == CONTAINER_STATE_ZOMBIE)) {
		return;
	}

	DEBUG("Device shutdown: a0 went down or shutting down, checking others before shutdown");

	/* iterate over containers and check their status:
	 * - every container, which is not yet down gets an observer to inspect global containers' statuses
	 * - every container, which is furthermore not yet shutting down, is sent the shutdown command, which
	 *   needs not to be done for a0, as this observer callback call tells that it is either already
	 *   dead or in shutting down state
	 */
	for (list_t *l = cmld_containers_list; l; l = l->next) {
		if (!(container_get_state(l->data) == CONTAINER_STATE_STOPPED ||
			container_get_state(l->data) == CONTAINER_STATE_ZOMBIE)) {
			shutdown_now = false;
			if (!container_register_observer(l->data, &cmld_shutdown_container_cb, NULL)) {
				ERROR("Could not register observer shutdown callback for %s",
					container_get_description(l->data));
			}
			if (l->data != a0 && !(container_get_state(l->data) == CONTAINER_STATE_SHUTTING_DOWN)) {
				DEBUG("Device shutdown: There is another running container:%s. Shut it down first",
					container_get_description(l->data));
				cmld_container_stop(l->data);
			}
		}
	}

	container_unregister_observer(a0, cb);

	#ifndef TRUSTME_DEBUG
	if (shutdown_now) {
		/* all containers are down, so shut down */
		DEBUG("Device shutdown: all containers already down; shutdown now");

		android_reboot(ANDROID_RB_POWEROFF, 0, 0);
		// should never arrive here, but in case the shutdown fails somehow, we exit
		exit(0);
	}
	#endif /* TRUSTME_DEBUG */
}

static int
cmld_init_a0(const char *path, const char *c0os)
{
	/* Get the a0 guestos */
	guestos_t *a0_os = guestos_mgr_get_latest_by_name(c0os, true);
	// TODO discuss if flashing should be done here or elsewhere
	int flash_result = guestos_images_flash(a0_os);
	if (flash_result < 0) {
		FATAL("Failed to verify and/or flash a0 images!");
	}
	if (flash_result > 0) {
		INFO("Flashed %d image(s), rebooting device ...", flash_result);
		android_reboot(ANDROID_RB_RESTART, 0, 0);
		FATAL("Failed to reboot!");
	}

	uuid_t *a0_uuid = uuid_new("00000000-0000-0000-0000-000000000000");
	char *a0_images_folder = mem_printf("%s/%s", path, "00000000-0000-0000-0000-000000000000");
	mount_t *a0_mnt = mount_new();
	guestos_fill_mount(a0_os, a0_mnt);
	unsigned int a0_ram_limit = 1024;
	bool a0_ns_net = strcmp(c0os, "idsos") ? true : false;
	bool privileged = true;
	bool is_switchable = strcmp(c0os, "idsos") ? true : false;

	container_t *new_a0 = container_new_internal(a0_uuid, "a0", false, a0_ns_net, privileged, a0_os, NULL,
			      a0_images_folder, a0_mnt, a0_ram_limit, 0xffffff00, 0, false, is_switchable, NULL,
			      cmld_get_device_host_dns(), cmld_container_get_telephony_name());

	/* depending on the storage of the a0 pointer, do ONE of the following: */
	/* store a0 as first element of the cmld_containers_list */
	cmld_containers_list = list_prepend(cmld_containers_list, new_a0);
	/* OR store a0 in a global variable */
	//a0 = new_a0;

	mem_free(a0_images_folder);
	INFO("Starting management container %s...", container_get_description(new_a0));

	int *control_sock_p = mem_new0(int, 1);
	*control_sock_p = container_bind_socket_before_start(new_a0, CMLD_CONTROL_SOCKET);

	if (!container_register_observer(new_a0, &cmld_init_a0_cb, control_sock_p)) {
		WARN("Could not register observer init callback on a0");
		return -1;
	}
	if (!container_register_observer(new_a0, &cmld_a0_boot_complete_cb, NULL)) {
		WARN("Could not register observer boot complete callback on a0");
		return -1;
	}

	ASSERT(!cmld_foreground_observer);
	cmld_foreground_observer = container_register_observer(new_a0, &cmld_foreground_observer_cb, NULL);
	if (!cmld_foreground_observer) {
		WARN("Could not register foreground watcher callback on a0");
	}

	container_set_key(new_a0, A0_KEY);
	if (container_start(new_a0))
		FATAL("Could not start management container");

	hardware_set_led(container_get_color(new_a0), !cmld_should_led_blink);

	if (container_set_active(new_a0) < 0)
		WARN("Set active failed for container %s", container_get_description(new_a0));

	/* register an observer to capture the shutdown command for the special container a0 */
	if (!container_register_observer(new_a0, &cmld_shutdown_a0_cb, NULL)) {
		WARN("Could not register observer shutdown callback for a0");
		return -1;
	}

	if (!container_register_observer(new_a0, &cmld_container_switch_to_container_cb, NULL)) {
		WARN("Could not register container switch observer callback for a0");
		return -1;
	}

	return 0;
}

static void
cmld_tune_network(const char *host_addr, uint32_t host_subnet, const char *host_if, const char *host_gateway)
{
	/*
	 * Increase the max socket send buffer size which is used for all types of
	 * connections. In particular, this is required by the TrustmeService in
	 * order to send moderately large messages (e.g. wallpaper data) over the
	 * unix domain socket to the cmld without blocking for several seconds.
	 */
	if (file_printf("/proc/sys/net/core/wmem_max", "%d", 1024*1024) < 0)
		WARN("Could not increase max OS send buffer size");

	/* configure loopback interface of root network namespace */
	network_setup_loopback();

	/* Temporary hardcoded configuration for trustme-x86 on qemu*/
	DEBUG("Trying to configure eth0");
	//network_set_ip_addr_of_interface("10.0.2.15", 24, "eth0");
	network_set_ip_addr_of_interface(host_addr, host_subnet, host_if);
	network_setup_default_route(host_gateway, true);
}

static void
cmld_cb_overwrite_led(UNUSED event_timer_t *timer, void *data)
{
	bool *led_on = data;

	*led_on = !*led_on;

	if (*led_on) {
		hardware_set_led(0x00000000, false);
		return;
	}

	container_t *active_container = cmld_containers_get_foreground();
	if (active_container)
		hardware_set_led(container_get_color(active_container), false);
	else
		hardware_set_led(0xffffff00, false);
}

int
cmld_init(const char *path)
{
	INFO("Storage path is %s", path);
	cmld_path = path;


	/* Currently the given path is used by the config module to generate the
	 * paths and it must therefore be ensured that it exists before loading
	 * the config file. */
	if (mkdir(path, 0755) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir base path %s", path);

	char *users_path = mem_printf("%s/%s", path, CMLD_PATH_USERS_DIR);
	if (mkdir(users_path, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir users directory %s", users_path);
	mem_free(users_path);

	char *device_path = mem_printf("%s/%s", path, CMLD_PATH_DEVICE_CONF);
	device_config_t *device_config = device_config_new(device_path);
	if (!device_config)
		WARN("Could not initialize device config");
	mem_free(device_path);

	cmld_tune_network(device_config_get_host_addr(device_config), device_config_get_host_subnet(device_config),
			device_config_get_host_if(device_config), device_config_get_host_gateway(device_config));

	cmld_shared_data_dir = mem_printf("%s/%s", path,
			CMLD_PATH_SHARED_DATA_DIR);
	if (mkdir(cmld_shared_data_dir, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir shared data directory %s",
				cmld_shared_data_dir);

	// Store uuid from device config. TODO: free?
	cmld_device_uuid = mem_strdup(device_config_get_uuid(device_config));

	const char *update_base_url = device_config_get_update_base_url(device_config);
	cmld_device_update_base_url = update_base_url
		? mem_strdup(update_base_url)
		: NULL;

	const char *host_dns = device_config_get_host_dns(device_config);
	cmld_device_host_dns = host_dns ? mem_strdup(host_dns) : NULL;

	if (mount_debugfs() < 0)
		FATAL("Could not mount debugfs");
	INFO("mounted debugfs");

	if (power_init() < 0)
		FATAL("Could not init power module");
	INFO("power initialized.");

	if (input_init() < 0)
		FATAL("Could not init input module");
	INFO("input initialized.");

	if (ksm_init() < 0)
		WARN("Could not init ksm module");
	INFO("ksm initialized.");

	/* the control module sets up a local or remote socket, registers a
	 * callback (via event_) and parses incoming commands
	 * and calls the corresponding function in the cmld module,
	 * e.g. cmld_switch_container */
	//control_cmld_cli = control_local_new(config_get_cmld_cli_sock_path(config));
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

	cmld_should_led_blink = device_config_get_should_led_blink(device_config);
	if (cmld_should_led_blink) {
		// setup the led blinking
		DEBUG("led debug blinking on");
		bool *led_on = mem_new0(bool, 1);
		event_timer_t *led_timer = event_timer_new(500, EVENT_TIMER_REPEAT_FOREVER,
							   &cmld_cb_overwrite_led, led_on);
		event_add_timer(led_timer);
	} else {
		DEBUG("led debug blinking off");
		hardware_set_led(0xffffff00, true); /* set led to white */
	}

	char *guestos_path = mem_printf("%s/%s", path, CMLD_PATH_GUESTOS_DIR);
	if (guestos_mgr_init(guestos_path) < 0)
		FATAL("Could not load guest operating systems");
	mem_free(guestos_path);
	INFO("guestos initialized.");
	guestos_mgr_update_images();

	char *containers_path = mem_printf("%s/%s", path, CMLD_PATH_CONTAINERS_DIR);
	if (mkdir(containers_path, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir containers directory %s", containers_path);

	char *tokens_path = mem_printf("%s/%s", path, CMLD_PATH_CONTAINER_KEYS_DIR);
	cmld_smartcard = smartcard_new(tokens_path);
	mem_free(tokens_path);

	if (cmld_smartcard == NULL)
		FATAL("Could not connect to smartcard daemon");
	else
		INFO("Connected to smartcard daemon");

	if (cmld_load_containers(containers_path) < 0)
		FATAL("Could not load containers");

	if (cmld_init_a0(containers_path, device_config_get_c0os(device_config)) < 0)
		FATAL("Could not init a0");

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
cmld_container_create_from_config(const char *config, size_t config_len)
{
	ASSERT(config);
	ASSERT(config_len);
	ASSERT(0);
	return NULL;
}

int
cmld_container_destroy(container_t *container)
{
	ASSERT(container);
	ASSERT(0);
	return 0;
}

int
cmld_container_stop(container_t *container)
{
	ASSERT(container);

	DEBUG("Trying to stop container %s", container_get_description(container));

	if (container_get_state(container) != CONTAINER_STATE_RUNNING) {
		ERROR("Container %s not running, unable to stop", container_get_description(container));
		return -1;
	}

	/* if a foreground container is stopped, switch back to a0 */
//	container_t *fg = cmld_containers_get_foreground();
//	container_t *a0 = cmld_containers_get_a0();

//	if (a0 && a0 != container) {
//		if (container == fg && container_get_state(a0) == CONTAINER_STATE_RUNNING) {
//			DEBUG("Stop a foreground container, switch to a0");
//			if (cmld_container_switch_to_a0() < 0)
//				WARN("Switch to A0 failed");
//		}
//	}

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
cmld_wipe_device() {

	dir_delete_folder(cmld_path, CMLD_PATH_GUESTOS_DIR);
	dir_delete_folder(cmld_path, CMLD_PATH_CONTAINERS_DIR);
	dir_delete_folder(cmld_path, CMLD_PATH_CONTAINER_KEYS_DIR);
	dir_delete_folder(cmld_path, CMLD_PATH_CONTAINER_TOKENS_DIR);
	dir_delete_folder(LOGFILE_DIR, "");
	android_reboot(ANDROID_RB_POWEROFF, 0, 0);
}
