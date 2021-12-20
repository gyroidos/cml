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
 * @file c_cgroups.c
 *
 * This submodule provides functionality to setup control groups for containers.
 * This includes configurations like the max ram for a container and  the functionality
 * to freeze and unfreeze a container.
 */

#define MOD_NAME "c_cgroups"

// for gnu version of basename
#define _GNU_SOURCE
#include <string.h>

#include "hardware.h"
#include "uevent.h"
#include "cmld.h"
#include "mount.h"

#include "common/mem.h"
#include "common/macro.h"
#include "common/file.h"
#include "common/event.h"
#include "common/dir.h"

#include <limits.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <errno.h>
#include <unistd.h>

#include <sched.h>

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#define CGROUPS_FOLDER MOUNT_CGROUPS_FOLDER

// FIXME: currently replaced by hardware_get_active_cgroups_subsystems() to
// work-around a buggy kernel cgroups implementation for the "deb" device.
//#define ACTIVE_CGROUPS_SUBSYSTEMS "cpu,memory,freezer,devices"

/* Define timeout for freeze in milliseconds */
#define CGROUPS_FREEZER_TIMEOUT 5000
/* Define the time interval between status checks while freezing */
#define CGROUPS_FREEZER_RETRY_INTERVAL 100

#define CGROUPS_FREEZER_RETRIES CGROUPS_FREEZER_TIMEOUT / CGROUPS_FREEZER_RETRY_INTERVAL

/* List of 2-element int arrays, representing maj:min of devices allowed to be used in the running containers.
  * wildcard '*' is mapped to -1 */
list_t *global_allowed_devs_list = NULL;

/* List of 2-element int arrays, representing maj:min of devices exclusively assigned to the running containers.
  * wildcard '*' is mapped to -1 */
list_t *global_assigned_devs_list = NULL;

typedef struct c_cgroups {
	container_t *container; // weak reference
	char *cgroup_path;
	list_t *active_cgroups;

	event_inotify_t *inotify_freezer_state;
	event_timer_t *freeze_timer; /* timer to handle a container freeze timeout */
	int freezer_retries;
	list_t *assigned_devs; /* list of 2 element int arrays, representing maj:min of exclusively assigned devices.
				  wildcard '*' is mapped to -1 */
	list_t *allowed_devs; /* list of 2 element int arrays, representing maj:min of devices allowed to be accessed.
				  wildcard '*' is mapped to -1 */
	bool ns_cgroup;
} c_cgroups_t;

static void *
c_cgroups_new(container_t *container)
{
	ASSERT(container);

	c_cgroups_t *cgroups = mem_new0(c_cgroups_t, 1);
	cgroups->container = container;
	//cgroups->cgroup_path = mem_printf("%s/%s", CONTAINER_HIERARCHY, uuid_string(container_get_uuid(cgroups->container)));
	cgroups->active_cgroups = hardware_get_active_cgroups_subsystems();

	cgroups->inotify_freezer_state = NULL;
	cgroups->freeze_timer = NULL;
	cgroups->assigned_devs = NULL;
	cgroups->allowed_devs = NULL;
	cgroups->ns_cgroup = file_exists("/proc/self/ns/cgroup");
	return cgroups;
}

static void
c_cgroups_free(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	mem_free0(cgroups->cgroup_path);
	mem_free0(cgroups);
}

/*******************/
/* Functions */

/**
 * Generic whitelist of devices to be available for all containers independent
 * from hardware and container configuration 
 */
static const char *c_cgroups_devices_generic_whitelist[] = {
	/*************/
	/* Character */

	/* Memory Devices */
	//"c 1:1 rwm", // physical mem
	//"c 1:2 rwm", // kmem
	"c 1:3 rwm", // null
	"c 1:5 rwm", // zero
	"c 1:7 rwm", // full
	"c 1:8 rwm", // random
	"c 1:9 rwm", // urandom
	//"c 1:11 rwm", // kmsg

	/* TTY */
	//"c 2:* rwm", // BSD pseudo-tty masters (deprecated)
	//"c 3:* rwm", // BSD pseudo-tty slaves  (deprecated)

	//"c 4:0 rwm", // tty0

	/* alternate tty devices - seem to be necessary for android logwrapper */
	//"c 5:0 rwm", // tty
	//"c 5:1 rwm", // console
	"c 5:2 rwm", // ptmx

	//"c 7:* rwm", // Virtual console capture devices

	/* Misc */
	"c 10:183 rwm", // hw_random
	"c 10:200 rwm", // tun (for VPN inside containers)
	"c 10:229 rwm", // fuse
	//"c 10:236 rwm", // mapper/control
	//"c 10:237 rwm", // loop-control

	/* Input Core */
	//"c 13:* rwm",

	/* Universal frame buffer */
	//"c 29:* rwm",

	/* camera v4l */
	//"c 81:* rwm", // video*, v4l-subdev*

	/* i2c */
	//"c 89:* rwm",

	/* ppp */
	//"c 108:* rwm",

	/* Unix98 PTY Slaves (majors 136-143) */
	"c 136:* rwm", // e.g. used for ssh sessions

	/* USB */
	//"c 180:* rwm", // USB
	//"c 188:* rwm", // USB serial converters
	//"c 189:* rwm", // USB serial converters - alternate devices

	/*************/
	/* Block     */
	//"b 1:* rwm", // ramdisks
	//"b 7:* rwm", // loopback devs
	//"b 253:* rwm", // ZRAM
	//"b 254:* rwm", // device-mapper

	NULL
};

/* extracts major and minor device numbers from a rule as an int array {major, minor} */
static int *
c_cgroups_dev_from_rule(const char *rule)
{
	int *ret = mem_new0(int, 2);
	ret[0] = -1;
	ret[1] = -1;

	char *rule_cp = mem_strdup(rule);
	char *pointer;
	char *type;
	char *dev;

	type = strtok_r(rule_cp, " ", &pointer);
	IF_NULL_GOTO_TRACE(type, out);

	dev = strtok_r(NULL, " ", &pointer);
	IF_NULL_GOTO_TRACE(dev, out);

	pointer = NULL;

	char *maj_str = strtok_r(dev, ":", &pointer);
	IF_NULL_GOTO_TRACE(maj_str, out);

	char *min_str = strtok_r(NULL, ":", &pointer);
	IF_NULL_GOTO_TRACE(min_str, out);

	if (strncmp("*", maj_str, 1)) {
		errno = 0;
		long int parsed_int = strtol(maj_str, NULL, 10);
		IF_TRUE_GOTO_TRACE(errno == ERANGE, out);
		IF_TRUE_GOTO_TRACE(parsed_int < INT_MIN, out);
		IF_TRUE_GOTO_TRACE(parsed_int > INT_MAX, out);
		ret[0] = (int)parsed_int;
	}
	if (strncmp("*", min_str, 1)) {
		errno = 0;
		long int parsed_int = strtol(min_str, NULL, 10);
		IF_TRUE_GOTO_TRACE(errno == ERANGE, out);
		IF_TRUE_GOTO_TRACE(parsed_int < INT_MIN, out);
		IF_TRUE_GOTO_TRACE(parsed_int > INT_MAX, out);
		ret[1] = (int)parsed_int;
	}

out:
	mem_free0(rule_cp);
	return ret;
}

static void
c_cgroups_list_add(list_t **list, const int *dev)
{
	int *dev_copy = mem_new0(int, 2);
	memcpy(dev_copy, dev, sizeof(int) * 2);
	*list = list_append(*list, dev_copy);
}

static void
c_cgroups_list_remove(list_t **list, const int *dev)
{
	for (list_t *elem = *list; elem != NULL; elem = elem->next) {
		int *dev_elem = (int *)elem->data;
		if ((dev_elem[0] == dev[0]) && (dev_elem[1] == dev[1])) {
			mem_free0(elem->data);
			*list = list_unlink(*list, elem);
			break;
		}
	}
}

static int
c_cgroups_list_contains_match(const list_t *list, const int *dev)
{
	for (const list_t *elem = list; elem != NULL; elem = elem->next) {
		const int *dev_elem = (const int *)elem->data;
		if ((dev_elem[0] == -1) || (dev[0] == -1))
			return 1;
		if (dev_elem[0] != dev[0])
			continue;
		if ((dev[1] == -1) || (dev_elem[1] == -1) || (dev[1] == dev_elem[1]))
			return 1;
	}
	return 0;
}

static void
c_cgroups_add_allowed(c_cgroups_t *cgroups, const int *dev)
{
	c_cgroups_list_add(&global_allowed_devs_list, dev);
	c_cgroups_list_add(&cgroups->allowed_devs, dev);
}

static void
c_cgroups_add_assigned(c_cgroups_t *cgroups, const int *dev)
{
	c_cgroups_list_add(&global_assigned_devs_list, dev);
	c_cgroups_list_add(&cgroups->assigned_devs, dev);
}

static int
c_cgroups_allow_rule(c_cgroups_t *cgroups, const char *rule)
{
	// first allow in host-side list, which cannot manipulated by container (if namspaced)
	char *path = mem_printf("%s/devices/%s/devices.allow", CGROUPS_FOLDER,
				uuid_string(container_get_uuid(cgroups->container)));
	if (file_write(path, rule, -1) == -1) {
		ERROR_ERRNO("Failed to write to %s", path);
		mem_free0(path);
		return -1;
	}

	// second allow in child list of container
	char *path_child = mem_printf("%s/devices/%s/child/devices.allow", CGROUPS_FOLDER,
				      uuid_string(container_get_uuid(cgroups->container)));
	if (file_exists(path_child)) {
		if (file_write(path, rule, -1) == -1) {
			ERROR_ERRNO("Failed to write to %s", path);
			mem_free0(path);
			mem_free0(path_child);
			return -1;
		}
	}

	mem_free0(path);
	mem_free0(path_child);
	return 0;
}

static int
c_cgroups_devices_allow(void *cgroupsp, const char *rule)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);
	ASSERT(rule);

	int *dev = c_cgroups_dev_from_rule(rule);
	if (c_cgroups_list_contains_match(global_assigned_devs_list, dev)) {
		WARN("Unable to allow rule %s: device busy (already assigned to another container)",
		     rule);
		mem_free0(dev);
		return 0;
	}
	c_cgroups_add_allowed(cgroups, dev);
	mem_free0(dev);
	return c_cgroups_allow_rule(cgroups, rule);
}

static int
c_cgroups_devices_assign(void *cgroupsp, const char *rule)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);
	ASSERT(rule);

	int *dev = c_cgroups_dev_from_rule(rule);
	if (c_cgroups_list_contains_match(global_allowed_devs_list, dev)) {
		ERROR("Unable to exclusively assign device according to rule %s: device busy (already available to another container)",
		      rule);
		mem_free0(dev);
		return -1;
	}

	if (c_cgroups_allow_rule(cgroups, rule) < 0) {
		mem_free0(dev);
		return -1;
	}

	c_cgroups_add_allowed(cgroups, dev);
	c_cgroups_add_assigned(cgroups, dev);
	mem_free0(dev);
	return 0;
}

static int
c_cgroups_devices_deny(void *cgroupsp, const char *rule)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);
	ASSERT(rule);

	// will automatically deny access to all sub folders including child
	char *path = mem_printf("%s/devices/%s/devices.deny", CGROUPS_FOLDER,
				uuid_string(container_get_uuid(cgroups->container)));

	if (file_write(path, rule, -1) == -1) {
		ERROR_ERRNO("Failed to write '%s' to %s", rule, path);
		goto error;
	}
	TRACE("Succeded to write '%s' to %s", rule, path);

	mem_free0(path);
	return 0;
error:
	mem_free0(path);
	return -1;
}

static int
c_cgroups_devices_allow_list(void *cgroupsp, const char **list)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	/* if the list is null, do nothing */
	if (!list)
		return 0;

	/* iterate over list and allow entries */
	for (int i = 0; list[i]; i++) {
		if (c_cgroups_devices_allow(cgroups, list[i]) < 0) {
			return -1;
		}
	}
	return 0;
}

static int
c_cgroups_devices_deny_list(void *cgroupsp, const char **list)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	/* if the list is null, do nothing */
	if (!list)
		return 0;

	/* iterate over list and allow entries */
	for (int i = 0; list[i]; i++) {
		if (c_cgroups_devices_deny(cgroups, list[i]) < 0) {
			return -1;
		}
	}
	return 0;
}

static int
c_cgroups_devices_assign_list(c_cgroups_t *cgroups, const char **list)
{
	if (!list)
		return 0;

	for (int i = 0; list[i]; i++) {
		if (c_cgroups_devices_assign(cgroups, list[i]) < 0) {
			return -1;
		}
	}
	return 0;
}

static int
c_cgroups_devices_deny_all(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	return c_cgroups_devices_deny(cgroups, "a");
}

static int
c_cgroups_devices_allow_audio(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	DEBUG("Allow audio access for container %s", container_get_description(cgroups->container));

	if (c_cgroups_devices_allow_list(cgroups, hardware_get_devices_whitelist_audio()) < 0) {
		ERROR("Could not allow audio devices for container %s",
		      container_get_description(cgroups->container));
		return -1;
	}
	return 0;
}

static int
c_cgroups_devices_deny_audio(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	DEBUG("Deny audio access for container %s", container_get_description(cgroups->container));

	if (c_cgroups_devices_deny_list(cgroups, hardware_get_devices_whitelist_audio()) < 0) {
		ERROR("Could not deny audio devices for container %s",
		      container_get_description(cgroups->container));
		return -1;
	}

	return 0;
}

static int
c_cgroups_devices_init(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	/* first deny all */
	if (c_cgroups_devices_deny_all(cgroups) < 0) {
		return -1;
	}

	/* allow generic base whitelist */
	if (c_cgroups_devices_allow_list(cgroups, c_cgroups_devices_generic_whitelist) < 0) {
		ERROR("Could not initialize generic devices whitelist for container %s",
		      container_get_description(cgroups->container));
		return -1;
	}

	/* allow hardware specific base whitelist */
	if (c_cgroups_devices_allow_list(cgroups, hardware_get_devices_whitelist_base()) < 0) {
		ERROR("Could not initialize hardware specific base devices whitelist for container %s",
		      container_get_description(cgroups->container));
		return -1;
	}

	if (container_is_privileged(cgroups->container)) {
		/* allow hardware specific whitelist for privileged containers */
		if (c_cgroups_devices_allow_list(cgroups, hardware_get_devices_whitelist_priv()) <
		    0) {
			ERROR("Could not initialize hardware specific privileged devices whitelist for container %s",
			      container_get_description(cgroups->container));
			return -1;
		}
	}

	/* get allowed features from the associated container object and configure
	 * according to it */
	/* currently: activate only for privileged containers... */
	if (container_is_privileged(cgroups->container)) {
		if (c_cgroups_devices_allow_audio(cgroups) < 0) {
			return -1;
		}
	}

	/* allow to run a KVM VMM inside an unprivileged Namespace */
	if (container_get_type(cgroups->container) == CONTAINER_TYPE_KVM) {
		if (c_cgroups_devices_allow(cgroups, "c 10:232 rwm") < 0)
			return -1;
		INFO("Allowing acces to /dev/kvm for lkvm inside new namespace");
	}

	/* allow container specific device whitelist */
	const char **container_dev_whitelist = container_get_dev_allow_list(cgroups->container);
	if (c_cgroups_devices_allow_list(cgroups, container_dev_whitelist) < 0) {
		ERROR("Could not initialize container specific device whitelist for container %s",
		      container_get_description(cgroups->container));
		return -1;
	}
	DEBUG("Applied containers whitelist");

	/* apply container specific exclusive device assignment */
	const char **container_dev_assignlist = container_get_dev_assign_list(cgroups->container);
	if (c_cgroups_devices_assign_list(cgroups, container_dev_assignlist) < 0) {
		ERROR("Could not initialize container specific device assignmet list for container %s",
		      container_get_description(cgroups->container));
		return -1;
	}
	DEBUG("Applied containers assign list");

	/* Print out the initialized devices whitelist */
	char *list_path = mem_printf("%s/devices/%s/devices.list", CGROUPS_FOLDER,
				     uuid_string(container_get_uuid(cgroups->container)));
	char *list_output = file_read_new(list_path, 10000);
	DEBUG("Devices whitelist for container %s:", container_get_description(cgroups->container));
	DEBUG("%s", list_output);
	mem_free0(list_output);
	mem_free0(list_path);

	return 0;
}

static void
c_cgroups_cleanup_freeze_timer(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	if (cgroups->freeze_timer) {
		DEBUG("Remove container freeze timer for %s",
		      container_get_description(cgroups->container));
		event_remove_timer(cgroups->freeze_timer);
		event_timer_free(cgroups->freeze_timer);
		cgroups->freeze_timer = NULL;
	}
	cgroups->freezer_retries = 0;
}

static int
c_cgroups_freeze(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	container_state_t state = container_get_state(cgroups->container);
	switch (state) {
	case CONTAINER_STATE_FROZEN:
	case CONTAINER_STATE_FREEZING:
		DEBUG("Container already frozen or freezing, doing nothing...");
		return 0;
	case CONTAINER_STATE_RUNNING:
	case CONTAINER_STATE_SETUP:
		break; // actually do freeze
	default:
		WARN("Container not running");
		return -1;
	}

	char *freezer_state_path = mem_printf("%s/freezer/%s/freezer.state", CGROUPS_FOLDER,
					      uuid_string(container_get_uuid(cgroups->container)));
	if (file_write(freezer_state_path, "FROZEN", -1) == -1) {
		ERROR_ERRNO("Failed to write to freezer file %s", freezer_state_path);
		mem_free0(freezer_state_path);
		return -1;
	}
	mem_free0(freezer_state_path);
	return 0;
}

static int
c_cgroups_unfreeze(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	// TODO think about where to check for unnecessary state changes

	char *freezer_state_path = mem_printf("%s/freezer/%s/freezer.state", CGROUPS_FOLDER,
					      uuid_string(container_get_uuid(cgroups->container)));
	if (file_write(freezer_state_path, "THAWED", -1) == -1) {
		ERROR_ERRNO("Failed to write to freezer file %s", freezer_state_path);
		mem_free0(freezer_state_path);
		return -1;
	}
	mem_free0(freezer_state_path);
	return 0;
}

static void
c_cgroups_freezer_state_cb(const char *path, uint32_t mask, event_inotify_t *inotify, void *data);

static void
c_cgroups_freeze_timeout_cb(UNUSED event_timer_t *timer, void *data)
{
	ASSERT(data);

	c_cgroups_t *cgroups = data;

	DEBUG("Checking state of the freezing process (try no. %d)", cgroups->freezer_retries + 1);

	if (cgroups->freezer_retries < CGROUPS_FREEZER_RETRIES) {
		cgroups->freezer_retries++;
		c_cgroups_freezer_state_cb(NULL, 0, NULL, cgroups);
		return;
	}

	container_state_t container_state = container_get_state(cgroups->container);
	if (container_state == CONTAINER_STATE_FREEZING) {
		WARN("Hit timeout for freezing container %s, aborting freeze...",
		     container_get_description(cgroups->container));

		if (c_cgroups_unfreeze(cgroups) < 0) {
			WARN("Could not abort freeze for container %s",
			     container_get_description(cgroups->container));
		} else {
			WARN("Freeze for container %s aborted",
			     container_get_description(cgroups->container));
		}
	}

	c_cgroups_cleanup_freeze_timer(cgroups);
}

static void
c_cgroups_freezer_state_cb(UNUSED const char *path, UNUSED uint32_t mask,
			   UNUSED event_inotify_t *inotify, void *data)
{
	c_cgroups_t *cgroups = data;

	ASSERT(cgroups);

	char *freezer_state_path = mem_printf("%s/freezer/%s/freezer.state", CGROUPS_FOLDER,
					      uuid_string(container_get_uuid(cgroups->container)));
	char *state = file_read_new(freezer_state_path, 10);
	mem_free0(freezer_state_path);

	DEBUG("State of freezer for container %s is %s",
	      container_get_description(cgroups->container), state);

	container_state_t container_state = container_get_state(cgroups->container);

	if (!strncmp(state, "THAWED", strlen("THAWED")) &&
	    (container_state == CONTAINER_STATE_FREEZING ||
	     container_state == CONTAINER_STATE_FROZEN)) {
		INFO("Container %s thawed from freezing or frozen state",
		     container_get_description(cgroups->container));
		c_cgroups_cleanup_freeze_timer(cgroups);
		container_set_state(cgroups->container, CONTAINER_STATE_RUNNING);
	} else if (!strncmp(state, "FREEZING", strlen("FREEZING")) &&
		   container_state != CONTAINER_STATE_FREEZING) {
		INFO("Container %s freezing", container_get_description(cgroups->container));

		c_cgroups_cleanup_freeze_timer(cgroups);
		/* register a timer to stop the freeze if it does not complete in time */
		cgroups->freeze_timer = event_timer_new(CGROUPS_FREEZER_RETRY_INTERVAL, -1,
							&c_cgroups_freeze_timeout_cb, cgroups);
		event_add_timer(cgroups->freeze_timer);

		container_set_state(cgroups->container, CONTAINER_STATE_FREEZING);
	} else if (!strncmp(state, "FROZEN", strlen("FROZEN")) &&
		   container_state != CONTAINER_STATE_FROZEN) {
		INFO("Container %s frozen", container_get_description(cgroups->container));
		c_cgroups_cleanup_freeze_timer(cgroups);
		container_set_state(cgroups->container, CONTAINER_STATE_FROZEN);
	}

	mem_free0(state);
}

static int
c_cgroups_set_ram_limit(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	if (container_get_ram_limit(cgroups->container) == 0) {
		INFO("Setting no RAM limit for container %s",
		     container_get_description(cgroups->container));
		return 0;
	}

	int ret = -1;
	char *limit_in_bytes_path = mem_printf("%s/memory/%s/memory.limit_in_bytes", CGROUPS_FOLDER,
					       uuid_string(container_get_uuid(cgroups->container)));

	INFO("Trying to set RAM limit of container %s to %d MBytes",
	     container_get_description(cgroups->container),
	     container_get_ram_limit(cgroups->container));

	if (!file_exists(limit_in_bytes_path)) {
		ERROR("%s file not found (cgroups or cgroups memory subsystem not mounted?)",
		      limit_in_bytes_path);
		goto out;
	}
	if (file_printf(limit_in_bytes_path, "%dM", container_get_ram_limit(cgroups->container)) ==
	    -1) {
		ERROR("Could not write to cgroups RAM limit file in %s", limit_in_bytes_path);
		goto out;
	}

	// TODO normally we have to read the file again to check if the kernel set the RAM limit correctly
	INFO("Successfully set RAM limit of container %s to %d MBytes",
	     container_get_description(cgroups->container),
	     container_get_ram_limit(cgroups->container));

	ret = 0;
out:
	mem_free0(limit_in_bytes_path);
	return ret;
}

static int
c_cgroups_set_cpu_exclusive(const c_cgroups_t *cgroups, char *path)
{
	ASSERT(cgroups);

	IF_NULL_RETVAL(path, -1);

	int ret = -1;
	char *cpuset_cpu_exclusive_path = mem_printf("%s/cpuset.cpu_exclusive", path);
	char *cpuset_cpu_exclusive = file_read_new(cpuset_cpu_exclusive_path, 2);

	if (!file_exists(cpuset_cpu_exclusive_path)) {
		ERROR("%s file not found (cgroups or cgroups cpuset subsystem not mounted?)",
		      cpuset_cpu_exclusive_path);
		goto out;
	}

	INFO("cgroups cpuset file %s = '%s'", cpuset_cpu_exclusive_path, cpuset_cpu_exclusive);
	if (cpuset_cpu_exclusive && cpuset_cpu_exclusive[0] == '1') {
		if (file_printf(cpuset_cpu_exclusive_path, "1") == -1) {
			ERROR("Could not write to cgroups cpuset file in %s",
			      cpuset_cpu_exclusive_path);
			goto out;
		}
	}

	if (file_printf(cpuset_cpu_exclusive_path, "1") == -1) {
		ERROR("Could not write to cgroups cpuset file in %s", cpuset_cpu_exclusive_path);
		goto out;
	}
	ret = 0;
out:
	mem_free0(cpuset_cpu_exclusive);
	mem_free0(cpuset_cpu_exclusive_path);
	return ret;
}

/**
 * This functions gets the allowed cpus for the container from its associated container
 * object and configures the cgroups cpuset subsystem to restrict access to that cpus.
 */
static int
c_cgroups_set_cpus_allowed(const c_cgroups_t *cgroups, char *path)
{
	ASSERT(cgroups);

	if (NULL == container_get_cpus_allowed(cgroups->container)) {
		INFO("Setting no CPU restrictions for container %s",
		     container_get_description(cgroups->container));
		return 0;
	}

	IF_NULL_RETVAL(path, -1);

	int ret = -1;
	char *cpuset_cpus_path = mem_printf("%s/cpuset.cpus", path);
	char *cpuset_mems_path = mem_printf("%s/cpuset.mems", path);

	if (!file_exists(cpuset_cpus_path)) {
		ERROR("%s file not found (cgroups or cgroups cpuset subsystem not mounted?)",
		      cpuset_cpus_path);
		goto out;
	}
	if (file_printf(cpuset_cpus_path, "%s", container_get_cpus_allowed(cgroups->container)) ==
	    -1) {
		ERROR("Could not write to cgroups cpuset file in %s", cpuset_cpus_path);
		goto out;
	}

	if (!file_exists(cpuset_mems_path)) {
		ERROR("%s file not found (cgroups or cgroups cpuset subsystem not mounted?)",
		      cpuset_mems_path);
		goto out;
	}
	if (file_printf(cpuset_mems_path, "0") == -1) {
		ERROR("Could not write to cgroups cpuset file in %s", cpuset_mems_path);
		goto out;
	}

	IF_TRUE_GOTO(c_cgroups_set_cpu_exclusive(cgroups, path) == -1, out);

	INFO("Successfully set CPU restriction of container %s to cores %s",
	     container_get_description(cgroups->container),
	     container_get_cpus_allowed(cgroups->container));

	ret = 0;
out:
	mem_free0(cpuset_cpus_path);
	mem_free0(cpuset_mems_path);

	return ret;
}

#ifndef _BSD_SOURCE
#define _BSD_SOURCE /* See feature_test_macros(7) */
#endif

static void
c_cgroups_devices_watch_dev_dir_cb(const char *path, uint32_t mask, UNUSED event_inotify_t *inotify,
				   void *data)
{
	c_cgroups_t *cgroups = data;

	char *type;

	if (!path)
		return;

	//char *path = mem_printf("/proc/%d/root/dev/%s", container_get_pid(cgroups->container), p);

	if (mask & IN_CREATE) {
		/* we are only interested in IN_CREATE if a directory was created */
		if (file_is_dir(path)) {
			/* If a directory was created in the dev directory register the same callback for it */
			event_inotify_t *inotify_dev =
				event_inotify_new(path, IN_OPEN | IN_CREATE,
						  &c_cgroups_devices_watch_dev_dir_cb, cgroups);
			event_add_inotify(inotify_dev);
			DEBUG("Registered inotify callback for %s", path);
		}
		return;
	}

	struct stat dev_stat;
	mem_memset(&dev_stat, 0, sizeof(dev_stat));

	if (stat(path, &dev_stat) == -1) {
		WARN_ERRNO("Could not stat %s", path);
		return;
	}

	if (S_ISBLK(dev_stat.st_mode)) {
		type = "b";
	} else if (S_ISCHR(dev_stat.st_mode)) {
		type = "c";
	} else {
		return;
	}

	unsigned int maj = major(dev_stat.st_rdev);
	unsigned int min = minor(dev_stat.st_rdev);

	/* print in the container like that:
	 * in one shell: $ cml-logcat -A | grep "dev in container a2" > devs.txt
	 * in another shell: $ cat devs.txt | sort -k 13 -n -k 14 -n -u
	 */
	DEBUG("dev in container %s: %s %u %u %s", container_get_description(cgroups->container),
	      type, maj, min, basename(path));

	//if (mask & IN_CREATE) {
	//	DEBUG("dev in container %s: %s (create)", container_get_description(cgroups->container), path);
	//} else if (mask & IN_OPEN) {
	//	DEBUG("dev in container %s: %s (open)", container_get_description(cgroups->container), path);
	//} else if (mask & IN_CLOSE) {
	//	DEBUG("dev in container %s: %s (close)", container_get_description(cgroups->container), path);
	//}
}

static int
c_cgroups_devices_dev_dir_foreach_cb(const char *path, const char *name, void *data)
{
	char *full_path = mem_printf("%s/%s", path, name);

	if (!file_is_dir(full_path))
		goto out;

	c_cgroups_t *cgroups = data;

	event_inotify_t *inotify_dev = event_inotify_new(
		full_path, IN_OPEN | IN_CREATE, &c_cgroups_devices_watch_dev_dir_cb, cgroups);
	event_add_inotify(inotify_dev);

	if (dir_foreach(full_path, &c_cgroups_devices_dev_dir_foreach_cb, cgroups) < 0) {
		WARN("Could not open %s for registering device watcher", full_path);
	}

out:
	mem_free0(full_path);
	return 0;
}

UNUSED static void
c_cgroups_devices_watch_dev_dir(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	char *dev_path = mem_printf("/proc/%d/root/dev", container_get_pid(cgroups->container));

	event_inotify_t *inotify_dev = event_inotify_new(
		dev_path, IN_OPEN | IN_CREATE, &c_cgroups_devices_watch_dev_dir_cb, cgroups);
	event_add_inotify(inotify_dev);

	if (dir_foreach(dev_path, &c_cgroups_devices_dev_dir_foreach_cb, cgroups) < 0) {
		WARN("Could not open %s for registering device watcher", dev_path);
	}

	mem_free0(dev_path);
}

static int
c_cgroups_devices_chardev_allow(void *cgroupsp, int major, int minor, bool assign)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	int ret;

	char *rule = mem_printf("c %d:%d rwm", major, minor);
	if (assign)
		ret = c_cgroups_devices_assign(cgroups, rule);
	else
		ret = c_cgroups_devices_allow(cgroups, rule);

	mem_free0(rule);
	return ret;
}

static int
c_cgroups_devices_chardev_deny(void *cgroupsp, int major, int minor)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	int ret;

	char *rule = mem_printf("c %d:%d rwm", major, minor);
	ret = c_cgroups_devices_deny(cgroups, rule);

	mem_free0(rule);
	return ret;
}

static int
c_cgroups_devices_usbdev_allow(c_cgroups_t *cgroups, uevent_usbdev_t *usbdev)
{
	ASSERT(cgroups);
	ASSERT(usbdev);
	if (0 != uevent_usbdev_set_sysfs_props(usbdev)) {
		ERROR("Failed to find usbedv in sysfs");
		return -1;
	}

	if (-1 == c_cgroups_devices_chardev_allow(cgroups, uevent_usbedv_get_major(usbdev),
						  uevent_usbdev_get_minor(usbdev),
						  uevent_usbdev_is_assigned(usbdev))) {
		WARN("Could not %s char device %d:%d !",
		     uevent_usbdev_is_assigned(usbdev) ? "assign" : "allow",
		     uevent_usbedv_get_major(usbdev), uevent_usbdev_get_minor(usbdev));
		return -1;
	}

	return 0;
}

static bool
c_cgroups_devices_is_dev_allowed(void *cgroupsp, int major, int minor)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);
	IF_TRUE_RETVAL_TRACE(major < 0 || minor < 0, false);

	int dev[2] = { major, minor };

	/* search in assigned devices */
	if (c_cgroups_list_contains_match(cgroups->assigned_devs, dev))
		return true;

	/* search in allowed devices */
	if (c_cgroups_list_contains_match(cgroups->allowed_devs, dev))
		return true;

	return false;
}

/*******************/
/* Hooks */

static int
c_cgroups_start_pre_clone(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	if (mount_cgroups(cgroups->active_cgroups))
		return -CONTAINER_ERROR_CGROUPS;

	return 0;
}

static int
c_cgroups_start_post_clone(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	// temporarily add systemd to list
	cgroups->active_cgroups = list_prepend(cgroups->active_cgroups, "systemd");

	for (list_t *l = cgroups->active_cgroups; l; l = l->next) {
		char *subsys = l->data;
		char *subsys_path = mem_printf("%s/%s/%s", CGROUPS_FOLDER, subsys,
					       uuid_string(container_get_uuid(cgroups->container)));

		INFO("Creating cgroup subsys in %s", subsys_path);
		/* the cgroup is created simply by creating a directory in our default hierarchy */
		if (mkdir(subsys_path, 0755) && errno != EEXIST) {
			ERROR_ERRNO("Could not create cgroup %s for container %s", subsys,
				    container_get_description(cgroups->container));
			mem_free0(subsys_path);
			goto error;
		}
		/* initialize cpuset child subsystem to limit access to allowed cpus */
		if (!strcmp(subsys, "cpuset")) {
			if (c_cgroups_set_cpus_allowed(cgroups, subsys_path) < 0) {
				ERROR("Could not configure cgroup to restrict cpus of container %s",
				      container_get_description(cgroups->container));
				goto error;
			}
		}
		mem_free0(subsys_path);
	}

	// remove temporarily added head
	cgroups->active_cgroups = list_unlink(cgroups->active_cgroups, cgroups->active_cgroups);

	/* initialize memory subsystem to limit ram to cgroups->ram_limit */
	if (c_cgroups_set_ram_limit(cgroups) < 0) {
		ERROR("Could not configure cgroup maximum ram for container %s",
		      container_get_description(cgroups->container));
		goto error;
	}

	/* initialize freezer subsystem */
	char *freezer_state_path = mem_printf("%s/freezer/%s/freezer.state", CGROUPS_FOLDER,
					      uuid_string(container_get_uuid(cgroups->container)));
	cgroups->inotify_freezer_state = event_inotify_new(freezer_state_path, IN_MODIFY,
							   &c_cgroups_freezer_state_cb, cgroups);
	event_add_inotify(cgroups->inotify_freezer_state);
	mem_free0(freezer_state_path);

	return 0;
error:
	// remove temporarily added head
	cgroups->active_cgroups = list_unlink(cgroups->active_cgroups, cgroups->active_cgroups);
	return -CONTAINER_ERROR_CGROUPS;
}

static int
c_cgroups_start_pre_exec(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	/* For analyzation purposes, start watching the devices of the container */
	//c_cgroups_devices_watch_dev_dir(cgroups);
	//return 0;

	/* initialize devices subsystem */
	if (c_cgroups_devices_init(cgroups) < 0) {
		ERROR_ERRNO("devices init failed!");
		return -CONTAINER_ERROR_CGROUPS;
	}
	/* append usb devices to devices_subsystem */
	for (list_t *l = container_get_usbdev_list(cgroups->container); l; l = l->next) {
		uevent_usbdev_t *usbdev = l->data;
		// USB devices of type PIN_READER are only required outside the container to enter the pin
		// before the container starts and should not be mapped into the container, as they can
		// be used for multiple containers and a container should not be able to log the pin of
		// another container
		if (uevent_usbdev_get_type(usbdev) == UEVENT_USBDEV_TYPE_PIN_ENTRY) {
			TRACE("Device of type pin reader is not mapped into the container");
			continue;
		} else if (uevent_usbdev_get_type(usbdev) == UEVENT_USBDEV_TYPE_TOKEN) {
			// token devices are previously registered to the uevent subsystem
			c_cgroups_devices_usbdev_allow(cgroups, usbdev);
		} else if (uevent_usbdev_get_type(usbdev) == UEVENT_USBDEV_TYPE_GENERIC) {
			c_cgroups_devices_usbdev_allow(cgroups, usbdev);
			// for hotplug events register the device at uevent subsystem
			uevent_register_usbdevice(cgroups->container, usbdev);
		} else {
			ERROR("Unknown UEVENT_USBDEV_TYPE. Device has not been configured!");
		}
	}

	// temporarily add systemd to list
	cgroups->active_cgroups = list_prepend(cgroups->active_cgroups, "systemd");

	for (list_t *l = cgroups->active_cgroups; l; l = l->next) {
		char *subsys = l->data;
		char *subsys_child_path =
			mem_printf("%s/%s/%s/child", CGROUPS_FOLDER, subsys,
				   uuid_string(container_get_uuid(cgroups->container)));
		char *cgroup_tasks = mem_printf("%s/tasks", subsys_child_path);

		INFO("Creating cgroup subsys in %s", subsys_child_path);
		/* the cgroup is created simply by creating a directory in our default hierarchy */
		if (mkdir(subsys_child_path, 0755) && errno != EEXIST) {
			ERROR_ERRNO("Could not create child %s for container %s", subsys,
				    container_get_description(cgroups->container));
			mem_free0(cgroup_tasks);
			mem_free0(subsys_child_path);
			goto error;
		}

		/* initialize cpuset child subsystem to limit access to allowed cpus */
		if (!strcmp(subsys, "cpuset")) {
			if (c_cgroups_set_cpus_allowed(cgroups, subsys_child_path) < 0) {
				ERROR("Could not configure child cgroup to restrict cpus of container %s",
				      container_get_description(cgroups->container));
				goto error;
			}
		}

		if (container_shift_ids(cgroups->container, subsys_child_path, false)) {
			ERROR("Could not shift ids of cgroup subsys for userns");
			mem_free0(cgroup_tasks);
			mem_free0(subsys_child_path);
			goto error;
		}

		/* assign the container to the cgroup */
		if (file_printf(cgroup_tasks, "%d", container_get_pid(cgroups->container)) == -1) {
			ERROR_ERRNO("Could not add container %s to its cgroup under %s",
				    container_get_description(cgroups->container),
				    subsys_child_path);
			mem_free0(cgroup_tasks);
			mem_free0(subsys_child_path);
			goto error;
		}
	}

	// remove temporarily added head
	cgroups->active_cgroups = list_unlink(cgroups->active_cgroups, cgroups->active_cgroups);
	return 0;
error:
	// remove temporarily added head
	cgroups->active_cgroups = list_unlink(cgroups->active_cgroups, cgroups->active_cgroups);
	return -CONTAINER_ERROR_CGROUPS;
}

static int
c_cgroups_add_pid(void *cgroupsp, pid_t pid)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	// temporarily add systemd to list
	cgroups->active_cgroups = list_prepend(cgroups->active_cgroups, "systemd");

	for (list_t *l = cgroups->active_cgroups; l; l = l->next) {
		char *subsys = l->data;
		char *subsys_child_path =
			mem_printf("%s/%s/%s/child", CGROUPS_FOLDER, subsys,
				   uuid_string(container_get_uuid(cgroups->container)));
		char *cgroup_tasks = mem_printf("%s/tasks", subsys_child_path);

		/* assign the container to the cgroup */
		if (file_printf(cgroup_tasks, "%d", pid) == -1) {
			ERROR_ERRNO("Could not add container %s to its cgroup under %s",
				    container_get_description(cgroups->container),
				    subsys_child_path);
			mem_free0(cgroup_tasks);
			mem_free0(subsys_child_path);
			goto error;
		}
	}

	// remove temporarily added head
	cgroups->active_cgroups = list_unlink(cgroups->active_cgroups, cgroups->active_cgroups);

	return 0;
error:
	// remove temporarily added head
	cgroups->active_cgroups = list_unlink(cgroups->active_cgroups, cgroups->active_cgroups);
	return -1;
}

static int
c_cgroups_start_pre_exec_child(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	/* check if cgroupns is supported else do nothing */
	IF_FALSE_RETVAL_TRACE(cgroups->ns_cgroup, 0);

	if (unshare(CLONE_NEWCGROUP) == -1) {
		WARN_ERRNO("Could not unshare cgroup namespace!");
		return -CONTAINER_ERROR_CGROUPS;
	}

	INFO("Successfully created new cgroup namespace for container %s",
	     container_get_name(cgroups->container));
	return 0;
}

static int
c_cgroups_start_child(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	if (container_has_userns(cgroups->container))
		return 0;

	INFO("Trying to unmount cgroups in container");

	/* We are doing our best to umount the cgroups related directories in child
	 * but we do not stop if it does not work */
	for (list_t *l = cgroups->active_cgroups; l; l = l->next) {
		char *subsys = l->data;
		char *subsys_path = mem_printf("%s/%s", CGROUPS_FOLDER, subsys);
		if (umount(subsys_path) < 0) {
			WARN_ERRNO("Could not umount %s", subsys_path);
		}
		mem_free0(subsys_path);
	}
	if (umount(CGROUPS_FOLDER) < 0) {
		WARN_ERRNO("Could not umount %s", CGROUPS_FOLDER);
	}

	return 0;
}

static int
c_cgroups_cleanup_subsys_remove_cb(const char *path, const char *name, UNUSED void *data)
{
	int ret = 0;
	char *file_to_remove = mem_printf("%s/%s", path, name);
	if (file_is_dir(file_to_remove)) {
		TRACE("Removing cgroup subsys in %s is dir", file_to_remove);
		if (dir_foreach(file_to_remove, &c_cgroups_cleanup_subsys_remove_cb, NULL) < 0) {
			ERROR_ERRNO("Could not delete cgroup subsys contents in %s",
				    file_to_remove);
			ret--;
		}
		TRACE("Removing now empty subsys %s", file_to_remove);
		if (rmdir(file_to_remove) < 0) {
			ERROR_ERRNO("Could not delete cgroup subsys %s", file_to_remove);
			ret--;
		}
	}
	mem_free0(file_to_remove);
	return ret;
}

static void
c_cgroups_cleanup(void *cgroupsp, UNUSED bool is_rebooting)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	/* unregister and free the inotify event on the freezer state */
	event_remove_inotify(cgroups->inotify_freezer_state);
	event_inotify_free(cgroups->inotify_freezer_state);
	cgroups->inotify_freezer_state = NULL;

	c_cgroups_cleanup_freeze_timer(cgroups);

	// temporarily add systemd to list
	cgroups->active_cgroups = list_prepend(cgroups->active_cgroups, "systemd");

	/* remove the cgroup if it exists and free the subsys list */
	for (list_t *l = cgroups->active_cgroups; l; l = l->next) {
		char *subsys = l->data;
		char *subsys_path = mem_printf("%s/%s/%s", CGROUPS_FOLDER, subsys,
					       uuid_string(container_get_uuid(cgroups->container)));

		if (file_exists(subsys_path) && file_is_dir(subsys_path)) {
			/* recursively remove all subfolders which the container may have created */
			if (dir_foreach(subsys_path, &c_cgroups_cleanup_subsys_remove_cb, NULL) <
			    0) {
				WARN_ERRNO("Could not remove cgroup %s for container %s", subsys,
					   container_get_description(cgroups->container));
			} else if (rmdir(subsys_path) < 0) {
				WARN_ERRNO("Could not delete cgroup subsys %s", subsys_path);
			} else {
				INFO("Removed cgroup subsys %s for container %s", subsys,
				     container_get_description(cgroups->container));
			}
		}
		mem_free0(subsys_path);
	}

	// remove temporarily added head
	cgroups->active_cgroups = list_unlink(cgroups->active_cgroups, cgroups->active_cgroups);

	/* unregister usbdevs from uevent subsystem for hotplugging */
	for (list_t *l = container_get_usbdev_list(cgroups->container); l; l = l->next) {
		uevent_usbdev_t *usbdev = l->data;
		if (UEVENT_USBDEV_TYPE_TOKEN !=
		    uevent_usbdev_get_type(
			    usbdev)) // keep token registered so it can be reinitialized on hotplug
			uevent_unregister_usbdevice(cgroups->container, usbdev);
	}

	/* free assigned devices */
	for (list_t *elem = cgroups->assigned_devs; elem != NULL; elem = elem->next) {
		int *dev_elem = (int *)elem->data;
		c_cgroups_list_remove(&global_assigned_devs_list, dev_elem);
	}
	list_delete(cgroups->assigned_devs);
	cgroups->assigned_devs = NULL;

	/* free allowed devices */
	for (list_t *elem = cgroups->allowed_devs; elem != NULL; elem = elem->next) {
		int *dev_elem = (int *)elem->data;
		c_cgroups_list_remove(&global_allowed_devs_list, dev_elem);
	}
	list_delete(cgroups->allowed_devs);
	cgroups->allowed_devs = NULL;
}

static container_module_t c_cgroups_module = {
	.name = MOD_NAME,
	.container_new = c_cgroups_new,
	.container_free = c_cgroups_free,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = c_cgroups_start_pre_clone,
	.start_post_clone = c_cgroups_start_post_clone,
	.start_pre_exec = c_cgroups_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = c_cgroups_start_child,
	.start_pre_exec_child = c_cgroups_start_pre_exec_child,
	.stop = NULL,
	.cleanup = c_cgroups_cleanup,
	.join_ns = NULL,
};

static void INIT
c_cgroups_init(void)
{
	// register this module in container.c
	container_register_module(&c_cgroups_module);

	// register relevant handlers implemented by this module
	container_register_freeze_handler(MOD_NAME, c_cgroups_freeze);
	container_register_unfreeze_handler(MOD_NAME, c_cgroups_unfreeze);
	container_register_allow_audio_handler(MOD_NAME, c_cgroups_devices_allow_audio);
	container_register_deny_audio_handler(MOD_NAME, c_cgroups_devices_deny_audio);
	container_register_device_allow_handler(MOD_NAME, c_cgroups_devices_chardev_allow);
	container_register_device_deny_handler(MOD_NAME, c_cgroups_devices_chardev_deny);
	container_register_is_device_allowed_handler(MOD_NAME, c_cgroups_devices_is_dev_allowed);
	container_register_add_pid_to_cgroups_handler(MOD_NAME, c_cgroups_add_pid);
}
