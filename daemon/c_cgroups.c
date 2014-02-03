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

#include "c_cgroups.h"

#include "hardware.h"

#include "common/mem.h"
#include "common/macro.h"
#include "common/file.h"
#include "common/event.h"
#include "common/dir.h"

#include <stdint.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>

#define CGROUPS_FOLDER "/sys/fs/cgroup"
#define CONTAINER_HIERARCHY CGROUPS_FOLDER "/trustme-containers"

// FIXME: currently replaced by hardware_get_active_cgroups_subsystems() to
// work-around a buggy kernel cgroups implementation for the "deb" device.
//#define ACTIVE_CGROUPS_SUBSYSTEMS "cpu,memory,freezer,devices"

/* Define timeout for freeze in milliseconds */
#define CGROUPS_FREEZER_TIMEOUT		5000
/* Define the time interval between status checks while freezing */
#define CGROUPS_FREEZER_RETRY_INTERVAL	100

#define CGROUPS_FREEZER_RETRIES		CGROUPS_FREEZER_TIMEOUT/CGROUPS_FREEZER_RETRY_INTERVAL

struct c_cgroups {
	container_t *container; // weak reference
	char *cgroup_path;

	event_inotify_t *inotify_freezer_state;
	event_timer_t *freeze_timer; /* timer to handle a container freeze timeout */
	int freezer_retries;
};

c_cgroups_t *
c_cgroups_new(container_t *container)
{
	c_cgroups_t *cgroups = mem_new0(c_cgroups_t, 1);
	cgroups->container = container;
	cgroups->cgroup_path = mem_printf("%s/%s", CONTAINER_HIERARCHY, uuid_string(container_get_uuid(cgroups->container)));

	cgroups->inotify_freezer_state = NULL;
	cgroups->freeze_timer = NULL;

	return cgroups;
}

void
c_cgroups_free(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);
	mem_free(cgroups->cgroup_path);
	mem_free(cgroups);
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
	"c 1:11 rwm", // kmsg

	/* TTY */
	//"c 2:* rwm", // BSD pseudo-tty masters (deprecated)
	//"c 3:* rwm", // BSD pseudo-tty slaves  (deprecated)

	"c 4:0 rwm", // tty0

	/* alternate tty devices - seem to be necessary for android logwrapper */
	"c 5:0 rwm", // tty
	"c 5:1 rwm", // console
	"c 5:2 rwm", // ptmx

	//"c 7:* rwm", // Virtual console capture devices

	/* Misc */
	"c 10:183 rwm", // hw_random
	"c 10:200 rwm", // tun (for VPN inside containers)
	"c 10:229 rwm", // fuse
	//"c 10:236 rwm", // mapper/control
	//"c 10:237 rwm", // loop-control

	/* Input Core */
	"c 13:* rwm",

	/* Universal frame buffer */
	"c 29:* rwm",

	/* camera v4l */
	"c 81:* rwm", // video*, v4l-subdev*

	/* i2c */
	//"c 89:* rwm",

	/* ppp */
	//"c 108:* rwm",

	/* Unix98 PTY Slaves (majors 136-143) */
	"c 136:* rwm", // seems to be necessary for android logwrapper

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

int
c_cgroups_devices_allow(c_cgroups_t *cgroups, const char *rule)
{
	ASSERT(cgroups);
	ASSERT(rule);

	char *path = mem_printf("%s/devices.allow", cgroups->cgroup_path);

	if (file_write(path, rule, -1) == -1) {
		ERROR_ERRNO("Failed to write to %s", path);
		goto error;
	}

	mem_free(path);
	return 0;
error:
	mem_free(path);
	return -1;
}

int
c_cgroups_devices_deny(c_cgroups_t *cgroups, const char *rule)
{
	ASSERT(cgroups);
	ASSERT(rule);

	char *path = mem_printf("%s/devices.deny", cgroups->cgroup_path);

	if (file_write(path, rule, -1) == -1) {
		ERROR_ERRNO("Failed to write to %s", path);
		goto error;
	}

	mem_free(path);
	return 0;
error:
	mem_free(path);
	return -1;
}

int
c_cgroups_devices_allow_list(c_cgroups_t *cgroups, const char **list)
{
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

int
c_cgroups_devices_deny_list(c_cgroups_t *cgroups, const char **list)
{
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

int
c_cgroups_devices_allow_all(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	return c_cgroups_devices_allow(cgroups, "a");
}

int
c_cgroups_devices_deny_all(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	return c_cgroups_devices_deny(cgroups, "a");
}

int
c_cgroups_devices_allow_audio(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	DEBUG("Allow audio access for container %s", container_get_description(cgroups->container));

	if (c_cgroups_devices_allow_list(cgroups, hardware_get_devices_whitelist_audio()) < 0) {
		ERROR("Could not allow audio devices for container %s",
				container_get_description(cgroups->container));
		return -1;
	}
	return 0;
}

int
c_cgroups_devices_deny_audio(c_cgroups_t *cgroups)
{
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
		if (c_cgroups_devices_allow_list(cgroups, hardware_get_devices_whitelist_priv()) < 0) {
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

	/* Print out the initialized devices whitelist */
	char *list_path = mem_printf("%s/devices.list", cgroups->cgroup_path);
	char *list_output = file_read_new(list_path, 10000);
	DEBUG("Devices whitelist for container %s:", container_get_description(cgroups->container));
	DEBUG("%s", list_output);
	mem_free(list_output);
	mem_free(list_path);

	return 0;
}

static void
c_cgroups_cleanup_freeze_timer(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	if (cgroups->freeze_timer) {
		DEBUG("Remove container freeze timer for %s", container_get_description(cgroups->container));
		event_remove_timer(cgroups->freeze_timer);
		event_timer_free(cgroups->freeze_timer);
		cgroups->freeze_timer = NULL;
	}
	cgroups->freezer_retries = 0;
}

int
c_cgroups_freeze(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	// TODO think about where to check for unnecessary state changes, currently done in container.c

	char *freezer_state_path = mem_printf("%s/freezer.state", cgroups->cgroup_path);
	if (file_write(freezer_state_path, "FROZEN", -1) == -1) {
		ERROR_ERRNO("Failed to write to freezer file %s", freezer_state_path);
		mem_free(freezer_state_path);
		return -1;
	}
	mem_free(freezer_state_path);
	return 0;
}

int
c_cgroups_unfreeze(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	// TODO think about where to check for unnecessary state changes

	char *freezer_state_path = mem_printf("%s/freezer.state", cgroups->cgroup_path);
	if (file_write(freezer_state_path, "THAWED", -1) == -1) {
		ERROR_ERRNO("Failed to write to freezer file %s", freezer_state_path);
		mem_free(freezer_state_path);
		return -1;
	}
	mem_free(freezer_state_path);
	return 0;
}

static void
c_cgroups_freezer_state_cb(const char *path, uint32_t mask, event_inotify_t *inotify,
	void *data);

static void
c_cgroups_freeze_timeout_cb(UNUSED event_timer_t *timer, void *data)
{
	ASSERT(data);

	c_cgroups_t *cgroups = data;

	DEBUG("Checking state of the freezing process (try no. %d)", cgroups->freezer_retries+1);

	if (cgroups->freezer_retries < CGROUPS_FREEZER_RETRIES) {
	    cgroups->freezer_retries++;
	    c_cgroups_freezer_state_cb(NULL, 0, NULL, cgroups);
	    return;
	}

	container_state_t container_state = container_get_state(cgroups->container);
	if (container_state == CONTAINER_STATE_FREEZING) {
		WARN("Hit timeout for freezing container %s, aborting freeze...", container_get_description(cgroups->container));

		if (c_cgroups_unfreeze(cgroups) < 0) {
			WARN("Could not abort freeze for container %s", container_get_description(cgroups->container));
		} else {
			WARN("Freeze for container %s aborted", container_get_description(cgroups->container));
		}
	}

	c_cgroups_cleanup_freeze_timer(cgroups);
}

static void
c_cgroups_freezer_state_cb(UNUSED const char *path, UNUSED uint32_t mask, UNUSED event_inotify_t *inotify, void *data)
{
	c_cgroups_t *cgroups = data;

	ASSERT(cgroups);

	char *freezer_state_path = mem_printf("%s/freezer.state", cgroups->cgroup_path);
	char *state = file_read_new(freezer_state_path, 10);
	mem_free(freezer_state_path);

	DEBUG("State of freezer for container %s is %s", container_get_description(cgroups->container), state);

	container_state_t container_state = container_get_state(cgroups->container);

	if (!strncmp(state, "THAWED", strlen("THAWED"))
			&& (container_state == CONTAINER_STATE_FREEZING || container_state == CONTAINER_STATE_FROZEN)) {
		INFO("Container %s thawed from freezing or frozen state", container_get_description(cgroups->container));
		c_cgroups_cleanup_freeze_timer(cgroups);
		container_set_state(cgroups->container, CONTAINER_STATE_RUNNING);
	} else if (!strncmp(state, "FREEZING", strlen("FREEZING"))
			&& container_state != CONTAINER_STATE_FREEZING) {
		INFO("Container %s freezing", container_get_description(cgroups->container));

		c_cgroups_cleanup_freeze_timer(cgroups);
		/* register a timer to stop the freeze if it does not complete in time */
		cgroups->freeze_timer = event_timer_new(CGROUPS_FREEZER_RETRY_INTERVAL, -1,
				&c_cgroups_freeze_timeout_cb, cgroups);
		event_add_timer(cgroups->freeze_timer);

		container_set_state(cgroups->container, CONTAINER_STATE_FREEZING);
	} else if (!strncmp(state, "FROZEN", strlen("FROZEN"))
			&& container_state != CONTAINER_STATE_FROZEN) {
		INFO("Container %s frozen", container_get_description(cgroups->container));
		c_cgroups_cleanup_freeze_timer(cgroups);
		container_set_state(cgroups->container, CONTAINER_STATE_FROZEN);
	}

	mem_free(state);
}


int
c_cgroups_set_ram_limit(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	INFO("Trying to set RAM limit of container %s to %d MBytes",
			container_get_description(cgroups->container),
			container_get_ram_limit(cgroups->container));
	char *limit_in_bytes_path = mem_printf("%s/%s", cgroups->cgroup_path, "memory.limit_in_bytes");
	if (!file_exists(limit_in_bytes_path)) {
		ERROR("%s file not found (cgroups or cgroups memory subsystem not mounted?)", limit_in_bytes_path);
		return -1;
	}
	if (file_printf(limit_in_bytes_path, "%dM", container_get_ram_limit(cgroups->container)) == -1) {
		ERROR("Could not write to cgroups RAM limit file in %s", limit_in_bytes_path);
		return -1;
	}

	// TODO normally we have to read the file again to check if the kernel set the RAM limit correctly
	INFO("Successfully set RAM limit of container %s to %d MBytes",
			container_get_description(cgroups->container),
			container_get_ram_limit(cgroups->container));

	return 0;
}

#define _BSD_SOURCE             /* See feature_test_macros(7) */

static void
c_cgroups_devices_watch_dev_dir_cb(const char *path, uint32_t mask, UNUSED event_inotify_t *inotify, void *data)
{
	c_cgroups_t *cgroups = data;

	char *type;

	if(!path)
		return;

	//char *path = mem_printf("/proc/%d/root/dev/%s", container_get_pid(cgroups->container), p);

	if (mask & IN_CREATE) {
		/* we are only interested in IN_CREATE if a directory was created */
		if (file_is_dir(path)) {
			/* If a directory was created in the dev directory register the same callback for it */
			event_inotify_t *inotify_dev = event_inotify_new(path, IN_OPEN | IN_CREATE, &c_cgroups_devices_watch_dev_dir_cb, cgroups);
			event_add_inotify(inotify_dev);
			DEBUG("Registered inotify callback for %s", path);
		}
		return;
	}

	struct stat dev_stat;
	memset(&dev_stat, 0, sizeof(dev_stat));

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
	DEBUG("dev in container %s: %s %u %u %s", container_get_description(cgroups->container), type, maj, min, basename(path));

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

	event_inotify_t *inotify_dev = event_inotify_new(full_path, IN_OPEN | IN_CREATE, &c_cgroups_devices_watch_dev_dir_cb, cgroups);
	event_add_inotify(inotify_dev);

	if (dir_foreach(full_path, &c_cgroups_devices_dev_dir_foreach_cb, cgroups) < 0) {
		WARN("Could not open %s for registering device watcher", full_path);
	}

out:
	mem_free(full_path);
	return 0;
}

UNUSED static void
c_cgroups_devices_watch_dev_dir(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	char *dev_path = mem_printf("/proc/%d/root/dev", container_get_pid(cgroups->container));

	event_inotify_t *inotify_dev = event_inotify_new(dev_path, IN_OPEN | IN_CREATE, &c_cgroups_devices_watch_dev_dir_cb, cgroups);
	event_add_inotify(inotify_dev);

	if (dir_foreach(dev_path, &c_cgroups_devices_dev_dir_foreach_cb, cgroups) < 0) {
		WARN("Could not open %s for registering device watcher", dev_path);
	}

	mem_free(dev_path);
}

/*******************/
/* Hooks */

int
c_cgroups_start_pre_clone(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	// mount cgroups control stuff if not already done (necessary globally once)

	if (!file_exists(CONTAINER_HIERARCHY)) {
		if (mkdir(CGROUPS_FOLDER, 0755) && errno != EEXIST) {
			ERROR_ERRNO("Could not create cgroup mount directory");
			return -1;
		}

		INFO("Mounting cgroups tmpfs");
		if (mount(NULL, CGROUPS_FOLDER, "tmpfs", 0, NULL) == -1 && errno != EBUSY) {
			ERROR_ERRNO("Could not mount tmpfs for cgroups");
			return -1;
		}

		INFO("Creating cgroups default hierarchy folder in %s", CONTAINER_HIERARCHY);
		if (mkdir(CONTAINER_HIERARCHY, 0755) == -1 && errno != EEXIST) {
			ERROR_ERRNO("Could not create cgroups hierarchy folder");
			goto error;
		}
	}

	INFO("Mounting cgroups");
	const char *subsystems = hardware_get_active_cgroups_subsystems();
	int ret = mount(NULL, CONTAINER_HIERARCHY, "cgroup", 0, subsystems);
	if (ret == -1) {
		if (errno == EBUSY) {
			INFO("cgroups already mounted");
		} else {
			ERROR_ERRNO("Error mounting cgroups subsystems %s into %s", subsystems,
				    CONTAINER_HIERARCHY);
			goto error;
		}
	}

	INFO("cgroups mounted successfully");
	return 0;

error:
	umount(CGROUPS_FOLDER);
	return -1;
}

int
c_cgroups_start_post_clone(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	INFO("Creating cgroup for container %s", container_get_description(cgroups->container));
	/* the cgroup is created simply by creating a directory in our default hierarchy */
	if (mkdir(cgroups->cgroup_path, 0755) && errno != EEXIST) {
		ERROR_ERRNO("Could not create cgroup for container %s", container_get_description(cgroups->container));
		return -1;
	}

	/* assign the container to the cgroup */
	char *cgroup_tasks = mem_printf("%s/tasks", cgroups->cgroup_path);
	if (file_printf(cgroup_tasks, "%d", container_get_pid(cgroups->container)) == -1) {
		ERROR("Could not add container %s to its cgroup under %s", container_get_description(cgroups->container), cgroups->cgroup_path);
		goto error;
	}

	///* initialize memory subsystem to limit ram to cgroups->ram_limit */
	//if (c_cgroups_set_ram_limit(cgroups) < 0) {
	//	ERROR("Could not configure cgroup maximum ram for container %s", container_get_description(cgroups->container));
	//	goto error;
	//}

	/* initialize freezer subsystem */
	char *freezer_state_path = mem_printf("%s/freezer.state", cgroups->cgroup_path);
	cgroups->inotify_freezer_state = event_inotify_new(freezer_state_path, IN_MODIFY, &c_cgroups_freezer_state_cb, cgroups);
	event_add_inotify(cgroups->inotify_freezer_state);
	mem_free(freezer_state_path);

	mem_free(cgroup_tasks);
	return 0;

error:
	mem_free(cgroup_tasks);
	return -1;
}

int
c_cgroups_start_pre_exec(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	/* For analyzation purposes, start watching the devices of the container */
	//c_cgroups_devices_watch_dev_dir(cgroups);
	//return 0;

	/* initialize devices subsystem */
	return c_cgroups_devices_init(cgroups);
}

int
c_cgroups_start_child(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	INFO("Trying to unmount cgroups in container");

	/* We are doing our best to umount the cgroups related directories in child
	 * but we do not stop if it does not work */
	if (umount(CONTAINER_HIERARCHY) < 0) {
		WARN_ERRNO("Could not umount %s", CONTAINER_HIERARCHY);
	}
	if (umount(CGROUPS_FOLDER) < 0) {
		WARN_ERRNO("Could not umount %s", CGROUPS_FOLDER);
	}

	return 0;
}

void
c_cgroups_cleanup(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	/* unregister and free the inotify event on the freezer state */
	event_remove_inotify(cgroups->inotify_freezer_state);
	event_inotify_free(cgroups->inotify_freezer_state);
	cgroups->inotify_freezer_state = NULL;

	c_cgroups_cleanup_freeze_timer(cgroups);

	/* remove the cgroup if it exists */
	if (file_exists(cgroups->cgroup_path) && file_is_dir(cgroups->cgroup_path)) {
		INFO("Trying to remove cgroup for container %s", container_get_description(cgroups->container));
		if (rmdir(cgroups->cgroup_path) == -1) {
			ERROR_ERRNO("Could not remove cgroup for container %s", container_get_description(cgroups->container));
		}
		INFO("Successfully removed cgroup for container %s", container_get_description(cgroups->container));
	}
}

