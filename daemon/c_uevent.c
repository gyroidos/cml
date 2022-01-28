/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2022 Fraunhofer AISEC
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

#define MOD_NAME "c_uevent"

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/uuid.h"
#include "common/uevent.h"

#include "container.h"

#include <unistd.h>
#include <libgen.h>
#include <sys/sysmacros.h>

typedef struct c_uevent {
	container_t *container;
	uevent_uev_t *uev;
} c_uevent_t;

static int
c_uevent_create_device_node(c_uevent_t *uevent, char *path, int major, int minor, char *devtype)
{
	char *path_dirname = NULL;

	if (file_exists(path)) {
		TRACE("Node '%s' exits, just fixup uids", path);
		goto shift;
	}

	// dirname may modify original string, thus strdup
	path_dirname = mem_strdup(path);
	if (dir_mkdir_p(dirname(path_dirname), 0755) < 0) {
		ERROR("Could not create path for device node");
		goto err;
	}
	dev_t dev = makedev(major, minor);
	mode_t mode = strcmp(devtype, "disk") ? S_IFCHR : S_IFBLK;
	INFO("Creating device node (%c %d:%d) in %s", S_ISBLK(mode) ? 'd' : 'c', major, minor,
	     path);
	if (mknod(path, mode, dev) < 0) {
		ERROR_ERRNO("Could not create device node");
		goto err;
	}
shift:
	if (container_shift_ids(uevent->container, path, false) < 0) {
		ERROR("Failed to fixup uids for '%s' in usernamspace of container %s", path,
		      container_get_name(uevent->container));
		goto err;
	}
	mem_free0(path_dirname);
	return 0;
err:
	mem_free0(path_dirname);
	return -1;
}

static void
c_uevent_handle_event_cb(unsigned actions, uevent_event_t *event, void *data)
{
	c_uevent_t *uevent = data;
	ASSERT(uevent);

	uevent_event_t *event_coldboot = NULL;
	char *devname = NULL;

	int major = uevent_event_get_major(event);
	int minor = uevent_event_get_minor(event);

	if (!container_is_device_allowed(uevent->container, major, minor)) {
		TRACE("skip not allowed device (%d:%d) for container %s", major, minor,
		      container_get_name(uevent->container));
		return;
	}

	/* handle coldboot events just for target container */
	uuid_t *synth_uuid = uuid_new(uevent_event_get_synth_uuid(event));
	if (uuid_equals(container_get_uuid(uevent->container), synth_uuid)) {
		TRACE("Got synth add/remove/change uevent SYNTH_UUID=%s", uuid_string(synth_uuid));
		event_coldboot = uevent_event_replace_synth_uuid_new(event, "0");
		if (!event_coldboot) {
			ERROR("Failed to mask out container uuid from SYNTH_UUID in uevent");
			return;
		}
		event = event_coldboot;
		goto send;
	}

	// newer versions of udev prepends '/dev/' in DEVNAME
	devname = mem_printf("%s%s%s", container_get_rootdir(uevent->container),
			     strncmp("/dev/", uevent_event_get_devname(event), 4) ? "/dev/" : "",
			     uevent_event_get_devname(event));

	if (actions & UEVENT_ACTION_ADD) {
		if (c_uevent_create_device_node(uevent, devname, major, minor,
						uevent_event_get_devtype(event)) < 0) {
			ERROR("Could not create device node");
			mem_free0(devname);
			return;
		}
	} else if (actions & UEVENT_ACTION_REMOVE) {
		if (unlink(devname) < 0 && errno != ENOENT) {
			WARN_ERRNO("Could not remove device node");
		}
	}

send:
	if (uevent_event_inject_into_netns(event, container_get_pid(uevent->container),
					   container_has_userns(uevent->container)) < 0) {
		WARN("Could not inject uevent into netns of container %s!",
		     container_get_name(uevent->container));
	} else {
		TRACE("Sucessfully injected uevent into netns of container %s!",
		      container_get_name(uevent->container));
	}

	if (devname)
		mem_free0(devname);
	if (event_coldboot)
		mem_free0(event_coldboot);
}

static void *
c_uevent_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_uevent_t *uevent = mem_new0(c_uevent_t, 1);
	uevent->container = compartment_get_extension_data(compartment);

	uevent->uev =
		uevent_uev_new(UEVENT_UEV_TYPE_KERNEL,
			       UEVENT_ACTION_ADD | UEVENT_ACTION_CHANGE | UEVENT_ACTION_REMOVE,
			       c_uevent_handle_event_cb, uevent);

	return uevent;
}

static void
c_uevent_free(void *ueventp)
{
	c_uevent_t *uevent = ueventp;
	ASSERT(uevent);

	uevent_uev_free(uevent->uev);
	mem_free0(uevent);
}

static bool
c_uevent_coldboot_dev_filter_cb(int major, int minor, void *data)
{
	c_uevent_t *uevent = data;
	ASSERT(uevent);

	if (!container_is_device_allowed(uevent->container, major, minor)) {
		TRACE("filter coldboot uevent for device (%d:%d)", major, minor);
		return false;
	}

	return true;
}

static int
c_uevent_start_post_exec(void *ueventp)
{
	c_uevent_t *uevent = ueventp;
	ASSERT(uevent);

	// register uevent handling for this c_uevent container submodule
	if (uevent_add_uev(uevent->uev))
		return -COMPARTMENT_ERROR;

	// fixup device nodes in userns by triggering uevent forwarding of coldboot events
	if (container_has_userns(uevent->container)) {
		uevent_udev_trigger_coldboot(container_get_uuid(uevent->container),
					     c_uevent_coldboot_dev_filter_cb, uevent);
	}

	return 0;
}

static int
c_uevent_stop(void *ueventp)
{
	c_uevent_t *uevent = ueventp;
	ASSERT(uevent);

	uevent_remove_uev(uevent->uev);
	return 0;
}

static compartment_module_t c_uevent_module = {
	.name = MOD_NAME,
	.compartment_new = c_uevent_new,
	.compartment_free = c_uevent_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = c_uevent_start_post_exec,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = c_uevent_stop,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
c_uevent_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_uevent_module);
}
