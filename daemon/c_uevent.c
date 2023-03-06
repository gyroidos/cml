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

#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define MOD_NAME "c_uevent"

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/event.h"
#include "common/file.h"
#include "common/uuid.h"
#include "common/uevent.h"

#include "container.h"

#include <unistd.h>
#include <libgen.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>

#define C_UEVENT_AUTO_MOUNT_RETRIES 10

typedef struct c_uevent {
	container_t *container;
	uevent_uev_t *uev;
	event_inotify_t *inotify_dev;
} c_uevent_t;

static int
c_uevent_create_device_node(c_uevent_t *uevent, char *path, int major, int minor,
			    const char *devtype)
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
	mode_t mode =
		(!strcmp(devtype, "disk") && !strcmp(devtype, "partition")) ? S_IFCHR : S_IFBLK;
	INFO("Creating device node (%c %d:%d) in %s", S_ISBLK(mode) ? 'b' : 'c', major, minor,
	     path);
	if (mknod(path, mode, dev) < 0) {
		ERROR_ERRNO("Could not create device node");
		goto err;
	}
shift:
	if (container_shift_ids(uevent->container, path, path, NULL) < 0) {
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

struct c_uevent_mount_timer_data {
	char *path;
	container_t *container;
};

static void
c_uevent_mount_timer_cb(event_timer_t *timer, void *data)
{
	static int retries = 0;
	ASSERT(data);

	struct c_uevent_mount_timer_data *tdata = data;
	int ret = 0;

	char *fstypes[] = { "vfat", "ext4", "btrfs", "ext2", "ext3" };
	char *basename_path = mem_strdup(tdata->path);
	char *devname = basename(basename_path);
	char *mount_path = mem_printf("%s/media/external/%s",
				      container_get_rootdir(tdata->container), devname);

	if (dir_mkdir_p(mount_path, 0755)) {
		ERROR("Could not create path for external storage mount point");
		goto out;
	}

	for (int i = 0; i < 5; ++i) {
		char *mount_data = NULL;
		if (!strcmp(fstypes[i], "vfat")) {
			int uid = container_get_uid(tdata->container);
			mount_data = mem_printf("uid=%d, gid=%d", uid, uid);
		}

		ret = mount(tdata->path, mount_path, fstypes[i], MS_RELATIME, mount_data);

		if (mount_data)
			mem_free0(mount_data);

		if (ret == 0) {
			INFO("Mounting %s to %s fstype = %s in container %s!", tdata->path,
			     mount_path, fstypes[i],
			     uuid_string(container_get_uuid(tdata->container)));
			break;
		} else {
			DEBUG_ERRNO("Failed mounting %s to %s fstype = %s!", tdata->path,
				    mount_path, fstypes[i]);
		}
	}

out:
	mem_free0(basename_path);
	mem_free0(mount_path);

	IF_TRUE_RETURN(ret && retries++ < C_UEVENT_AUTO_MOUNT_RETRIES);

	retries = 0;
	mem_free0(tdata->path);
	mem_free0(tdata);

	event_remove_timer(timer);
	event_timer_free(timer);
}

static void
c_uevent_mount_watch_dev_dir_cb(const char *path, uint32_t mask, UNUSED event_inotify_t *inotify,
				void *data)
{
	ASSERT(data);
	c_uevent_t *uevent = data;

	IF_FALSE_RETURN(mask & IN_CREATE);

	struct stat dev_stat;
	mem_memset(&dev_stat, 0, sizeof(dev_stat));

	if (stat(path, &dev_stat) == -1) {
		WARN_ERRNO("Could not stat %s", path);
		return;
	}

	IF_FALSE_RETURN(S_ISBLK(dev_stat.st_mode));

	DEBUG("blk in container %s: %s (create)", container_get_description(uevent->container),
	      path);

	unsigned int major = major(dev_stat.st_rdev);
	unsigned int minor = minor(dev_stat.st_rdev);

	if (!container_is_device_allowed(uevent->container, major, minor)) {
		TRACE("skip not allowed device (%d:%d) for container %s", major, minor,
		      container_get_name(uevent->container));
		return;
	}

	// give device some time to get ready
	struct c_uevent_mount_timer_data *tdata = mem_new0(struct c_uevent_mount_timer_data, 1);
	tdata->path = mem_strdup(path);
	tdata->container = uevent->container;
	event_timer_t *e =
		event_timer_new(1000, EVENT_TIMER_REPEAT_FOREVER, c_uevent_mount_timer_cb, tdata);
	event_add_timer(e);
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
	if (synth_uuid) {
		if (uuid_equals(container_get_uuid(uevent->container), synth_uuid)) {
			TRACE("Got synth add/remove/change uevent SYNTH_UUID=%s",
			      uuid_string(synth_uuid));
			event_coldboot = uevent_event_replace_synth_uuid_new(event, "0");
			if (!event_coldboot) {
				ERROR("Failed to mask out container uuid from SYNTH_UUID in uevent");
				return;
			}
			event = event_coldboot;
			goto send;
		} else {
			TRACE("Skip coldboot event's for other conainer");
			uuid_free(synth_uuid);
			return;
		}
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

	// watch /dev for device nodes to appear in filesystem
	uevent->inotify_dev =
		event_inotify_new("/dev", IN_CREATE, &c_uevent_mount_watch_dev_dir_cb, uevent);

	return uevent;
}

static void
c_uevent_free(void *ueventp)
{
	c_uevent_t *uevent = ueventp;
	ASSERT(uevent);

	uevent_uev_free(uevent->uev);

	event_inotify_free(uevent->inotify_dev);
	uevent->inotify_dev = NULL;

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

static void
c_uevent_boot_complete_cb(container_t *container, container_callback_t *cb, void *data)
{
	ASSERT(container);
	ASSERT(cb);
	c_uevent_t *uevent = data;
	ASSERT(uevent);

	compartment_state_t state = container_get_state(container);
	if (state == COMPARTMENT_STATE_RUNNING) {
		// fixup device nodes in userns by triggering uevent forwarding of coldboot events
		if (container_has_userns(uevent->container)) {
			uevent_udev_trigger_coldboot(container_get_uuid(uevent->container),
						     c_uevent_coldboot_dev_filter_cb, uevent);
		}
		container_unregister_observer(container, cb);
	}
}

static int
c_uevent_start_child_early(void *ueventp)
{
	c_uevent_t *uevent = ueventp;
	ASSERT(uevent);

	char *mnt_media = mem_printf("%s/media", container_get_rootdir(uevent->container));

	INFO("Mounting tmpfs to %s", mnt_media);

	if (mkdir(mnt_media, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir %s", mnt_media);
		goto error;
	}

	if (mount("tmpfs", mnt_media, "tmpfs", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount %s", mnt_media);
		goto error;
	}

	if (mount(NULL, mnt_media, NULL, MS_SHARED, NULL) < 0) {
		ERROR_ERRNO("Could not apply MS_SHARED to %s", mnt_media);
		goto error;
	} else {
		DEBUG("Applied MS_SHARED to %s", mnt_media);
	}

	if (container_shift_ids(uevent->container, mnt_media, mnt_media, NULL)) {
		ERROR_ERRNO("Could not shift ids for dev on '%s'", mnt_media);
		goto error;
	}

	mem_free0(mnt_media);
	return 0;
error:
	mem_free0(mnt_media);
	return -COMPARTMENT_ERROR;
}

static int
c_uevent_start_post_exec(void *ueventp)
{
	c_uevent_t *uevent = ueventp;
	ASSERT(uevent);

	// register uevent handling for this c_uevent container submodule
	if (uevent_add_uev(uevent->uev))
		return -COMPARTMENT_ERROR;

	/* register an observer to wait for the container to be running */
	if (!container_register_observer(uevent->container, &c_uevent_boot_complete_cb, uevent)) {
		WARN("Could not register c_uevent_boot_complete observer callback for %s",
		     container_get_description(uevent->container));
	}

	/* start watching device nodes for automount */
	event_add_inotify(uevent->inotify_dev);

	return 0;
}

static int
c_uevent_stop(void *ueventp)
{
	c_uevent_t *uevent = ueventp;
	ASSERT(uevent);

	uevent_remove_uev(uevent->uev);

	event_remove_inotify(uevent->inotify_dev);

	return 0;
}

static compartment_module_t c_uevent_module = {
	.name = MOD_NAME,
	.compartment_new = c_uevent_new,
	.compartment_free = c_uevent_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = c_uevent_start_child_early,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = c_uevent_start_post_exec,
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
