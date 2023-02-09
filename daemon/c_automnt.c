/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2023 Fraunhofer AISEC
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

#define _GNU_SOURCE
#include "c_automnt.h"
#include "cmld.h"
#include "container.h"
#include "audit.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/ns.h"
#include "common/uuid.h"
#include "common/str.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/file.h"

#include <unistd.h>
#include <libgen.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>

#define C_UEVENT_AUTO_MOUNT_RETRIES 10

struct c_automnt {
	container_t *container;
	event_inotify_t *inotify_dev;
};

struct c_automnt_mount_timer_data {
	char *path;
	container_t *container;
};

static void
c_automnt_mount_timer_cb(event_timer_t *timer, void *data)
{
	static int retries = 0;
	ASSERT(data);

	struct c_automnt_mount_timer_data *tdata = data;
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
			mount_data = mem_printf("uid=%d,gid=%d", uid, uid);
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
c_automnt_mount_watch_dev_dir_cb(const char *path, uint32_t mask, UNUSED event_inotify_t *inotify,
				 void *data)
{
	ASSERT(data);
	c_automnt_t *automnt = data;

	IF_FALSE_RETURN(mask & IN_CREATE);

	struct stat dev_stat;
	mem_memset(&dev_stat, 0, sizeof(dev_stat));

	if (stat(path, &dev_stat) == -1) {
		WARN_ERRNO("Could not stat %s", path);
		return;
	}

	IF_FALSE_RETURN(S_ISBLK(dev_stat.st_mode));

	DEBUG("blk in container %s: %s (create)", container_get_description(automnt->container),
	      path);

	unsigned int major = major(dev_stat.st_rdev);
	unsigned int minor = minor(dev_stat.st_rdev);

	if (!container_is_device_allowed(automnt->container, major, minor)) {
		TRACE("skip not allowed device (%d:%d) for container %s", major, minor,
		      container_get_name(automnt->container));
		return;
	}

	// give device some time to get ready
	struct c_automnt_mount_timer_data *tdata = mem_new0(struct c_automnt_mount_timer_data, 1);
	tdata->path = mem_strdup(path);
	tdata->container = automnt->container;
	event_timer_t *e =
		event_timer_new(1000, EVENT_TIMER_REPEAT_FOREVER, c_automnt_mount_timer_cb, tdata);
	event_add_timer(e);
}

c_automnt_t *
c_automnt_new(container_t *container)
{
	ASSERT(container);

	c_automnt_t *automnt = mem_new0(c_automnt_t, 1);

	automnt->container = container;

	// watch /dev for device nodes to appear in filesystem
	automnt->inotify_dev =
		event_inotify_new("/dev", IN_CREATE, &c_automnt_mount_watch_dev_dir_cb, automnt);

	return automnt;
}

void
c_automnt_free(c_automnt_t *automnt)
{
	ASSERT(automnt);
	mem_free0(automnt);
}

int
c_automnt_start_child_early(c_automnt_t *automnt)
{
	ASSERT(automnt);

	char *mnt_media = mem_printf("%s/media", container_get_rootdir(automnt->container));

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

	if (container_shift_ids(automnt->container, mnt_media, false)) {
		ERROR_ERRNO("Could not shift ids for dev on '%s'", mnt_media);
		goto error;
	}

	mem_free0(mnt_media);
	return 0;
error:
	mem_free0(mnt_media);
	return -CONTAINER_ERROR;
}

int
c_automnt_start_post_exec(c_automnt_t *automnt)
{
	ASSERT(automnt);

	INFO("Registering inotify on %s", container_get_rootdir(automnt->container));

	/* start watching device nodes for automount */
	event_add_inotify(automnt->inotify_dev);

	return 0;
}

void
c_automnt_cleanup(void *automntp)
{
	ASSERT(automntp);
	c_automnt_t *automnt = (c_automnt_t *)automntp;

	INFO("Removing inotify on %s", container_get_rootdir(automnt->container));

	event_remove_inotify(automnt->inotify_dev);

	return;
}
