/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2024 Fraunhofer AISEC
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

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define MOD_NAME "c_automount"

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/event.h"
#include "common/file.h"

#include "container.h"

#include <unistd.h>
#include <libgen.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>

#define C_AUTOMOUNT_MOUNT_RETRIES 10

typedef struct c_automount {
	container_t *container;
	event_inotify_t *inotify_dev;
} c_automount_t;

struct c_automount_mount_timer_data {
	char *path;
	container_t *container;
};

static void
c_automount_mount_timer_cb(event_timer_t *timer, void *data)
{
	static int retries = 0;
	ASSERT(data);

	struct c_automount_mount_timer_data *tdata = data;
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

	IF_TRUE_RETURN(ret && retries++ < C_AUTOMOUNT_MOUNT_RETRIES);

	retries = 0;
	mem_free0(tdata->path);
	mem_free0(tdata);

	event_remove_timer(timer);
	event_timer_free(timer);
}

static void
c_automount_mount_watch_dev_dir_cb(const char *path, uint32_t mask, UNUSED event_inotify_t *inotify,
				   void *data)
{
	ASSERT(data);
	c_automount_t *automount = data;

	IF_FALSE_RETURN(mask & IN_CREATE);

	struct stat dev_stat;
	mem_memset(&dev_stat, 0, sizeof(dev_stat));

	if (stat(path, &dev_stat) == -1) {
		WARN_ERRNO("Could not stat %s", path);
		return;
	}

	IF_FALSE_RETURN(S_ISBLK(dev_stat.st_mode));

	DEBUG("blk in container %s: %s (create)", container_get_description(automount->container),
	      path);

	char type;
	if (S_ISBLK(dev_stat.st_mode)) {
		type = 'b';
	} else if (S_ISCHR(dev_stat.st_mode)) {
		type = 'c';
	} else {
		return;
	}

	unsigned int major = major(dev_stat.st_rdev);
	unsigned int minor = minor(dev_stat.st_rdev);

	if (!container_is_device_allowed(automount->container, type, major, minor)) {
		TRACE("skip not allowed device (%c %d:%d) for container %s", type, major, minor,
		      container_get_name(automount->container));
		return;
	}

	// give device some time to get ready
	struct c_automount_mount_timer_data *tdata =
		mem_new0(struct c_automount_mount_timer_data, 1);
	tdata->path = mem_strdup(path);
	tdata->container = automount->container;
	event_timer_t *e = event_timer_new(1000, EVENT_TIMER_REPEAT_FOREVER,
					   c_automount_mount_timer_cb, tdata);
	event_add_timer(e);
}

static void *
c_automount_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_automount_t *automount = mem_new0(c_automount_t, 1);
	automount->container = compartment_get_extension_data(compartment);

	// watch /dev for device nodes to appear in filesystem
	automount->inotify_dev = event_inotify_new("/dev", IN_CREATE,
						   &c_automount_mount_watch_dev_dir_cb, automount);

	return automount;
}

static void
c_automount_free(void *automountp)
{
	c_automount_t *automount = automountp;
	ASSERT(automount);

	event_inotify_free(automount->inotify_dev);
	automount->inotify_dev = NULL;

	mem_free0(automount);
}

static int
c_automount_start_child_early(void *automountp)
{
	c_automount_t *automount = automountp;
	ASSERT(automount);

	char *mnt_media = mem_printf("%s/media", container_get_rootdir(automount->container));

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

	if (container_shift_ids(automount->container, mnt_media, mnt_media, NULL)) {
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
c_automount_start_post_exec(void *automountp)
{
	c_automount_t *automount = automountp;
	ASSERT(automount);

	/* start watching device nodes for automount */
	int error = event_add_inotify(automount->inotify_dev);
	if (error && error != -EEXIST) {
		ERROR("Could not register inotify event for automount events!");
		return -COMPARTMENT_ERROR;
	}

	return 0;
}

static int
c_automount_stop(void *automountp)
{
	c_automount_t *automount = automountp;
	ASSERT(automount);

	event_remove_inotify(automount->inotify_dev);

	return 0;
}

static void
c_automount_cleanup(void *automountp, UNUSED bool rebooting)
{
	c_automount_t *automount = automountp;
	ASSERT(automount);

	char *mnt_media = mem_printf("%s/media", container_get_rootdir(automount->container));
	if (umount(mnt_media) < 0)
		WARN_ERRNO("Could not umount %s", mnt_media);

	mem_free0(mnt_media);
}

static compartment_module_t c_automount_module = {
	.name = MOD_NAME,
	.compartment_new = c_automount_new,
	.compartment_free = c_automount_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = c_automount_start_child_early,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = c_automount_start_post_exec,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = c_automount_stop,
	.cleanup = c_automount_cleanup,
	.join_ns = NULL,
};

static void INIT
c_automount_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_automount_module);
}
