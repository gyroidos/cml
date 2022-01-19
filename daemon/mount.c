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

#define _GNU_SOURCE
#include <sched.h>

#include "mount.h"
#include "crypto.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/list.h"
#include "common/file.h"

#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

struct mount {
	list_t *list; /**< list of mount entries */
};

struct mount_entry {
	enum mount_type type; /**< type of the image file */
	char *image_file;     /**< image name without suffix, e.g. "system" */
	char *mount_point; /**< directory where to mount the image inside the container, e.g. /system */
	char *fs_type;	   /**< file system type of the mount, e.g. ext4 */
	uint64_t default_size; /**< default size for EMPTY images */
	uint64_t image_size;   /**< size overwriting default_size */
	// TODO: add list of hash, min/max size for EMPTY images, etc.
	char *sha1;
	char *sha256;
	char *mount_data; /**< mount_data to use for mount syscall e.g. "uid=1000,gid=1000,dmask=227,fmask=337,context=u:object_r:firmware_file:s0" */
};

mount_t *
mount_new(void)
{
	return mem_new0(mount_t, 1);
}

mount_entry_t *
mount_add_entry(mount_t *mnt, enum mount_type type, const char *image_file, const char *mount_point,
		const char *fs_type, uint64_t default_size)
{
	ASSERT(mnt);

	mount_entry_t *mntent = mem_new(mount_entry_t, 1);

	mntent->type = type;
	mntent->image_file = mem_strdup(image_file);
	mntent->mount_point = mem_strdup(mount_point);
	mntent->fs_type = mem_strdup(fs_type);
	mntent->default_size = default_size;
	mntent->image_size = 0;
	mntent->sha1 = NULL;
	mntent->sha256 = NULL;
	mntent->mount_data = NULL;

	mnt->list = list_append(mnt->list, mntent);
	return mntent;
}

void
mount_free(mount_t *mnt)
{
	IF_NULL_RETURN(mnt);

	while (mnt->list) {
		mount_entry_t *mntent = mnt->list->data;
		ASSERT(mntent);
		// free mandatory/required fields
		mem_free0(mntent->image_file);
		mem_free0(mntent->mount_point);
		mem_free0(mntent->fs_type);
		// free optional fields
		if (mntent->sha1)
			mem_free0(mntent->sha1);
		if (mntent->sha256)
			mem_free0(mntent->sha256);
		if (mntent->mount_data)
			mem_free0(mntent->mount_data);
		mem_free0(mntent);
		mnt->list = list_unlink(mnt->list, mnt->list);
	}

	mem_free0(mnt);
}

size_t
mount_get_count(const mount_t *mnt)
{
	ASSERT(mnt);

	return list_length(mnt->list);
}

mount_entry_t *
mount_get_entry(const mount_t *mnt, size_t idx)
{
	ASSERT(mnt);

	return list_nth_data(mnt->list, idx);
}

mount_entry_t *
mount_get_entry_by_img(const mount_t *mnt, const char *img)
{
	ASSERT(mnt);

	for (list_t *l = mnt->list; l; l = l->next) {
		mount_entry_t *mntent = l->data;
		ASSERT(mntent);
		if (!strcmp(img, mntent->image_file))
			return mntent;
	}

	return NULL;
}

/******************************************************************************/

enum mount_type
mount_entry_get_type(const mount_entry_t *mntent)
{
	ASSERT(mntent);
	return mntent->type;
}

const char *
mount_entry_get_img(const mount_entry_t *mntent)
{
	ASSERT(mntent);
	return mntent->image_file;
}

void
mount_entry_set_img(mount_entry_t *mntent, char *image_name)
{
	ASSERT(mntent);
	IF_NULL_RETURN(image_name);
	if (mntent->image_file)
		mem_free0(mntent->image_file);
	mntent->image_file = mem_strdup(image_name);
}

const char *
mount_entry_get_dir(const mount_entry_t *mntent)
{
	ASSERT(mntent);
	return mntent->mount_point;
}

const char *
mount_entry_get_fs(const mount_entry_t *mntent)
{
	ASSERT(mntent);
	return mntent->fs_type;
}

uint64_t
mount_entry_get_size(const mount_entry_t *mntent)
{
	ASSERT(mntent);
	return mntent->image_size ? mntent->image_size : mntent->default_size;
}

void
mount_entry_set_size(mount_entry_t *mntent, uint64_t size)
{
	ASSERT(mntent);
	mntent->image_size = size;
}

char *
mount_entry_get_sha1(const mount_entry_t *mntent)
{
	ASSERT(mntent);
	return mntent->sha1;
}

char *
mount_entry_get_sha256(const mount_entry_t *mntent)
{
	ASSERT(mntent);
	return mntent->sha256;
}

void
mount_entry_set_sha1(mount_entry_t *mntent, char *sha1)
{
	ASSERT(mntent);
	IF_NULL_RETURN(sha1);
	mntent->sha1 = mem_strdup(sha1);
}

void
mount_entry_set_sha256(mount_entry_t *mntent, char *sha256)
{
	ASSERT(mntent);
	IF_NULL_RETURN(sha256);
	mntent->sha256 = mem_strdup(sha256);
}

void
mount_entry_set_mount_data(mount_entry_t *mntent, char *mount_data)
{
	ASSERT(mntent);
	IF_NULL_RETURN(mount_data);
	mntent->mount_data = mem_strdup(mount_data);
}

char *
mount_entry_get_mount_data(const mount_entry_t *mntent)
{
	ASSERT(mntent);
	return mntent->mount_data;
}

bool
mount_entry_match_sha1(const mount_entry_t *e, const char *hash)
{
	ASSERT(e);

	const char *img_name = mount_entry_get_img(e);
	const char *expected = mount_entry_get_sha1(e);

	DEBUG("Checking image %s.img with expected SHA1 hash %s, actual hash: %s", img_name,
	      expected, hash);
	return crypto_match_hash(20, expected, hash);
}

bool
mount_entry_match_sha256(const mount_entry_t *e, const char *hash)
{
	ASSERT(e);

	const char *img_name = mount_entry_get_img(e);
	const char *expected = mount_entry_get_sha256(e);
	DEBUG("Checking image %s.img with expected SHA256 hash %s, actual hash: %s", img_name,
	      expected, hash);
	return crypto_match_hash(32, expected, hash);
}

bool
mount_entry_is_encrypted(const mount_entry_t *e)
{
	ASSERT(e);

	switch (e->type) {
	case MOUNT_TYPE_EMPTY:
		return strncmp(e->fs_type, "tmpfs", 5);
	case MOUNT_TYPE_OVERLAY_RW:
		return true;
	default:
		return false;
	}
}

int
mount_remount_root_ro(void)
{
	DEBUG("Remounting rootfs readonly");
	int ret = mount("none", "/", "none", MS_REMOUNT | MS_RDONLY, NULL);
	if (ret < 0)
		ERROR_ERRNO("Could not remount rootfs as readonly");
	return ret;
}

int
mount_debugfs(void)
{
	DEBUG("Mounting /sys/kernel/debugfs");
	int ret = mount("none", "/sys/kernel/debug/", "debugfs", MS_RELATIME | MS_NOSUID, NULL);
	if (ret < 0)
		WARN_ERRNO("Could not mount debugfs");
	return ret;
}

int
mount_private_tmp(void)
{
	if (unshare(CLONE_NEWNS)) {
		ERROR_ERRNO("Could not unshare host mount ns!");
		return -1;
	}
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
		ERROR_ERRNO("Could not mount / MS_PRIVATE");
		return -1;
	}
	if (file_is_mountpoint("/tmp")) {
		if (umount("/tmp") < 0 && errno != ENOENT) {
			ERROR_ERRNO("Could not umount /tmp");
			return -1;
		}
	}
	if (mount("tmpfs", "/tmp", "tmpfs", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount /tmp");
		return -1;
	}

	list_t *system_mnts = NULL;
	system_mnts = list_append(system_mnts, "/sys");
	system_mnts = list_append(system_mnts, "/proc");
	system_mnts = list_append(system_mnts, "/dev");
	system_mnts = list_append(system_mnts, "/tmp");

	for (list_t *l = system_mnts; l; l = l->next) {
		char *mnt = l->data;
		if (file_is_mountpoint(mnt)) {
			if (mount(NULL, mnt, NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
				ERROR_ERRNO("Could not mount %s MS_PRIVATE", mnt);
				list_delete(system_mnts);
				return -1;
			}
			TRACE("Succesfully set MS_PRIVATE on mount '%s'", mnt);
		}
	}
	list_delete(system_mnts);

	return 0;
}

static int
mount_cgroups_create_and_mount_subsys(const char *subsys, const char *mount_path)
{
	int ret = 0;
	if (!file_is_mountpoint(mount_path)) {
		if (mkdir(mount_path, 0755) && errno != EEXIST) {
			ERROR_ERRNO("Could not create cgroup subsys directory %s", mount_path);
			return -1;
		}

		INFO("Mounting cgroups subsystems %s", subsys);
		ret = mount("cgroup", mount_path, "cgroup",
			    MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME, subsys);
		if (ret == -1) {
			if (errno == EBUSY) {
				INFO("cgroup %s already mounted", subsys);
				ret = 0;
			} else {
				ERROR_ERRNO("Error mounting cgroups subsystems %s", subsys);
				return -1;
			}
		}
	}
	if (!strcmp(subsys, "memory")) {
		char *use_hierarchy = mem_printf("%s/memory.use_hierarchy", mount_path);
		if (file_printf(use_hierarchy, "1") < 0)
			WARN_ERRNO("Cloning default setting to child cgroups failes!");
		mem_free0(use_hierarchy);
	}
	if (strcmp(subsys, "devices")) {
		char *cgroup_clone_children = mem_printf("%s/cgroup.clone_children", mount_path);
		if (file_printf(cgroup_clone_children, "1") < 0)
			WARN_ERRNO("Cloning default setting to child cgroups failes!");
		mem_free0(cgroup_clone_children);
	}
	return ret;
}

int
mount_cgroups(list_t *cgroups_subsystems)
{
	// mount cgroups control stuff if not already done (necessary globally once)
	// tmpfs does not always result in EBUSY if already mounted
	if (!file_is_mountpoint(MOUNT_CGROUPS_FOLDER)) {
		INFO("Mounting cgroups tmpfs");
		if (mkdir(MOUNT_CGROUPS_FOLDER, 0755) && errno != EEXIST) {
			ERROR_ERRNO("Could not create cgroup mount directory");
			return -1;
		}
		if (mount("cgroup", MOUNT_CGROUPS_FOLDER, "tmpfs",
			  MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME, "mode=755") == -1 &&
		    errno != EBUSY) {
			ERROR_ERRNO("Could not mount tmpfs for cgroups");
			return -1;
		}
	}

	for (list_t *l = cgroups_subsystems; l; l = l->next) {
		char *subsys = l->data;
		char *mount_path = mem_printf("%s/%s", MOUNT_CGROUPS_FOLDER, subsys);
		if (mount_cgroups_create_and_mount_subsys(subsys, mount_path) < 0) {
			ERROR("Failed to mount cgroups to %s", mount_path);
			mem_free0(mount_path);
			goto error;
		}
		mem_free0(mount_path);
	}

	// create a named hierarchy for systemd containers
	if (mount_cgroups_create_and_mount_subsys("none,name=systemd",
						  MOUNT_CGROUPS_FOLDER "/systemd") < 0) {
		ERROR("Failed to mount cgroups to %s/systemd", MOUNT_CGROUPS_FOLDER);
		goto error;
	}

	INFO("cgroups created successfully");
	return 0;

error:
	for (list_t *l = cgroups_subsystems; l; l = l->next) {
		char *subsys = l->data;
		char *subsys_path = mem_printf("%s/%s", MOUNT_CGROUPS_FOLDER, subsys);
		umount(subsys_path);
		mem_free0(subsys_path);
	}
	umount(MOUNT_CGROUPS_FOLDER "/systemd");
	umount(MOUNT_CGROUPS_FOLDER);
	return -1;
}
