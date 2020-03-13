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

#include "common/macro.h"
#include "common/mem.h"
#include "common/list.h"

#include <string.h>
#include <sys/mount.h>
#include <errno.h>

struct mount {
	list_t *list; /**< list of mount entries */
};

struct mount_entry {
	enum mount_type type; /**< type of the image file */
	char *image_file;     /**< image name without suffix, e.g. "system" */
	char *mount_point; /**< directory where to mount the image inside the container, e.g. /system */
	char *fs_type;     /**< file system type of the mount, e.g. ext4 */
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
		mem_free(mntent->image_file);
		mem_free(mntent->mount_point);
		mem_free(mntent->fs_type);
		mem_free(mntent->sha1);
		mem_free(mntent->sha256);
		mem_free(mntent->mount_data);
		mnt->list = list_unlink(mnt->list, mnt->list);
	}

	mem_free(mnt);
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
		mem_free(mntent->image_file);
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

static bool
match_hash(const char *hash_name, size_t hash_len, const char *img_name, const char *expected_hash,
	   const char *hash)
{
	ASSERT(hash_name);
	ASSERT(img_name);

	if (!hash) {
		ERROR("Checking image %s.img with %s: empty hash value", img_name, hash_name);
		return false;
	}
	if (!expected_hash) {
		ERROR("Checking image %s.img with %s: reference hash value for image is missing",
		      img_name, hash_name);
		return false;
	}
	size_t len = strlen(expected_hash);
	if (len != 2 * hash_len) {
		ERROR("Checking image %s.img with %s: invalid hash length %zu/2, expected %zu/2 bytes",
		      img_name, hash_name, len, 2 * hash_len);
		return false;
	}
	if (strncasecmp(expected_hash, hash, len + 1)) {
		DEBUG("Checking image %s.img with %s: hash mismatch", img_name, hash_name);
		return false;
	}
	DEBUG("Checking image %s.img with %s: hashes match", img_name, hash_name);
	return true;
}

bool
mount_entry_match_sha1(const mount_entry_t *e, const char *hash)
{
	ASSERT(e);

	const char *img_name = mount_entry_get_img(e);
	const char *expected = mount_entry_get_sha1(e);
	return match_hash("SHA1", 20, img_name, expected, hash);
}

bool
mount_entry_match_sha256(const mount_entry_t *e, const char *hash)
{
	ASSERT(e);

	const char *img_name = mount_entry_get_img(e);
	const char *expected = mount_entry_get_sha256(e);
	return match_hash("SHA256", 32, img_name, expected, hash);
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
		FATAL_ERRNO("Could not remount rootfs as readonly");
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
	if (umount("/tmp") < 0 && errno != ENOENT) {
		ERROR_ERRNO("Could not umount /tmp");
		return -1;
	}
	if (mount("tmpfs", "/tmp", "tmpfs", MS_RELATIME | MS_NOSUID | MS_NODEV, NULL) < 0) {
		ERROR_ERRNO("Could not mount /tmp");
		return -1;
	}
	return 0;
}
