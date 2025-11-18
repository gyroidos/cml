/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#ifndef MOUNT_H
#define MOUNT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>

#include "common/list.h"

#define MOUNT_CGROUPS_FOLDER "/sys/fs/cgroup"

#define MOUNT_DM_INTEGRITY_META_FACTOR 0.1

/**
 * A structure to present an operating system partition table for a container.
 */
typedef struct mount mount_t;

/**
 * A structure to present an operating system mount table entry.
 */
typedef struct mount_entry mount_entry_t;

/**
 * An enum to present the type of mountable image files for operating systems.
 */
enum mount_type {
	MOUNT_TYPE_SHARED =
		1, /**< image file is shared by all containers of the operating system type */
	MOUNT_TYPE_DEVICE = 2,	  /**< image file is copied from a device partition */
	MOUNT_TYPE_DEVICE_RW = 3, /**< image file is copied from a device partition */
	MOUNT_TYPE_EMPTY = 4, /**< image file is generated on container start if not available */
	MOUNT_TYPE_COPY = 5,  // TODO: remove
	MOUNT_TYPE_FLASH = 6, ///< image to be flashed to a partition
	MOUNT_TYPE_OVERLAY_RO = 7,    /**< image file that contains features e.g.
				      gps, camera ... as overly for system */
	MOUNT_TYPE_SHARED_RW = 8,     /**< image file is shared by all containers of the operating
				      system type and an individual writable tmpfs is mounted
				      as overlay to each container */
	MOUNT_TYPE_OVERLAY_RW = 9,    /**< image file is shared by all containers of the operating
				      system type and an individual writable persitent fs is mounted
				      as overlay to each container */
	MOUNT_TYPE_BIND_FILE = 10,    /**< file is bind mounted to container (RO) */
	MOUNT_TYPE_BIND_FILE_RW = 11, /**< file is bind mounted to container (RW) */
	MOUNT_TYPE_BIND_DIR = 12,     /**< dir is bind mounted to container (RO) */
	MOUNT_TYPE_BIND_DIR_RW = 13,  /**< dir is bind mounted to container (RW) */
	MOUNT_TYPE_STORE_ONLY = 14,   /**< image is only held in guestos store */
};

mount_t *
mount_new(void);

/**
 * Adds a new mount entry to the mount_t instance.
 * @param mnt the mount_t instance to which to add the new mount entry
 * @param type the mount type of the mount entry
 * @param image_file the image name of the mount entry
 * @param mount_point the mount point ("directory") of the mount entry
 * @param fs_type the file system type of the mount entry
 * @param default_size the default size of the image of the mount entry
 * @return pointer to the newly added mount entry
 */
mount_entry_t *
mount_add_entry(mount_t *mnt, enum mount_type type, const char *image_file, const char *mount_point,
		const char *fs_type, uint64_t default_size);

/**
 * Frees the mount_t instance.
 */
void
mount_free(mount_t *mnt);

/**
 * Returns the number of mount entries in the mount_t instance.
 */
size_t
mount_get_count(const mount_t *mnt);

/**
 * Returns the i-th mount entry in the mount_t instance.
 */
mount_entry_t *
mount_get_entry(const mount_t *mnt, size_t i);

/**
 * Gets the mount entry with the given image name.
 */
mount_entry_t *
mount_get_entry_by_img(const mount_t *mnt, const char *img);

/**
 * Calculate the max disk usage of a given container mount table
 * 
 * @param mnt the mount table
 * @return Success: required disk space, Error: -1
*/
off_t
mount_get_disk_usage_container(const mount_t *mnt);

/**
 * Calculate the max disk usage of a given guestos mount table
 * 
 * @param mnt the mount table
 * @return Success: required disk space, Error: -1
*/
off_t
mount_get_disk_usage_guestos(const mount_t *mnt);

/**
 * Sets the size of the image of the mount entry.
 */
void
mount_entry_set_size(mount_entry_t *mntent, uint64_t size);

/**
 * Returns a string with the SHA1 hash of the mount entry.
 */
char *
mount_entry_get_sha1(const mount_entry_t *mntent);

/**
 * Returns a string with the SHA256 hash of the mount entry.
 */
char *
mount_entry_get_sha256(const mount_entry_t *mntent);

char *
mount_entry_get_verity_sha256(const mount_entry_t *mntent);

/**
 * Sets the SHA1 hash for the mount entry.
 */
void
mount_entry_set_sha1(mount_entry_t *mntent, char *sha1);

/**
 * Sets the SHA256 hash for the mount entry.
 */
void
mount_entry_set_sha256(mount_entry_t *mntent, char *sha256);

void
mount_entry_set_verity_sha256(mount_entry_t *mntent, char *sha256);

/**
 * Checks if the given SHA1 hash matches with the one stored in the mount entry.
 */
bool
mount_entry_match_sha1(const mount_entry_t *e, const char *hash);

/**
 * Checks if the given SHA256 hash matches with the one stored in the mount entry.
 */
bool
mount_entry_match_sha256(const mount_entry_t *e, const char *hash);

/**
 * Returns the type of the mount entry.
 */
enum mount_type
mount_entry_get_type(const mount_entry_t *mntent);

/**
 * Returns a string with the image name of the mount entry.
 */
const char *
mount_entry_get_img(const mount_entry_t *mntent);

/**
 * Updates the image name of the mount entry.
 */
void
mount_entry_set_img(mount_entry_t *mntent, char *image_name);

/**
 * Returns the "directory" (i.e. the mount point) of the mount entry.
 */
const char *
mount_entry_get_dir(const mount_entry_t *mntent);

/**
 * Returns a string with the file system type of the mount entry.
 */
const char *
mount_entry_get_fs(const mount_entry_t *mntent);

/**
 * Returns the size of the image of the mount entry.
 */
uint64_t
mount_entry_get_size(const mount_entry_t *mntent);

/**
  * Sets the mount_data used for mounting the mount entry
  */
void
mount_entry_set_mount_data(mount_entry_t *mntent, char *mount_data);

/**
 * Gets the mount_data of the mount entry
 */
char *
mount_entry_get_mount_data(const mount_entry_t *mntent);

/**
 * returns if a mount entry iuses encryption
 */
bool
mount_entry_is_encrypted(const mount_entry_t *mntent);

/**
 * Remounts rootfs read-only
 */
int
mount_remount_root_ro(void);

/**
 * Mounts kernel debugfs
 */
int
mount_debugfs(void);

/**
 * Mounts a tmpfs for container setup privatly for cmld
 *
 * This hides the cmld's view of container mounts from processes
 * in the rest of the CML, e.g., s shell process for debugging and
 * adminstration.
 */
int
mount_private_tmp(void);

/**
 * Mount cgroups fs and subsystem controllers if not already done
 *
 * This is necessary globally once, and also before lxcfs_init()
 * @param cgroups_subsystems a list of subsystems to be mounted/created
 * @return 0 on success, -1 on error
 */
int
mount_cgroups(list_t *cgroups_subsystems);

#endif /* MOUNT_H */
