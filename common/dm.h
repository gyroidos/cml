/*
 * This file is part of trust|me
 * Copyright(c) 2022 Fraunhofer AISEC
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

#ifndef DM_H
#define DM_H

#include <linux/dm-ioctl.h>

#define DM_NAME_LEN 128
#define DM_UUID_LEN 129

#define DM_EXISTS_FLAG 0x00000004

#ifdef ANDROID
#define DM_CONTROL "/dev/device-mapper"
#define DM_PATH_PREFIX "/dev/block/dm-"
#else
#define DM_CONTROL "/dev/mapper/control"
#define DM_PATH_PREFIX "/dev/mapper/"
#endif

enum dm_cmd_index {
	INDEX_DM_DEV_CREATE,
	INDEX_DM_TABLE_LOAD,
	INDEX_DM_DEV_REMOVE,
	INDEX_DM_REMOVE_ALL,
	// Suspend is also used for resume
	INDEX_DM_DEV_SUSPEND,
	INDEX_DM_DEV_STATUS,
	INDEX_DM_TABLE_DEPS,
	INDEX_DM_DEV_RENAME,
	INDEX_DM_VERSION,
	INDEX_DM_TABLE_STATUS,
	INDEX_DM_DEV_WAIT,
	INDEX_DM_LIST_DEVICES,
	INDEX_DM_TABLE_CLEAR,
	INDEX_DM_LIST_VERSIONS,
	INDEX_DM_TARGET_MSG,
	INDEX_DM_DEV_SET_GEOMETRY,
	INDEX_DM_DEV_ARM_POLL,
	INDEX_DM_GET_TARGET_VERSION
};

struct dm_cmd_table {
	const unsigned cmd;
	const int version[3];
};

#ifdef __GNU_LIBRARY__
#define dm_ioctl(...) ioctl(__VA_ARGS__)
#else
/*
 * non glibc std libraries such as musl provide ioctl (int, int, ...)
 * wrapper. However, dm integrity requests are 'unsigned long int' and
 * would overflow on a cast to int. Thus, we directly provide a wrapper
 * here instead of using the ioctl wrapper of the std library.
 */
int
dm_ioctl(int fd, unsigned long int request, ...);
#endif

/**
 * Initializes the device-mapper ioctl data structure dm_ioctl
 * whith its parameters. See linux/dm-ioctl.h for details of the
 * struct parameters
 */
int
dm_ioctl_init(struct dm_ioctl *io, enum dm_cmd_index idx, size_t dataSize, const char *name,
	      const char *uuid, unsigned flags, unsigned long long dev, unsigned int target_count,
	      unsigned int event_nr);

/**
 * Opens /dev/mapper/control
 *
 * @return int 0 in case of success, -1 in case of failure
 */
int
dm_open_control(void);

/**
 * Closes /dev/mapper/control
 *
 * @param fd The fd for /dev/mapper/control
 */
void
dm_close_control(int fd);

/**
 * Get the size of a Linux special block device in bytes
 *
 * This function uses BLKGETSIZE64, which returns the size in bytes,
 * compared to the deprecated BLKGETSIZE, which returns the size as
 * a number of 512-byte blocks. To get size in blocks similar to the
 * deprecated command, the value must be divided by the result of
 * dm_get_blkdev_sector_size.
 *
 * @param fd The file descriptor of the block device
 * @return uint64_t The size of the block device in bytes
 */
uint64_t
dm_get_blkdev_size64(int fd);

/**
 * Get the sector size of a Linux block device
 *
 * @param fd The file descriptor of the block device
 * @return int The sector size
 */
int
dm_get_blkdev_sector_size(int fd);

/**
 * Check if block device is read-only
 *
 * @param fd The file descriptor of the block device to be checked
 * @return int 0 if read-write, 1 if read-only, -1 on error
 */
int
dm_get_blkdev_readonly(int fd);

/**
 * Read dm-verity version via the DM_VERSION ioctl
 *
 * @param fd The /dev/mapper/control file descripter (can be retrieved
 * 				via dm_open_control)
 * @return int 0 in case of success, -1 in case of failure
 */
int
dm_read_version(int fd);

/**
 * List dm-verity versions via the DM_LIST_VERSIONS ioctl
 *
 * @param fd The /dev/mapper/control file descripter (can be retrieved
 * 				via dm_open_control)
 * @return int 0 in case of success, -1 in case of failure
 */
int
dm_list_versions(int fd);

#endif // DM_H