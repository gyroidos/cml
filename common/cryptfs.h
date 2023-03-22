/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 * @file cryptfs.h
 *
 * This module is based on the implementation in system/vold/cryptfs.c and was modified to
 * be used by the c_vol module.
 * It helps to mount, respectively remove an encrypted, nonremovable (device-mapper) volume.
 */

#ifndef CRYPTFS_H
#define CRYPTFS_H

#include <stdbool.h>

#define CRYPTFS_FDE_KEY_LEN 64

/**
 * Get the full path of a cryptfs device with the specified name
 *
 * @param label The name to get the path for
 * @return char* The device path in case of success, otherwise NULL
 */
char *
cryptfs_get_device_path_new(const char *label);

/**
 * Create a new cryptfs device with the specified name,
 *
 * @param label The name of the volume
 * @param real_blk_dev The name of the loop device
 * @param ascii_key The key for the volume
 * @param meta_blk_dev The meta loop device
 * @return char* The path of the newly created volume
 */
char *
cryptfs_setup_volume_new(const char *label, const char *real_blk_dev, const char *ascii_key,
			 const char *meta_blk_dev);

/**
 * Close a device-mapper volume
 *
 * @param fd The filedescriptor of the device
 * @param name The name of the device
 * @return int 0 if successful, otherwise -1
 */
int
cryptfs_delete_blk_dev(int fd, const char *name);

#endif /* CRYPTFS_H */
