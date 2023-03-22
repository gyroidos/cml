/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#ifndef VERITY_H
#define VERITY_H

/**
 * @brief Returns the path for a dm-verity device
 *
 * @param label The verity device name
 * @return char* The path, must be freed
 */
char *
verity_get_device_path_new(const char *label);

/**
 * Open a device-mapper verity device
 *
 * @param name The name of the device to be created
 * @param fs_img_name The path of the image
 * @param hash_dev_name The path of the hash-tree image
 * @param root_hash The root hash as a hexadecimal string
 * @return int 0 if successful, otherwise -1
 */
int
verity_create_blk_dev(const char *name, const char *fs_img_name, const char *hash_dev_name,
		      const char *root_hash);

/**
 * Close a device-mapper verity device
 *
 * @param name The name of the device to be closed
 * @return int 0 if successful, otherwise -1
 *
 */
int
verity_delete_blk_dev(const char *name);

#endif // VERITY_H