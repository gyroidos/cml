/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
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

char *
cryptfs_get_device_path_new(const char *label);

char *
cryptfs_setup_volume_new(const char *label, const char *real_blk_dev, const char *ascii_key,
			 bool integrity);

int
cryptfs_delete_blk_dev(const char *name);

#endif /* CRYPTFS_H */
