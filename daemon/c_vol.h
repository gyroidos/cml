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

/**
  * @file c_vol.h
  *
  * This module is responsible for mounting images (for a container, at its startup) into the filesystem.
  * It is capable of utilizing a decryption key for mounting encrypted images. When a new container thread
  * gets cloned, the root directory of the images filesystem (and e.g. the proc, sys, dev directories) is/are
  * created and the image is mounted there together with a chroot.
  */
#ifndef C_VOL_H
#define C_VOL_H

#include "container.h"

typedef struct c_vol c_vol_t;

/**
 * @param container A reference to the corresponding container.
 * @param dir The path of the folder in which the
 * container-specific images (e.g. data and cache) are or should be stored.
 */
c_vol_t *
c_vol_new(const container_t *container);

void
c_vol_free(c_vol_t *vol);

char *
c_vol_get_rootdir(c_vol_t *vol);

bool
c_vol_is_encrypted(c_vol_t *vol);

/* Start hooks */
int
c_vol_start_child_early(c_vol_t *vol);

int
c_vol_start_child(c_vol_t *vol);

int
c_vol_start_pre_exec(c_vol_t *vol);

void
c_vol_cleanup(c_vol_t *vol, bool is_rebooting);

#endif /* C_VOL_H */
