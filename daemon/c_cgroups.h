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
 * @file c_cgroups.h
 *
 * This submodule provides functionality to setup control groups for containers.
 * This includes configurations like the max ram for a container and  the functionality
 * to freeze and unfreeze a container.
 */

#ifndef C_CGROUPS_H
#define C_CGROUPS_H

#include "container.h"

typedef struct c_cgroups c_cgroups_t;

c_cgroups_t *
c_cgroups_new(container_t *container);

void
c_cgroups_free(c_cgroups_t *cgroups);

/*******************/
/* Functions */
int
c_cgroups_freeze(c_cgroups_t *cgroups);

int
c_cgroups_unfreeze(c_cgroups_t *cgroups);

int
c_cgroups_devices_allow_audio(c_cgroups_t *cgroups);

int
c_cgroups_devices_deny_audio(c_cgroups_t *cgroups);

int
c_cgroups_devices_chardev_allow(c_cgroups_t *cgroups, int major, int minor, bool assign);
int
c_cgroups_devices_chardev_deny(c_cgroups_t *cgroups, int major, int minor);

bool
c_cgroups_devices_is_dev_allowed(c_cgroups_t *cgroups, int major, int minor);

/**
 * This function gets the ram_limit for the container from its associated container
 * object and configures the cgroups memory subsystem to this limit.
 */
int
c_cgroups_set_ram_limit(c_cgroups_t *cgroups);

int
c_cgroups_add_pid(c_cgroups_t *cgroups, pid_t pid);

/******************************/
/*
 * Container start hooks
 * These Functions are part of TSF.CML.CompartmentIsolation.
 */
int
c_cgroups_start_pre_clone(c_cgroups_t *cgroups);

int
c_cgroups_start_post_clone(c_cgroups_t *cgroups);

int
c_cgroups_start_pre_exec(c_cgroups_t *cgroups);

int
c_cgroups_start_pre_exec_child(c_cgroups_t *cgroups);

int
c_cgroups_start_child(c_cgroups_t *cgroups);

/******************************/

void
c_cgroups_cleanup(c_cgroups_t *cgroups);

#endif /* C_CGROUPS_H */
