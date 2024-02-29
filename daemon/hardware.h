/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 * @file hardware.h
 *
 * The hardware submodule contains device specific functionality or definitions.
 * The API is specified in the header file, while at compile time a specific
 * implementation is choosen, e.g. hw_i9505.c for Galaxy S4 or hw_hammerhead.c
 * for Nexus 5.
 */

#ifndef HARDWARE_H
#define HARDWARE_H

#include <stdint.h>
#include <stdbool.h>
#include "common/list.h"
#include <stddef.h>

/**
 * Get the unique hardware name, e.g. hammerhead.
 * @return The hardware name.
 */

const char *
hardware_get_name(void);

/**
 * Returns a list containing strings of the active cgroups subsystems
 */
list_t *
hardware_get_active_cgroups_subsystems(void);

#endif /* HARDWARE_H */
