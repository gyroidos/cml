/*
 * This file is part of GyroidOS
 * Copyright(c) 2025 Fraunhofer AISEC
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

#ifndef EFIVARS_H
#define EFIVARS_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

int
mount_efivarfs(void);

/**
 * @brief Returns the index of the current boot entry
 *
 * @return uint16_t boot index
 */
uint16_t
efivars_get_boot_current(void);

uint16_t *
efivars_get_boot_order(size_t *len_out);

void
efivars_set_boot_order(bool invert);

void
efivars_set_boot_next(uint16_t next);

bool
efivars_boot_entries_initialized(void);

void
efivars_init_boot_entries(void);

#endif // EFIVARS_H
