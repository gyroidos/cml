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

/**
 * @brief Returns the index of the current boot entry
 *
 * @return uint16_t* allocated boot index
 */
uint16_t *
efivars_get_boot_current_new(void);

uint16_t *
efivars_get_boot_order_new(size_t *len_out);

int
efivars_set_boot_order(const uint16_t *order, size_t len);

int
efivars_set_boot_next(uint16_t next);

bool
efivars_boot_entry_initialized(uint16_t idx, const char *label, const char *path);

int
efivars_set_boot_entry(uint16_t idx, const char *label, const char *path);

#endif // EFIVARS_H
