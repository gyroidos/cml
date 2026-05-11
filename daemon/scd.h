/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2021 Fraunhofer AISEC
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

#ifndef CML_SCD_H
#define CML_SCD_H

#include <stdbool.h>

#include "unit.h"

/**
 * Initializes the scd subsystem (starts the corresponding daemon)
 * @return 0 on success, -1 on error
 */
int
scd_init(void);

/**
 * Cleans up the scd subsystem (stops the corresponding daemon)
 */
void
scd_cleanup(void);

/**
 * Returns the scd subsystems unit instance
 */
unit_t *
scd_get_unit(void);

#endif /* CML_SCD_H */
