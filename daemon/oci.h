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

#include "container.h"

/**
 * Data structure containing the variables associated to a oci control socket.
 */
typedef struct oci_control oci_control_t;

/**
 * Data structure containing the variables associated to a oci container.
 */
typedef struct oci_container oci_container_t;

/**
 * Frees the oci_container data structure
 */
void
oci_container_free(oci_container_t *oci_container);

/**
 * Get the oci_container data structure by its corresponding container reference
 *
 * container and oci_container always have a one-by-one relationship
 */
oci_container_t *
oci_get_oci_container_by_container(const container_t *container);

/**
 * Create a control socket receiving the OCI wrapper messages
 */
oci_control_t *
oci_control_new(char *path);
