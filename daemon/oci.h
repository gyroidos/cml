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
 * Run prestart hooks
 *
 * Call this function in host after OCT START has been triggerd but
 * before exec of container process
 */
int
oci_do_hooks_prestart(const container_t *container);

/**
 * Run create_runtime hooks
 *
 * Call this function in host during OCI CREATE before pivot root
 */
int
oci_do_hooks_create_runtime(const container_t *container);

/**
 * Run create_container hooks
 *
 * Call this function in child during OCI CREATE before pivot root
 */
int
oci_do_hooks_create_container(const container_t *container);

/**
 * Run start_container hooks
 *
 * Call this function in child during OCI START before exec of container init
 */
int
oci_do_hooks_start_container(const container_t *container);

/**
 * Run poststart hooks
 *
 * Call this function in host after exec of container init
 */
int
oci_do_hooks_poststart(const container_t *container);

/**
 * Run poststop hooks
 *
 * Call this function in host after stop during OCI DELETE
 */
int
oci_do_hooks_poststop(const container_t *container);

/**
 * Creates a new oci_control_t object listening on the specified socket.
 *
 * @param socket listening socket
 */
oci_control_t *
oci_control_new(int socket);

/**
 * Creates a new oci_control_t object listening on a UNIX socket bound to the specified file.
 *
 * @param path path of the socket file to bind the socket to
 */
oci_control_t *
oci_control_local_new(const char *path);
