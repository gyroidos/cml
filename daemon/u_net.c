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

/**
 * @file u_net.c
 *
 * This module is responsible for a private network without external connectivity for units.
 */

#define _GNU_SOURCE

#define MOD_NAME "c_net"

#include "common/macro.h"
#include "common/mem.h"
#include "compartment.h"
#include "unit.h"

#include <sys/mount.h>

/* Dummy Network structure */
typedef struct u_net {
	unit_t *unit; //!< unit which the u_net struct is associated to
} u_net_t;

/**
 * This function allocates a new u_net_t instance, associated to a specific unit object.
 * @return the u_net_t network structure which holds networking information for an unit.
 */
static void *
u_net_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	u_net_t *net = mem_new0(u_net_t, 1);
	net->unit = compartment_get_extension_data(compartment);

	return net;
}

/**
 * Frees the u_net_t structure
 */
static void
u_net_free(void *netp)
{
	u_net_t *net = netp;
	ASSERT(net);

	mem_free0(net);
}

/*
 * Mount sys in namspaced child
 */
static int
u_net_start_child(void *netp)
{
	u_net_t *net = netp;
	ASSERT(net);

	if (!unit_has_netns(net->unit))
		return 0;

	if (mount("sys", "/sys", "sys", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not remount /sys in unit %s", unit_get_description(net->unit));
		return -COMPARTMENT_ERROR_NET;
	}

	return 0;
}

static compartment_module_t u_net_module = {
	.name = MOD_NAME,
	.compartment_new = u_net_new,
	.compartment_free = u_net_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_pre_exec_child_early = NULL,
	.start_child = u_net_start_child,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
u_net_init(void)
{
	// register this module in unit.c
	unit_register_compartment_module(&u_net_module);
}
