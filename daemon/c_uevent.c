/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2022 Fraunhofer AISEC
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

#define MOD_NAME "c_uevent"

#include "common/macro.h"
#include "common/mem.h"
#include "container.h"
#include "uevent.h"

typedef struct c_uevent {
	container_t *container;
} c_uevent_t;

static void *
c_uevent_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_uevent_t *uevent = mem_new0(c_uevent_t, 1);
	uevent->container = compartment_get_extension_data(compartment);

	return uevent;
}

static void
c_uevent_free(void *ueventp)
{
	c_uevent_t *uevent = ueventp;
	ASSERT(uevent);
	mem_free0(uevent);
}

static bool
c_uevent_coldboot_dev_filter_cb(int major, int minor, void *data)
{
	c_uevent_t *uevent = data;
	ASSERT(uevent);

	if (!container_is_device_allowed(uevent->container, major, minor)) {
		TRACE("filter coldboot uevent for device (%d:%d)", major, minor);
		return false;
	}

	return true;
}

static int
c_uevent_start_post_exec(void *ueventp)
{
	c_uevent_t *uevent = ueventp;
	ASSERT(uevent);

	// fixup device nodes in userns by triggering uevent forwarding of coldboot events
	if (container_has_userns(uevent->container)) {
		uevent_udev_trigger_coldboot(container_get_uuid(uevent->container),
					     c_uevent_coldboot_dev_filter_cb, uevent);
	}

	return 0;
}

static compartment_module_t c_uevent_module = {
	.name = MOD_NAME,
	.compartment_new = c_uevent_new,
	.compartment_free = c_uevent_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = c_uevent_start_post_exec,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
c_uevent_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_uevent_module);
}
