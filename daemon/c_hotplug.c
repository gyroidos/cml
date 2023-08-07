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

/**
 * @file c_hotplug.c
 *
 * This submodule provides functionality to acct on hotplug events
 * and forward devices according to the container configuration.
 */

#define MOD_NAME "c_hotplug"

#include "container.h"
#include "hotplug.h"

#include "common/mem.h"
#include "common/macro.h"

typedef struct c_hotplug {
	container_t *container; // weak reference
} c_hotplug_t;

static void *
c_hotplug_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_hotplug_t *hotplug = mem_new0(c_hotplug_t, 1);
	hotplug->container = compartment_get_extension_data(compartment);

	return hotplug;
}

static void
c_hotplug_free(void *hotplugp)
{
	c_hotplug_t *hotplug = hotplugp;
	ASSERT(hotplug);

	mem_free0(hotplug);
}

static int
c_hotplug_usbdev_allow(c_hotplug_t *hotplug, hotplug_usbdev_t *usbdev)
{
	ASSERT(hotplug);
	ASSERT(usbdev);
	if (0 != hotplug_usbdev_set_sysfs_props(usbdev)) {
		ERROR("Failed to find usbedv in sysfs");
		return -1;
	}

	if (-1 == container_device_allow(hotplug->container, 'c', hotplug_usbedv_get_major(usbdev),
					 hotplug_usbdev_get_minor(usbdev),
					 hotplug_usbdev_is_assigned(usbdev))) {
		WARN("Could not %s char device %d:%d !",
		     hotplug_usbdev_is_assigned(usbdev) ? "assign" : "allow",
		     hotplug_usbedv_get_major(usbdev), hotplug_usbdev_get_minor(usbdev));
		return -1;
	}

	return 0;
}

static int
c_hotplug_register_usbdevs(void *hotplugp)
{
	c_hotplug_t *hotplug = hotplugp;
	ASSERT(hotplug);

	/* append usb devices to devices_subsystem */
	for (list_t *l = container_get_usbdev_list(hotplug->container); l; l = l->next) {
		hotplug_usbdev_t *usbdev = l->data;
		// USB devices of type PIN_READER are only required outside the container to enter the pin
		// before the container starts and should not be mapped into the container, as they can
		// be used for multiple containers and a container should not be able to log the pin of
		// another container
		if (hotplug_usbdev_get_type(usbdev) == HOTPLUG_USBDEV_TYPE_PIN_ENTRY) {
			TRACE("Device of type pin reader is not mapped into the container");
			continue;
		} else if (hotplug_usbdev_get_type(usbdev) == HOTPLUG_USBDEV_TYPE_TOKEN) {
			// token devices are previously registered to the hotplug subsystem
			c_hotplug_usbdev_allow(hotplug, usbdev);
		} else if (hotplug_usbdev_get_type(usbdev) == HOTPLUG_USBDEV_TYPE_GENERIC) {
			c_hotplug_usbdev_allow(hotplug, usbdev);
			// for hotplug events register the device at hotplug subsystem
			hotplug_register_usbdevice(hotplug->container, usbdev);
		} else {
			ERROR("Unknown HOTPLUG_USBDEV_TYPE. Device has not been configured!");
		}
	}
	return 0;
}

static void
c_hotplug_cleanup(void *hotplugp, UNUSED bool is_rebooting)
{
	c_hotplug_t *hotplug = hotplugp;
	ASSERT(hotplug);

	/* unregister usbdevs from hotplug subsystem */
	for (list_t *l = container_get_usbdev_list(hotplug->container); l; l = l->next) {
		hotplug_usbdev_t *usbdev = l->data;
		if (HOTPLUG_USBDEV_TYPE_TOKEN !=
		    hotplug_usbdev_get_type(
			    usbdev)) // keep token registered so it can be reinitialized on hotplug
			hotplug_unregister_usbdevice(hotplug->container, usbdev);
	}
}

static compartment_module_t c_hotplug_module = {
	.name = MOD_NAME,
	.compartment_new = c_hotplug_new,
	.compartment_free = c_hotplug_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
#ifdef CGROUPS_LEGACY
	.start_post_clone = NULL,
	.start_pre_exec = c_hotplug_register_usbdevs,
#else
	.start_post_clone = c_hotplug_register_usbdevs,
	.start_pre_exec = NULL,
#endif
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child_early = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_hotplug_cleanup,
	.join_ns = NULL,
};

static void INIT
c_hotplug_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_hotplug_module);
}
