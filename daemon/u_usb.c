/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2026 Fraunhofer AISEC
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

#define MOD_NAME "c_usb"

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/proc.h"
#include "common/ns.h"
#include "common/uevent.h"
#include "unit.h"

#include <sys/mount.h>

/* Usb structure with specific uevent forwarders */
typedef struct u_usb {
	unit_t *unit;		//!< unit which the u_usb struct is associated to
	uevent_uev_t *uev_udev; //!< uevent forwarding for userns (allow usb devices in unit)
} u_usb_t;

static void
u_usb_handle_event_cb(UNUSED unsigned actions, uevent_event_t *event, void *data)
{
	u_usb_t *usb = data;
	ASSERT(usb);

	if (unit_get_pid(usb->unit) <= 0)
		return;

	/* handle usb hotplug devices */
	IF_FALSE_RETURN_TRACE(0 == strncmp(uevent_event_get_subsystem(event), "usb", 3));

	if (uevent_event_inject_into_netns(event, unit_get_pid(usb->unit), true) < 0) {
		WARN("Could not inject uevent into netns of unit %s!",
		     unit_get_description(usb->unit));
	} else {
		TRACE("Successfully injected usb into netns of unit %s!",
		      unit_get_description(usb->unit));
	}
}

/**
 * This function allocates a new u_usb_t instance, associated to a specific unit object.
 * @return the u_usb_t usb structure which holds usb namespace information for a unit.
 */
static void *
u_usb_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	u_usb_t *usb = mem_new0(u_usb_t, 1);
	usb->unit = compartment_get_extension_data(compartment);

	// skip uevent forwarding if netns is shared with host
	if (!unit_has_netns(usb->unit))
		return usb;

	// allow libusb based on udev
	usb->uev_udev =
		uevent_uev_new(UEVENT_UEV_TYPE_KERNEL,
			       UEVENT_ACTION_ADD | UEVENT_ACTION_CHANGE | UEVENT_ACTION_REMOVE |
				       UEVENT_ACTION_BIND | UEVENT_ACTION_UNBIND,
			       u_usb_handle_event_cb, usb);

	return usb;
}

/**
 * Frees the u_usb_t structure
 */
static void
u_usb_free(void *usbp)
{
	u_usb_t *usb = usbp;
	ASSERT(usb);

	if (usb->uev_udev) {
		uevent_remove_uev(usb->uev_udev);
		uevent_uev_free(usb->uev_udev);
	}

	mem_free0(usb);
}

static int
u_usb_start_pre_exec(void *usbp)
{
	u_usb_t *usb = usbp;
	ASSERT(usb);

	// skip uevent forwarding if netns is shared with host
	if (!unit_has_netns(usb->unit))
		return 0;

	// register hotplug handling for this u_usb unit submodule
	if (uevent_add_uev(usb->uev_udev)) {
		return -COMPARTMENT_ERROR_UEVENT;
	}

	return 0;
}

static char *bin_path[] = {
	"/usr/lib/systemd/systemd-", "/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/",
};

static int
u_usb_start_udevd(void)
{
	char *udev_path = NULL;
	for (size_t i = 0; i < sizeof(bin_path) / sizeof(bin_path[0]); i++) {
		udev_path = mem_printf("%sudevd", bin_path[i]);
		if (access(udev_path, F_OK) == 0) {
			DEBUG("Found udevd with full path '%s'", udev_path);
			break;
		}
		mem_free0(udev_path);
	}
	if (udev_path == NULL) {
		ERROR("udevd binary not found in valid path.");
		return -1;
	}

	const char *const argv[] = { udev_path, NULL };

	pid_t pid = fork();
	IF_TRUE_RETVAL(pid == -1, -1);

	if (pid == 0) {
		execve(argv[0], (char *const *)argv, NULL);
		FATAL_ERRNO("Could not execvp %s", argv[0]);
		return -1;
	}

	mem_free0(udev_path);

	return 0;
}

static int
u_usb_start_child(void *usbp)
{
	u_usb_t *usb = usbp;
	ASSERT(usb);

	// skip uevent forwarding if netns is shared with host
	if (!unit_has_netns(usb->unit))
		return 0;

	if (mount("tmpfs", "/run/udev", "tmpfs", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount /run/udev in unit %s",
			    unit_get_description(usb->unit));
		WARN("Failed to start mount /run/udevd in unit %s!"
		     " Hotplug inside unit will not work!)",
		     unit_get_description(usb->unit));
		return 0;
	}

	if (u_usb_start_udevd() < -1)
		return -COMPARTMENT_ERROR_UEVENT;

	return 0;
}

static int
u_usb_stop(void *usbp)
{
	u_usb_t *usb = usbp;
	ASSERT(usb);

	// skip uevent forwarding if netns is shared with host
	if (!unit_has_netns(usb->unit))
		return 0;

	uevent_remove_uev(usb->uev_udev);

	return 0;
}

static compartment_module_t u_usb_module = {
	.name = MOD_NAME,
	.compartment_new = u_usb_new,
	.compartment_free = u_usb_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = u_usb_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = u_usb_start_child,
	.start_pre_exec_child = NULL,
	.stop = u_usb_stop,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
u_usb_init(void)
{
	// register this module in unit.c
	unit_register_compartment_module(&u_usb_module);
}
