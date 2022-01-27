/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
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

/**
 * @file uevent.h
 *
 * This module handles uevents from the netlink interface coming from the kernel or udev.
 * It parses those events into a dedicated uevent struct and handles them.
 */
#ifndef UEVENT_H
#define UEVENT_H

#include <stdlib.h>
#include <stdint.h>

#include "container.h"
#include "uuid.h"

#define UEVENT_BUF_LEN 64 * 1024

#define UEVENT_ACTION_ADD (1 << 0)
#define UEVENT_ACTION_BIND (1 << 1)
#define UEVENT_ACTION_CHANGE (1 << 2)
#define UEVENT_ACTION_REMOVE (1 << 3)
#define UEVENT_ACTION_UNBIND (1 << 4)

typedef struct uevent_uev uevent_uev_t;

typedef enum { UEVENT_UEV_TYPE_KERNEL = 1, UEVENT_UEV_TYPE_UDEV } uevent_uev_type_t;

typedef enum uevent_usbdev_type {
	UEVENT_USBDEV_TYPE_GENERIC = 1,
	UEVENT_USBDEV_TYPE_TOKEN,
	UEVENT_USBDEV_TYPE_PIN_ENTRY
} uevent_usbdev_type_t;

/**
 * Structure to define the mapping of event to usb device

 * It defines the usb vendor and product as show by lsusb
 * and if there is any the serial of a device, e.g. from uTrust Token.
 * Further, it is defined if the device should be assigned exclusivly
 * to the container or if just the access is allowed.
 */
typedef struct uevent_usbdev uevent_usbdev_t;

uevent_usbdev_t *
uevent_usbdev_new(uevent_usbdev_type_t type, uint16_t id_vendor, uint16_t id_product,
		  char *i_serial, bool assign);

uint16_t
uevent_usbdev_get_id_vendor(uevent_usbdev_t *usbdev);

uint16_t
uevent_usbdev_get_id_product(uevent_usbdev_t *usbdev);

char *
uevent_usbdev_get_i_serial(uevent_usbdev_t *usbdev);

uevent_usbdev_type_t
uevent_usbdev_get_type(uevent_usbdev_t *usbdev);

bool
uevent_usbdev_is_assigned(uevent_usbdev_t *usbdev);

void
uevent_usbdev_set_major(uevent_usbdev_t *usbdev, int major);

void
uevent_usbdev_set_minor(uevent_usbdev_t *usbdev, int minor);

int
uevent_usbedv_get_major(uevent_usbdev_t *usbdev);

int
uevent_usbdev_get_minor(uevent_usbdev_t *usbdev);

int
uevent_usbdev_set_sysfs_props(uevent_usbdev_t *usbdev);

/**
 * Global setup for the uevent handler
 *
 * @return 0 if successful. -1 indicates an error.
 */
int
uevent_init();

/**
  * Registers an usb device mapping for a container at the uevent subsystem
  */
int
uevent_register_usbdevice(container_t *container, uevent_usbdev_t *usbdev);

/**
  * Unregisters an usb device mapping for a container at the uevent subsystem
  */
int
uevent_unregister_usbdevice(container_t *container, uevent_usbdev_t *usbdev);

/**
 * Registers a net device by its pnet_cfg for a container at the uevent subsystem
 * 
 * @param container container which assigns the interface
 * @param pnet_cfg containing the config including mac address of the interface which should be registered
 * @return 0 if successful. -1 indicates an error.
 */
int
uevent_register_netdev(container_t *container, container_pnet_cfg_t *pnet_cfg);

/**
 * Unregisters a net device by its mac address for a container at the uevent subsystem
 *
 * @param container container which has the interface assigned
 * @param mac buffer containing the mac address of the interface which should be removed
 * @return 0 if successful. -1 indicates an error.
 */
int
uevent_unregister_netdev(container_t *container, uint8_t mac[6]);

/**
 * Trigger cold boot events to allow user namespaced containers to fixup
 * their device nodes by udevd in container.
 * The uuid of a container can be used for synthetic events to allow directing
 * events to corresponding container only.
 *
 * @param synth_uuid uuid used for syth event paramter in uevent.
 * @param filter callback function which is called for each major:minor.
 * @param data generic data pointer which is given to filter callback data.
 */
void
uevent_udev_trigger_coldboot(const uuid_t *synth_uuid,
			     bool (*filter)(int major, int minor, void *data), void *data);

uevent_uev_t *
uevent_uev_new(uevent_uev_type_t type, unsigned actions,
	       void (*func)(unsigned actions, uevent_uev_t *uev, void *data), void *data);
int
uevent_add_uev(uevent_uev_t *uev);

void
uevent_remove_uev(uevent_uev_t *uev);

#endif /* UEVENT_H */
