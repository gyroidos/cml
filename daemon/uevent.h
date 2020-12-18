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
  * Registers a net device by its mac address for a container at the uevent subsystem
  */
int
uevent_register_netdev(container_t *container, uint8_t mac[6]);

/**
 * Unregisters a net device by its mac address for a container at the uevent subsystem
 *
 * @param container container which assigns the interface
 * @param mac buffer containing the mac address of the interface which should be registered
 * @return 0 if successful. -1 indicates an error.
 */
int
uevent_unregister_netdev(container_t *container, uint8_t mac[6]);

/**
 * Trigger cold boot events to allow user namespaced containers to fixup
 * their device nodes by udevd in container.
 * Internally the uuid of the container is used for synthetic events
 * to allow directing events to corresponding container only.
 *
 * @param container container for which the cold boot is triggered.
 */
void
uevent_udev_trigger_coldboot(container_t *container);

#endif /* UEVENT_H */
