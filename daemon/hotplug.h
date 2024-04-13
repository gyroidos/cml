/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 * @file hotplug.h
 *
 * This module handles hotpluging of network and usb devices.
 * It responds to corresponding hotplugs and forwards them to the registered containers.
 */
#ifndef HOTPLUG_H
#define HOTPLUG_H

#include <stdlib.h>
#include <stdint.h>

#include "container.h"

typedef enum hotplug_usbdev_type {
	HOTPLUG_USBDEV_TYPE_GENERIC = 1,
	HOTPLUG_USBDEV_TYPE_TOKEN,
	HOTPLUG_USBDEV_TYPE_PIN_ENTRY
} hotplug_usbdev_type_t;

/**
 * Structure to define the mapping of hotplug event to usb device

 * It defines the usb vendor and product as show by lsusb
 * and if there is any the serial of a device, e.g. from uTrust Token.
 * Further, it is defined if the device should be assigned exclusivly
 * to the container or if just the access is allowed.
 */
typedef struct hotplug_usbdev hotplug_usbdev_t;

hotplug_usbdev_t *
hotplug_usbdev_new(hotplug_usbdev_type_t type, uint16_t id_vendor, uint16_t id_product,
		   char *i_serial, bool assign);

uint16_t
hotplug_usbdev_get_id_vendor(hotplug_usbdev_t *usbdev);

uint16_t
hotplug_usbdev_get_id_product(hotplug_usbdev_t *usbdev);

char *
hotplug_usbdev_get_i_serial(hotplug_usbdev_t *usbdev);

hotplug_usbdev_type_t
hotplug_usbdev_get_type(hotplug_usbdev_t *usbdev);

bool
hotplug_usbdev_is_assigned(hotplug_usbdev_t *usbdev);

void
hotplug_usbdev_set_major(hotplug_usbdev_t *usbdev, int major);

void
hotplug_usbdev_set_minor(hotplug_usbdev_t *usbdev, int minor);

int
hotplug_usbedv_get_major(hotplug_usbdev_t *usbdev);

int
hotplug_usbdev_get_minor(hotplug_usbdev_t *usbdev);

/**
 * Global setup for the hotplug handler for netdev and usbdevice handling
 *
 * @return 0 if successful. -1 indicates an error.
 */
int
hotplug_init();

/**
 * Cleanup of hotplug module, remove handler for netdev and usbdevices
 */
void
hotplug_cleanup();

/**
  * Registers an usb device mapping for a container at the hotplug subsystem
  */
int
hotplug_register_usbdevice(container_t *container, hotplug_usbdev_t *usbdev);

/**
  * Unregisters an usb device mapping for a container at the hotplug subsystem
  */
int
hotplug_unregister_usbdevice(container_t *container, hotplug_usbdev_t *usbdev);

/**
 * Registers a net device by its pnet_cfg for a container at the hotplug subsystem
 * 
 * @param container container which assigns the interface
 * @param pnet_cfg containing the config including mac address of the interface which should be registered
 * @return 0 if successful. -1 indicates an error.
 */
int
hotplug_register_netdev(container_t *container, container_pnet_cfg_t *pnet_cfg);

/**
 * Unregisters a net device by its mac address for a container at the hotplug subsystem
 *
 * @param container container which has the interface assigned
 * @param mac buffer containing the mac address of the interface which should be removed
 * @return 0 if successful. -1 indicates an error.
 */
int
hotplug_unregister_netdev(container_t *container, uint8_t mac[6]);

#endif /* UEVENT_H */
