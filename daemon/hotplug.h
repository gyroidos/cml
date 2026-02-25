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
hotplug_unregister_netdev(container_t *container, uint8_t mac[MAC_ADDR_LEN]);

#endif /* UEVENT_H */
