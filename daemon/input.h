/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
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

#ifndef INPUT_H
#define INPUT_H

/**
 * @file input.h
 *
 * This module implements the device side of the input event virtualization.
 * It configures the kernel and listens for power button input events and switches
 * containers if necesassry.
 */

/**
 * Global setup for the input forwarder.
 */
int
input_init(void);

/**
 * Disable all input injecting (ie. power button and syn events) into the foreground container
 */
void
input_pb_injecting_disable(void);

/**
 * Enable all input injecting (ie. power button and syn events) into the foreground container
 */
void
input_pb_injecting_enable(void);

#if 0
/**
 * The following functions allow the configuration of input events on input
 * device granularity.
 */

/**
 * Set the given input device to be foreground exclusive, i.e. events from
 * this device are always only forwarded to the current foreground container.
 * NOTE: This is the default for all devices.
 */
void
input_device_set_foreground_exclusive(/*inputdevice*/);

/**
 * Set the given device to be concurrent, i.e. events from this device are
 * always forwarded to _all_ containers.
 */
void
input_device_set_concurrent(/*inputdevice*/);

void
input_device_set_active_for_container(/*inputdevice*/, container_t *container);

void
input_device_set_inactive_for_container(/*inputdevice*/, container_t *container);
#endif

#endif /* INPUT_H */
