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
 * @file input.h
 *
 * This module implements functionality to search for an external usb
 * input pin reader and to read in pins from that device
 */

#ifndef DAEMON_INPUT_H_
#define DAEMON_INPUT_H_

/**
 * Register callback to interactively read in container pin from USB
 * pin entry device and start container afterwards
 *
 * @param container_start_ptr_t container_start_ptr Function pointer
 *          to the container start function
 * @param control_t *control
 * @param container_t *container
 * @param ContainerStartParams *start_params
 */
int
input_register_container_start_cb(control_t *control, container_t *container);

void
input_clean_pin_entry(void);

#endif // DAEMON_INPUT_H_