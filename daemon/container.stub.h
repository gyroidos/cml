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

/**
 * @file container.stub.h
 *
 * Stub for the container module used for (control module) unit tests.
 * providing minimal (dummy) functionality.
 */
#ifndef CONTAINER_STUB_H
#define CONTAINER_STUB_H

#include "container.h"

/**
 * Creates a new dummy container stub with the given name.
 *
 * @param container_name The name of the dummy container stub.
 * @return Pointer to the new dummy container stub object.
 */
container_t *
container_stub_new(char const *container_name);

void
container_free(container_t *container);

const char *
container_get_name(const container_t *container);

const char *
container_get_config_filename(const container_t *container);

const uuid_t *
container_get_uuid(const container_t *container);

container_state_t
container_get_state(const container_t *container);

pid_t
container_get_pid(const container_t *container);

char*
container_get_imei(container_t *container);

char*
container_get_mac_address(container_t *container);

char*
container_get_phone_number(container_t *container);

void
container_set_radio_ip(container_t *container, char *ip);

void
container_set_radio_dns(container_t *container, char *dns);

void
container_set_radio_gateway(container_t *container, char *gateway);

#endif // CONTAINER_STUB_H
