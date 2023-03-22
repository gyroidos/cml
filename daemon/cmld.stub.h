/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 * @file cmld.stub.h
 *
 * Stub for the cmld module used for (control module) unit tests,
 * providing stubbed versions of the cmld API.
 *
 * Reports back which stubbed cmld functions were called via a file descriptor
 * (UNIX socket) passed to the cmld_stub_init function which must be called
 * before invoking regular cmld functions of the stub.
 */
#ifndef CMLD_STUB_H
#define CMLD_STUB_H

#include "cmld.h"

/**
 * Initialize the cmld stub module with the given file descriptor
 * used to report back which functions were invoked.
 *
 * @param fd    File descriptor (UNIX socket) to report back invoked * functions.
 */
void
cmld_stub_init(int fd);

/**
 * Creates a dummy container stub with the given name.
 *
 * @param container_name Name of the dummy container.
 * @return Pointer to the dummy container object.
 */
container_t *
cmld_stub_container_create(const char *container_name);

container_t *
cmld_containers_get_a0();

#endif // CMLD_STUB_H
