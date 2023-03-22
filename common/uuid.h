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
 * @file uuid.h
 *
 * This modules enables to create unique identifiers, which are e.g. used to identify containers.
 * It also supports the comparison and random initialization of uuids.
 */

#ifndef UUID_H
#define UUID_H

#include <stdbool.h>
#include <stdint.h>

typedef struct uuid uuid_t;

/**
 * Generate new UUID.
 *
 * @param uuid String representing the UUID to generate. If NULL the function
 * generates a random UUID.
 * @return New UUID.
 */
uuid_t *
uuid_new(char const *uuid);

/**
 * Test two UUIDs for equality.
 *
 * @param uuid1 First UUID.
 * @param uuid2 Second UUID.
 * @return True if uuid1 and uuid2 are equal. False if not.
 */
bool
uuid_equals(const uuid_t *uuid1, const uuid_t *uuid2);

/**
 * Free a UUID.
 *
 * @param uuid UUID to be freed.
 * @return True if uuid1 and uuid2 are equal. False if not.
 */
void
uuid_free(uuid_t *uuid);

/**
 * Get a string representation of the UUID.
 *
 * @param uuid UUID for which the string representation is returned.
 * @return The string representation of uuid.
 */
const char *
uuid_string(const uuid_t *uuid);

/**
 * Get 48 bit node ID in last Part of uuid
 *
 * @param uuid UUID for which the string representation is returned.
 * @return The node ID as 64 bit unsigned integer
 */
uint64_t
uuid_get_node(const uuid_t *uuid);

#endif /* UUID_H */
