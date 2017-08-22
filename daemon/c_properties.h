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

#ifndef C_PROPERTIES_H
#define C_PROPERTIES_H

#include "container.h"

typedef struct c_properties c_properties_t;

c_properties_t *
c_properties_new(const container_t *container, const char *telephony_name);

void
c_properties_free(c_properties_t *prop);

int
c_properties_set_property(c_properties_t *prop, const char *prop_name, const char *prop_value);

void
c_properties_set_telephony_name(c_properties_t *prop, const char* name);

/* Start hooks */
int
c_properties_start_child(c_properties_t *prop);

#endif /* C_PROPERTIES_H */
