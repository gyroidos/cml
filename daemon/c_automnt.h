/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2023 Fraunhofer AISEC
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

#ifndef C_AUTOMNT_H
#define C_AUTOMNT_H

#include "container.h"

typedef struct c_automnt c_automnt_t;

void
c_automnt_cleanup(void *automnt);

void
c_automnt_free(c_automnt_t *automnt);

int
c_automnt_start_child_early(c_automnt_t *automnt);

int
c_automnt_start_post_exec(c_automnt_t *automnt);

c_automnt_t *
c_automnt_new(container_t *container);

#endif /* C_AUTOMOUNT_H */
