/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2021 Fraunhofer AISEC
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

#ifndef C_AUDIT_H
#define C_AUDIT_H

#include "container.h"
#include "audit.h"

typedef struct c_audit c_audit_t;

c_audit_t *
c_audit_new(const container_t *container);

int
c_audit_start_post_clone(c_audit_t *audit);

char *
c_audit_get_last_ack(const c_audit_t *audit);

void
c_audit_set_last_ack(c_audit_t *audit, const char *last_ack);

bool
c_audit_get_processing_ack(const c_audit_t *audit);

void
c_audit_set_processing_ack(c_audit_t *audit, bool processing_ack);

#endif /* C_AUDIT_H */
