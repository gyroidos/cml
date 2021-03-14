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

#ifndef AUDIT_H
#define AUDIT_H

#include "container.h"

typedef enum { CONTAINER, C0 } AUDIT_MODE;

typedef enum { SUA, FUA, SSA, FSA, RLE } AUDIT_CATEGORY;

typedef enum {
	GUESTOS_MGMT,
	TOKEN_MGMT,
	CONTAINER_MGMT,
	CONTAINER_ISOLATION,
	TPM_COMM,
	KAUDIT,
} AUDIT_EVENTCLASS;

typedef enum { COMMAND, INTERNAL, TOKEN, UPDATE } AUDIT_EVENTTYPE;

typedef enum { CMLD, SCD, TPM2D } AUDIT_COMPONENT;

int
audit_set_size(uint32_t size);

int
audit_kernel_log_event(AUDIT_CATEGORY category, AUDIT_COMPONENT component, AUDIT_EVENTCLASS evclass,
		       const char *evtype, const char *subject_id, int meta_count, ...);
int
audit_log_event(const uuid_t *uuid, AUDIT_CATEGORY category, AUDIT_COMPONENT component,
		AUDIT_EVENTCLASS evclass, const char *evtype, const char *subject_id,
		int meta_count, ...);

int
audit_process_ack(const container_t *audit, const char *ack);

int
audit_init();

#endif /* AUDIT_H */
