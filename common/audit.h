/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#ifndef COMMON_AUDIT_H
#define COMMON_AUDIT_H

#include "nl.h"

#ifdef ANDROID
#include "device/fraunhofer/common/cml/common/audit.pb-c.h"
#else
#include "audit.pb-c.h"
#endif

#ifndef NETLINK_AUDIT
#define NETLINK_AUDIT 9
#endif

#define MAX_AUDIT_MESSAGE_LENGTH 8970
#define AUDIT_FIRST_EVENT 1300
#define AUDIT_INTEGRITY_LAST_MSG 1899
#define AUDIT_TRUSTED_APP 1121 /* Trusted app msg - freestyle text */

typedef enum { CONTAINER, C0 } AUDIT_MODE;

AuditRecord *
audit_record_new(const char *type, const char *subject_id, int meta_length,
		 AuditRecord__Meta **metas);

int
audit_kernel_send(nl_sock_t *audit_sock, int type, const void *data, size_t len);

int
audit_kernel_log_event(const char *type, const char *subject_id, int meta_count, ...);

int
audit_kernel_write_loginuid(uint32_t uid);

#endif /* COMMON_AUDIT_H */
