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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "c_audit.h"

#include "cmld.h"
#include "smartcard.h"
#include "common/mem.h"
#include "common/uuid.h"
#include "common/str.h"
#include "common/macro.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/protobuf.h"

#include <string.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <google/protobuf-c/protobuf-c-text.h>

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

struct c_audit {
	const container_t *container;
	char *last_ack;
	bool processing_ack;
	uint32_t loginuid;
};

static int
c_audit_set_contid(c_audit_t *audit)
{
	ASSERT(audit);

	int ret = 0;
	char *aucontid_file =
		mem_printf("/proc/%d/audit_containerid", container_get_pid(audit->container));

	// skip if contid is not supported by kernel
	if (!file_exists(aucontid_file)) {
		goto out;
	}

	if (0 > file_printf(aucontid_file, "%llu",
			    uuid_get_node(container_get_uuid(audit->container)))) {
		ERROR("Failed to set audit container ID '%llu'",
		      (unsigned long long)uuid_get_node(container_get_uuid(audit->container)));
		ret = -1;
		goto out;
	}
	INFO("Set audit container ID '%llu'",
	     (unsigned long long)uuid_get_node(container_get_uuid(audit->container)));
out:
	mem_free0(aucontid_file);
	return ret;
}

int
c_audit_start_post_clone_early(c_audit_t *audit)
{
	ASSERT(audit);
	// update kernel container id
	return c_audit_set_contid(audit);
}

int
c_audit_start_child_early(c_audit_t *audit)
{
	ASSERT(audit);

	// update kernel login uid with internal set loginuid
	if (audit_kernel_write_loginuid(audit->loginuid)) {
		ERROR("Could not set loginuid!");
		return -1;
	}
	return 0;
}

c_audit_t *
c_audit_new(const container_t *container)
{
	ASSERT(container);

	c_audit_t *audit = mem_new0(c_audit_t, 1);

	audit->container = container;

	TRACE("Node ID test: %" PRIx64, uuid_get_node(container_get_uuid(container)));

	audit->container = container;
	audit->last_ack = mem_strdup("");
	audit->processing_ack = false;
	audit->loginuid = UINT32_MAX;

	return audit;
}

char *
c_audit_get_last_ack(const c_audit_t *audit)
{
	ASSERT(audit);
	return audit->last_ack;
}

void
c_audit_set_last_ack(c_audit_t *audit, const char *last_ack)
{
	ASSERT(audit);
	ASSERT(last_ack);

	if (audit->last_ack)
		mem_free0(audit->last_ack);

	audit->last_ack = mem_strdup(last_ack);
}

bool
c_audit_get_processing_ack(const c_audit_t *audit)
{
	ASSERT(audit);
	return audit->processing_ack;
}

void
c_audit_set_processing_ack(c_audit_t *audit, bool processing_ack)
{
	ASSERT(audit);
	audit->processing_ack = processing_ack;
}

void
c_audit_set_loginuid(c_audit_t *audit, uint32_t uid)
{
	ASSERT(audit);
	audit->loginuid = uid;
}

uint32_t
c_audit_get_loginuid(const c_audit_t *audit)
{
	ASSERT(audit);
	return audit->loginuid;
}
