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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define MOD_NAME "c_audit"

#include "common/mem.h"
#include "common/uuid.h"
#include "common/macro.h"
#include "common/file.h"
#include "common/audit.h"
#include "container.h"

#include <string.h>
#include <unistd.h>
#include <inttypes.h>

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

typedef struct c_audit {
	const container_t *container;
	char *last_ack;
	bool processing_ack;
	uint32_t loginuid;
} c_audit_t;

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

static int
c_audit_start_post_clone_early(void *auditp)
{
	c_audit_t *audit = auditp;
	ASSERT(audit);

	// update kernel container id
	if (c_audit_set_contid(audit) < 0)
		return -COMPARTMENT_ERROR_AUDIT;

	return 0;
}

static int
c_audit_start_child_early(void *auditp)
{
	c_audit_t *audit = auditp;
	ASSERT(audit);

	// update kernel login uid with internal set loginuid
	if (audit_kernel_write_loginuid(audit->loginuid)) {
		ERROR("Could not set loginuid!");
		return -COMPARTMENT_ERROR_AUDIT;
	}
	return 0;
}

static void *
c_audit_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_audit_t *audit = mem_new0(c_audit_t, 1);
	audit->container = compartment_get_extension_data(compartment);

	TRACE("Node ID test: %" PRIx64, uuid_get_node(container_get_uuid(audit->container)));

	audit->last_ack = mem_strdup("");
	audit->processing_ack = false;
	audit->loginuid = UINT32_MAX;

	return audit;
}

static void
c_audit_free(void *auditp)
{
	c_audit_t *audit = auditp;
	ASSERT(audit);

	if (audit->last_ack)
		mem_free0(audit->last_ack);

	mem_free0(audit);
}

static const char *
c_audit_get_last_ack(void *auditp)
{
	c_audit_t *audit = auditp;
	ASSERT(audit);
	return (const char *)audit->last_ack;
}

static int
c_audit_set_last_ack(void *auditp, const char *last_ack)
{
	c_audit_t *audit = auditp;
	ASSERT(audit);
	ASSERT(last_ack);

	if (audit->last_ack)
		mem_free0(audit->last_ack);

	audit->last_ack = mem_strdup(last_ack);

	return 0;
}

static bool
c_audit_get_processing_ack(void *auditp)
{
	c_audit_t *audit = auditp;
	ASSERT(audit);
	return audit->processing_ack;
}

static int
c_audit_set_processing_ack(void *auditp, bool processing_ack)
{
	c_audit_t *audit = auditp;
	ASSERT(audit);
	audit->processing_ack = processing_ack;

	return 0;
}

static int
c_audit_set_loginuid(void *auditp, uint32_t uid)
{
	c_audit_t *audit = auditp;
	ASSERT(audit);
	audit->loginuid = uid;

	return 0;
}

uint32_t
c_audit_get_loginuid(void *auditp)
{
	c_audit_t *audit = auditp;
	ASSERT(audit);
	return audit->loginuid;
}

static compartment_module_t c_audit_module = {
	.name = MOD_NAME,
	.compartment_new = c_audit_new,
	.compartment_free = c_audit_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = c_audit_start_post_clone_early,
	.start_child_early = c_audit_start_child_early,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child_early = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
c_audit_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_audit_module);

	// register relevant handlers implemented by this module
	container_register_audit_get_last_ack_handler(MOD_NAME, c_audit_get_last_ack);
	container_register_audit_set_last_ack_handler(MOD_NAME, c_audit_set_last_ack);
	container_register_audit_get_processing_ack_handler(MOD_NAME, c_audit_get_processing_ack);
	container_register_audit_set_processing_ack_handler(MOD_NAME, c_audit_set_processing_ack);
	container_register_audit_get_loginuid_handler(MOD_NAME, c_audit_get_loginuid);
	container_register_audit_set_loginuid_handler(MOD_NAME, c_audit_set_loginuid);
}
