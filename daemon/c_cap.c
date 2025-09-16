/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
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

#define MOD_NAME "c_cap"

#include "common/macro.h"
#include "common/mem.h"
#include "container.h"

#include <linux/capability.h>
#include <sys/prctl.h>

#define C_CAP_DROP(cap)                                                                            \
	do {                                                                                       \
		DEBUG("Dropping capability %s:%d for %s", #cap, cap,                               \
		      container_get_description(container));                                       \
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {                                    \
			ERROR_ERRNO("Could not drop capability %s:%d for %s", #cap, cap,           \
				    container_get_description(container));                         \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

typedef struct c_cap {
	container_t *container;
	compartment_t *compartment;
} c_cap_t;

static void *
c_cap_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_cap_t *cap = mem_new0(c_cap_t, 1);
	cap->container = compartment_get_extension_data(compartment);
	cap->compartment = compartment;

	return cap;
}

static void
c_cap_free(void *capp)
{
	c_cap_t *cap = capp;
	ASSERT(cap);
	mem_free0(cap);
}

static int
c_cap_set_current_process(void *capp)
{
	c_cap_t *cap = capp;
	ASSERT(cap);

	// C_CAP_DROP macro needs variable container
	const container_t *container = cap->container;

	///* 1 */ C_CAP_DROP(CAP_DAC_OVERRIDE); /* does NOT work properly */
	///* 2 */ C_CAP_DROP(CAP_DAC_READ_SEARCH);
	///* 3 */ C_CAP_DROP(CAP_FOWNER); /* does NOT work */
	///* 4 */ C_CAP_DROP(CAP_FSETID);
	///* 6 */ C_CAP_DROP(CAP_SETGID); /* does NOT work */
	///* 7 */ C_CAP_DROP(CAP_SETUID); /* does NOT work */

	/* 9 */ C_CAP_DROP(CAP_LINUX_IMMUTABLE);
	/* 15 */ C_CAP_DROP(CAP_IPC_OWNER);
	if (!(COMPARTMENT_FLAG_MODULE_LOAD & compartment_get_flags(cap->compartment)))
		/* 16 */ C_CAP_DROP(CAP_SYS_MODULE);
	///* 17 */ C_CAP_DROP(CAP_SYS_RAWIO); /* does NOT work */
#ifndef DEBUG_BUILD
	/* 19 */ C_CAP_DROP(CAP_SYS_PTRACE);
#endif
	/* 20 */ C_CAP_DROP(CAP_SYS_PACCT);
	///* 22 */ C_CAP_DROP(CAP_SYS_BOOT);

	///* 23 */ C_CAP_DROP(CAP_SYS_NICE); /* Is needed for some usecases*/
	///* 24 */ C_CAP_DROP(CAP_SYS_RESOURCE); /* does NOT work */
	/* 28 */ C_CAP_DROP(CAP_LEASE);

	///* 29 */ C_CAP_DROP(CAP_AUDIT_WRITE); /* needed for console/X11 login */
	/* 30 */ C_CAP_DROP(CAP_AUDIT_CONTROL);

	/* 31 */ C_CAP_DROP(CAP_SETFCAP);

	/* 32 */ C_CAP_DROP(CAP_MAC_OVERRIDE);
	/* 33 */ C_CAP_DROP(CAP_MAC_ADMIN);

	/* 34 */ C_CAP_DROP(CAP_SYSLOG);
	///* 35 */ C_CAP_DROP(CAP_WAKE_ALARM); /* needed by alarm driver */

	if (container_has_userns(container))
		return 0;

	/* 21 */ C_CAP_DROP(CAP_SYS_ADMIN);
	/* 14 */ C_CAP_DROP(CAP_IPC_LOCK);

	/* Use the following for dropping caps only in unprivileged containers */
	if (!container_is_privileged(container) &&
	    container_get_state(container) != COMPARTMENT_STATE_SETUP) {
		/* 18 */ C_CAP_DROP(CAP_SYS_CHROOT);
		/* 25 */ C_CAP_DROP(CAP_SYS_TIME);
		/* 26 */ C_CAP_DROP(CAP_SYS_TTY_CONFIG);
	}

	return 0;
}

static int
c_cap_start_child(void *capp)
{
	c_cap_t *cap = capp;
	ASSERT(cap);

	if (c_cap_set_current_process(cap))
		return -COMPARTMENT_ERROR;

	return 0;
}

static compartment_module_t c_cap_module = {
	.name = MOD_NAME,
	.compartment_new = c_cap_new,
	.compartment_free = c_cap_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = c_cap_start_child,
	.start_pre_exec_child_early = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
c_cap_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_cap_module);

	// register relevant handlers implemented by this module
	container_register_set_cap_current_process_handler(MOD_NAME, c_cap_set_current_process);
}
