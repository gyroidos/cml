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

#include "c_cap.h"

#include "common/macro.h"

#include <sys/capability.h>
#include <sys/prctl.h>

#define C_CAP_DROP(cap)                                                                            \
	do {                                                                                       \
		DEBUG("Dropping capability %s for %s", #cap,                                       \
		      container_get_description(container));                                       \
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {                                    \
			ERROR_ERRNO("Could not drop capability %s for %s", #cap,                   \
				    container_get_description(container));                         \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

int
c_cap_set_current_process(const container_t *container)
{
	///* 1 */ C_CAP_DROP(CAP_DAC_OVERRIDE); /* does NOT work properly */
	///* 2 */ C_CAP_DROP(CAP_DAC_READ_SEARCH);
	///* 3 */ C_CAP_DROP(CAP_FOWNER); /* does NOT work */
	///* 4 */ C_CAP_DROP(CAP_FSETID);
	///* 6 */ C_CAP_DROP(CAP_SETGID); /* does NOT work */
	///* 7 */ C_CAP_DROP(CAP_SETUID); /* does NOT work */

	/* 9 */ C_CAP_DROP(CAP_LINUX_IMMUTABLE);
	/* 14 */ C_CAP_DROP(CAP_IPC_LOCK);
	/* 15 */ C_CAP_DROP(CAP_IPC_OWNER);
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
	///* 30 */ C_CAP_DROP(CAP_AUDIT_CONTROL); /* needed by logd */

	/* 31 */ C_CAP_DROP(CAP_SETFCAP);

	/* 32 */ C_CAP_DROP(CAP_MAC_OVERRIDE);
	/* 33 */ C_CAP_DROP(CAP_MAC_ADMIN);

	/* 34 */ C_CAP_DROP(CAP_SYSLOG);
	///* 35 */ C_CAP_DROP(CAP_WAKE_ALARM); /* needed by alarm driver */

	/* Use the following for dropping caps only in unprivileged containers */
	if (!container_is_privileged(container) &&
	    container_get_state(container) != CONTAINER_STATE_SETUP) {
		/* 18 */ C_CAP_DROP(CAP_SYS_CHROOT);
		/* 25 */ C_CAP_DROP(CAP_SYS_TIME);
		/* 26 */ C_CAP_DROP(CAP_SYS_TTY_CONFIG);
	}
	if (!container_has_userns(container)) {
		/* 21 */ C_CAP_DROP(CAP_SYS_ADMIN);
	}

	return 0;
}

int
c_cap_start_child(const container_t *container)
{
	return c_cap_set_current_process(container);
}
