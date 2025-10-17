/*
 * This file is part of GyroidOS
 * Copyright(c) 2025 Fraunhofer AISEC
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

#include "unit.h"
#include "common/macro.h"

typedef struct u_perm u_perm_t;

#ifdef UNIT_MODULE_PERM
int
u_perm_allow_dev(u_perm_t *perm, char type, int major, int minor, const char *name);

int
u_perm_deny_dev(u_perm_t *perm, const char *name);

int
u_perm_set_initial_allow_dev(u_perm_t *perm, list_t *device_names);
#else
inline int
u_perm_allow_dev(UNUSED u_perm_t *perm, UNUSED char type, UNUSED int major, UNUSED int minor,
		 UNUSED const char *name)
{
	return 0;
}

inline int
u_perm_deny_dev(UNUSED u_perm_t *perm, UNUSED const char *name)
{
	return 0;
}

int
u_perm_set_initial_allow_dev(UNUSED u_perm_t *perm, UNUSED list_t *device_names)
{
	return 0;
}
#endif /* UNIT_MODULE_PERM */
