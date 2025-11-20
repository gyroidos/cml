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

/**
 * @file u_time.c
 *
 * This module is responsible for provideing uptime and creation time for units.
 */

#define _GNU_SOURCE

#define MOD_NAME "c_time"

#include "common/macro.h"
#include "common/mem.h"
#include "compartment.h"
#include "u_time.h"
#include "unit.h"

#include <sys/time.h>

struct u_time {
	time_t time_created;
	time_t time_started;
};

/**
 * This function allocates a new u_time_t instance, associated to a specific unit object.
 * @return the u_time_t time structure which holds  for an unit.
 */
static void *
u_time_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	u_time_t *_time = mem_new0(u_time_t, 1);
	_time->time_created = time(NULL);

	return _time;
}

/**
 * Frees the u_time_t structure
 */
static void
u_time_free(void *timep)
{
	u_time_t *time = timep;
	ASSERT(time);

	mem_free0(time);
}

static int
u_time_start_post_exec(void *timep)
{
	u_time_t *_time = timep;
	ASSERT(_time);
	_time->time_started = time(NULL);
	return 0;
}

time_t
u_time_get_creation_time(const u_time_t *u_time)
{
	ASSERT(u_time);
	if (u_time->time_created < 0)
		return 0;
	return u_time->time_created;
}

time_t
u_time_get_uptime(const u_time_t *u_time)
{
	ASSERT(u_time);
	if (u_time->time_started < 0)
		return 0;

	time_t uptime = time(NULL) - u_time->time_started;
	return (uptime < 0) ? 0 : uptime;
}

static compartment_module_t u_time_module = {
	.name = MOD_NAME,
	.compartment_new = u_time_new,
	.compartment_free = u_time_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = u_time_start_post_exec,
	.start_pre_exec_child_early = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
u_time_init(void)
{
	// register this module in unit.c
	unit_register_compartment_module(&u_time_module);
}
