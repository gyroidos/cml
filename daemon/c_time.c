/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#define _GNU_SOURCE
#include "c_time.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"

#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

struct c_time {
	const container_t *container;
	bool ns_time;
};

static long
c_time_get_clock_secs(clockid_t clock)
{
	struct timespec ts;
	IF_TRUE_RETVAL(clock_gettime(clock, &ts) == -1, 0);
	return ts.tv_sec;
}

c_time_t *
c_time_new(container_t *container)
{
	c_time_t *time = mem_new0(c_time_t, 1);
	time->container = container;
	time->ns_time = file_exists("/proc/self/ns/time");
	return time;
}

void
c_time_free(c_time_t *time)
{
	ASSERT(time);
	mem_free(time);
}

int
c_time_start_child(const c_time_t *time)
{
	ASSERT(time);

	/* check if timens is supported else do nothing */
	IF_FALSE_RETVAL_TRACE(time->ns_time, 0);

	/* since timens can not be set with clone directly do it now in the child */
	if (unshare(CLONE_NEWTIME) == -1) {
		ERROR_ERRNO("Could not unshare time namespace!");
		return -1;
	}

	INFO("Successfully created new time namespace for container %s",
	     container_get_name(time->container));
	return 0;
}

int
c_time_start_pre_exec(const c_time_t *time)
{
	ASSERT(time);

	/* check if timens is supported else do nothing */
	IF_FALSE_RETVAL_TRACE(time->ns_time, 0);

	char *path_timens_offsets =
		mem_printf("/proc/%d/timens_offsets", container_get_pid(time->container));

	long boottime = c_time_get_clock_secs(CLOCK_BOOTTIME);
	long monotonic = c_time_get_clock_secs(CLOCK_MONOTONIC);

	if (file_printf(path_timens_offsets, "boottime -%ld 0", boottime) == -1) {
		ERROR_ERRNO("Could not reset boottime -%ld 0", boottime);
		goto error;
	}
	if (file_printf(path_timens_offsets, "monotonic -%ld 0", monotonic) == -1) {
		ERROR_ERRNO("Could not reset monotonic -%ld 0", monotonic);
		goto error;
	}
	INFO("Successfully updated timens offsets in new time namespace");

	mem_free(path_timens_offsets);
	return 0;
error:
	mem_free(path_timens_offsets);
	return -1;
}

int
c_time_start_pre_exec_child(const c_time_t *time)
{
	ASSERT(time);

	/* check if timens is supported else do nothing */
	IF_FALSE_RETVAL_TRACE(time->ns_time, 0);

	int nsfd = -1;
	if ((nsfd = open("/proc/self/ns/time_for_children", O_RDONLY)) < 0) {
		ERROR_ERRNO("Could not open namespace file for timens");
		return -1;
	}
	if (setns(nsfd, 0) == -1) {
		ERROR_ERRNO("Could not join time namespace");
		goto error;
	}
	INFO("Successfully moved init process of container %s to new time namespace",
	     container_get_name(time->container));
	close(nsfd);
	return 0;
error:
	close(nsfd);
	return -1;
}
