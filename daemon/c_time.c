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

/*
 * @file c_time.c
 *
 * This module implements the new time namespace available since Linux 5.6.
 * It resest the available clocks for boottime and monotonic by setting the
 * corresponding offsets to the negated current system values.
 * Thus, for instance uptime will show the time since a container was started
 * and not the overall system uptime.
 *
 * Time namespace could not be activated by clone directly but only by a call
 * to unshare. After unshare the calling process is not directly part of the
 * new time namespace, to be allowed to set the new clock offsets. All
 * children will be placed in the new time namespace. To put the later init
 * process of a container also to the new time namespace, a call to setns
 * using /proc/self/time_for_children does the trick.
 */

#define _GNU_SOURCE

#define MOD_NAME "c_time"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "container.h"

#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

typedef struct c_time {
	const container_t *container;
	bool ns_time;
	time_t time_started;
	time_t time_created;
} c_time_t;

/*
 * if we create the container for the first time, we store its creation time
 * in a file, otherwise this functions reads the creation time from that file
 */
static time_t
c_time_get_creation_time_from_file(c_time_t *_time)
{
	time_t ret = -1;
	char *file_name_created =
		mem_printf("%s.created", container_get_images_dir(_time->container));
	if (!file_exists(file_name_created)) {
		ret = time(NULL);
		if (file_write(file_name_created, (char *)&ret, sizeof(ret)) < 0) {
			WARN("Failed to store creation time of container %s",
			     uuid_string(container_get_uuid(_time->container)));
		}
	} else {
		if (file_read(file_name_created, (char *)&ret, sizeof(ret)) < 0) {
			WARN("Failed to get creation time for container %s",
			     uuid_string(container_get_uuid(_time->container)));
		}
	}
	INFO("container %s was created at %s", uuid_string(container_get_uuid(_time->container)),
	     ctime(&ret));

	mem_free0(file_name_created);
	return ret;
}

static long
c_time_get_clock_secs(clockid_t clock)
{
	struct timespec ts;
	IF_TRUE_RETVAL(clock_gettime(clock, &ts) == -1, 0);
	return ts.tv_sec;
}

static void *
c_time_new(container_t *container)
{
	c_time_t *time = mem_new0(c_time_t, 1);
	time->container = container;
	time->ns_time = file_exists("/proc/self/ns/time");
	time->time_started = -1;
	time->time_created = c_time_get_creation_time_from_file(time);
	return time;
}

static void
c_time_free(void *timep)
{
	c_time_t *time = timep;
	ASSERT(time);
	mem_free0(time);
}

static int
c_time_start_child(void *timep)
{
	c_time_t *time = timep;
	ASSERT(time);

	/* check if timens is supported else do nothing */
	IF_FALSE_RETVAL_TRACE(time->ns_time, 0);

	/* since timens can not be set with clone directly do it now in the child */
	if (unshare(CLONE_NEWTIME) == -1) {
		ERROR_ERRNO("Could not unshare time namespace!");
		return -CONTAINER_ERROR_TIME;
	}

	INFO("Successfully created new time namespace for container %s",
	     container_get_name(time->container));
	return 0;
}

static int
c_time_start_pre_exec(void *timep)
{
	c_time_t *time = timep;
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

	mem_free0(path_timens_offsets);
	return 0;
error:
	mem_free0(path_timens_offsets);
	return -CONTAINER_ERROR_TIME;
}

static int
c_time_start_post_exec(void *timep)
{
	c_time_t *_time = timep;
	ASSERT(_time);
	_time->time_started = time(NULL);
	return 0;
}

static int
c_time_start_pre_exec_child(void *timep)
{
	c_time_t *time = timep;
	ASSERT(time);

	/* check if timens is supported else do nothing */
	IF_FALSE_RETVAL_TRACE(time->ns_time, 0);

	int nsfd = -1;
	if ((nsfd = open("/proc/self/ns/time_for_children", O_RDONLY)) < 0) {
		ERROR_ERRNO("Could not open namespace file for timens");
		return -CONTAINER_ERROR_TIME;
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
	return -CONTAINER_ERROR_TIME;
}

static time_t
c_time_get_creation_time(void *timep)
{
	c_time_t *time = timep;
	ASSERT(time);
	if (time->time_created < 0)
		return 0;
	return time->time_created;
}

static time_t
c_time_get_uptime(void *timep)
{
	c_time_t *_time = timep;
	ASSERT(_time);
	if (_time->time_started < 0)
		return 0;

	time_t uptime = time(NULL) - _time->time_started;
	return (uptime < 0) ? 0 : uptime;
}

static void
c_time_cleanup(void *timep, UNUSED bool rebooting)
{
	c_time_t *time = timep;
	ASSERT(time);
	time->time_started = -1;
}

static container_module_t c_time_module = {
	.name = MOD_NAME,
	.container_new = c_time_new,
	.container_free = c_time_free,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = c_time_start_pre_exec,
	.start_post_exec = c_time_start_post_exec,
	.start_child = c_time_start_child,
	.start_pre_exec_child = c_time_start_pre_exec_child,
	.stop = NULL,
	.cleanup = c_time_cleanup,
	.join_ns = NULL,
};

static void INIT
c_time_init(void)
{
	// register this module in container.c
	container_register_module(&c_time_module);

	// register relevant handlers implemented by this module
	container_register_get_creation_time_handler(MOD_NAME, c_time_get_creation_time);
	container_register_get_uptime_handler(MOD_NAME, c_time_get_uptime);
}
