/*
 * This file is part of GyroidOS
 * Copyright(c) 2022 Fraunhofer AISEC
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
 * @file c_cgroups_v2.c
 *
 * This submodule provides functionality to setup control groups for containers.
 * This includes configurations like the max ram for a container and the functionality
 * to freeze and unfreeze a container.
 */

#define MOD_NAME "c_cgroups_v2"

#define _GNU_SOURCE

#include "container.h"

#include "common/mem.h"
#include "common/macro.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/uuid.h"

#include <sched.h>
#include <unistd.h>

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#define CGROUPS_FOLDER "/sys/fs/cgroup"

typedef struct c_cgroups {
	container_t *container; // weak reference
	bool ns_cgroup;
	char *path;
} c_cgroups_t;

static void *
c_cgroups_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_cgroups_t *cgroups = mem_new0(c_cgroups_t, 1);
	cgroups->container = compartment_get_extension_data(compartment);

	cgroups->ns_cgroup = file_exists("/proc/self/ns/cgroup");

	cgroups->path = mem_printf("%s/%s", CGROUPS_FOLDER,
				   uuid_string(container_get_uuid(cgroups->container)));
	return cgroups;
}

static void
c_cgroups_free(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	mem_free0(cgroups->path);
	mem_free0(cgroups);
}

static int
c_cgroups_add_pid(void *cgroupsp, pid_t pid)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);
	int ret = 0;

	char *cgroup_tasks = mem_printf("%s/cgroup.procs", cgroups->path);

	/* assign the container to the cgroup */
	if (file_printf(cgroup_tasks, "%d", pid) == -1) {
		ERROR_ERRNO("Could not add container %s to its cgroup under %s/%s",
			    container_get_description(cgroups->container), CGROUPS_FOLDER,
			    uuid_string(container_get_uuid(cgroups->container)));
		ret = -1;
	}

	mem_free0(cgroup_tasks);
	return ret;
}

static int
c_cgroups_start_post_clone(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	INFO("Creating cgroup %s", cgroups->path);

	/* the cgroup is created simply by creating a directory in our default hierarchy */
	if (mkdir(cgroups->path, 0755) && errno != EEXIST) {
		ERROR_ERRNO("Could not create cgroup %s for container %s", cgroups->path,
			    container_get_description(cgroups->container));
		return -COMPARTMENT_ERROR_CGROUPS;
	}

	return 0;
}

static int
c_cgroups_start_pre_exec(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	IF_TRUE_RETVAL(c_cgroups_add_pid(cgroups, container_get_pid(cgroups->container)),
		       -COMPARTMENT_ERROR_CGROUPS);

	if (container_shift_ids(cgroups->container, cgroups->path, cgroups->path, NULL)) {
		ERROR("Could not shift ids of cgroup '%s' for userns", cgroups->path);
		return -COMPARTMENT_ERROR_CGROUPS;
	}

	return 0;
}

static int
c_cgroups_start_pre_exec_child(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	/* check if cgroupns is supported else do nothing */
	IF_FALSE_RETVAL_TRACE(cgroups->ns_cgroup, 0);

	if (unshare(CLONE_NEWCGROUP) == -1) {
		WARN_ERRNO("Could not unshare cgroup namespace!");
		return -COMPARTMENT_ERROR_CGROUPS;
	}

	INFO("Successfully created new cgroup namespace for container %s",
	     container_get_name(cgroups->container));

	return 0;
}

static int
c_cgroups_cleanup_subtree_remove_cb(const char *path, const char *name, UNUSED void *data)
{
	int ret = 0;
	char *file_to_remove = mem_printf("%s/%s", path, name);
	if (file_is_dir(file_to_remove)) {
		TRACE("Removing cgroup subtree in %s is dir", file_to_remove);
		if (dir_foreach(file_to_remove, &c_cgroups_cleanup_subtree_remove_cb, NULL) < 0) {
			ERROR_ERRNO("Could not delete cgroup subtree contents in %s",
				    file_to_remove);
			ret--;
		}
		TRACE("Removing now empty subtree %s", file_to_remove);
		if (rmdir(file_to_remove) < 0) {
			ERROR_ERRNO("Could not delete cgroup subtree %s", file_to_remove);
			ret--;
		}
	}
	mem_free0(file_to_remove);
	return ret;
}

static void
c_cgroups_cleanup(void *cgroupsp, UNUSED bool is_rebooting)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	if (file_exists(cgroups->path) && file_is_dir(cgroups->path)) {
		/* recursively remove all subfolders which the container may have created */
		if (dir_foreach(cgroups->path, &c_cgroups_cleanup_subtree_remove_cb, NULL) < 0) {
			WARN_ERRNO("Could not remove cgroup v2 for container %s",
				   container_get_description(cgroups->container));
		} else if (rmdir(cgroups->path) < 0) {
			WARN_ERRNO("Could not delete cgroup %s", cgroups->path);
		} else {
			INFO("Removed cgroup for container %s",
			     container_get_description(cgroups->container));
		}
	}
}

static compartment_module_t c_cgroups_module = {
	.name = MOD_NAME,
	.compartment_new = c_cgroups_new,
	.compartment_free = c_cgroups_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = c_cgroups_start_post_clone,
	.start_pre_exec = c_cgroups_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = c_cgroups_start_pre_exec_child,
	.stop = NULL,
	.cleanup = c_cgroups_cleanup,
	.join_ns = NULL,
};

static void INIT
c_cgroups_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_cgroups_module);

	// register relevant handlers implemented by this module
	container_register_add_pid_to_cgroups_handler(MOD_NAME, c_cgroups_add_pid);
}
