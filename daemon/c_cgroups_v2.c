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
#include "common/proc.h"
#include "common/str.h"
#include "common/uuid.h"

#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#define CGROUPS_FOLDER "/sys/fs/cgroup"
char *c_cgroups_subtree = NULL; // in which containers are running in

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

	cgroups->path = mem_printf("%s/%s", c_cgroups_subtree,
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
c_cgroups_add_pid_by_path(char *path, pid_t pid)
{
	ASSERT(path);

	int ret = 0;
	char *cgroup_tasks = mem_printf("%s/cgroup.procs", path);

	/* assign the pid to the cgroup on path */
	if (file_printf(cgroup_tasks, "%d", pid) == -1) {
		ERROR_ERRNO("Could not add pid %d to its cgroup under %s", pid, path);
		ret = -1;
	}

	mem_free0(cgroup_tasks);
	return ret;
}

static int
c_cgroups_add_pid(void *cgroupsp, pid_t pid)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	int ret = 0;

	/*
	 * in v2 we need to be in leaf cgroup. For instance if we are running a
	 * nested systemd as container payload, that one would create some
	 * subcgroups and moves all process out of the container 'root' cgroup.
	 * thus to later join processes into the container's cgroup we have to
	 * directly move that process to such a subcgroup of the container.
	 * 'user.slice' seams to be appropriate for this. Otherwise and
	 * especially the first process would be added to the container's 'root'
         * cgroup.
	 */

	char *user_slice = mem_printf("%s/user.slice", cgroups->path);

	if (file_is_dir(user_slice))
		ret = c_cgroups_add_pid_by_path(user_slice, pid);
	else
		ret = c_cgroups_add_pid_by_path(cgroups->path, pid);

	mem_free0(user_slice);
	return ret;
}

static int
c_cgroups_set_ram_limit(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	if (container_get_ram_limit(cgroups->container) == 0) {
		INFO("Setting no RAM limit for container %s",
		     container_get_description(cgroups->container));
		return 0;
	}

	int ret = -1;
	char *memory_max_path = mem_printf("%s/memory.max", cgroups->path);
	char *mem_max_string = NULL;
	unsigned int mem_max;

	INFO("Trying to set RAM limit of container %s to %d MBytes",
	     container_get_description(cgroups->container),
	     container_get_ram_limit(cgroups->container));

	if (!file_exists(memory_max_path)) {
		ERROR("%s file not found (cgroups not mounted or cgroups memory controler not enabled?)",
		      memory_max_path);
		goto out;
	}
	if (file_printf(memory_max_path, "%uM", container_get_ram_limit(cgroups->container)) ==
	    -1) {
		ERROR("Could not write to cgroups RAM limit file in %s", memory_max_path);
		goto out;
	}

	IF_NULL_GOTO((mem_max_string = file_read_new(memory_max_path, 1024)), out);

	if (sscanf(mem_max_string, "%u", &mem_max) != 1) {
		ERROR("Could not parse cgroups RAM limit file '%s'", memory_max_path);
		goto out;
	}
	// check if the kernel has set the RAM limit correctly
	if (mem_max != container_get_ram_limit(cgroups->container) * 1024 * 1024) {
		ERROR("Requested %uM limit, however kernel has set %u Bytes instead!",
		      container_get_ram_limit(cgroups->container), mem_max);
		goto out;
	}
	INFO("Successfully set RAM limit of container %s to %d MBytes",
	     container_get_description(cgroups->container),
	     container_get_ram_limit(cgroups->container));

	ret = 0;
out:
	mem_free0(memory_max_path);
	mem_free0(mem_max_string);
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

	/* initialize memory subsystem to limit ram to cgroups->ram_limit */
	if (c_cgroups_set_ram_limit(cgroups) < 0) {
		ERROR("Could not configure cgroup maximum ram for container %s",
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

	// mount cgroups if not already mounted by init
	if (!file_is_mountpoint(CGROUPS_FOLDER)) {
		if (mount("cgroup2", CGROUPS_FOLDER, "cgroup2",
			  MS_NOEXEC | MS_NODEV | MS_NOSUID | MS_RELATIME, NULL) == -1 &&
		    errno != EBUSY) {
			FATAL_ERRNO("Could not mount cgroups_v2 unified hirachy");
		}
	}

	// if not running in root cgroup, we have to move ourselves to a leaf cgroup
	// e.g. if the cmld were started by systemd
	char *cgroup_subtree = proc_get_cgroups_path_new(getpid());
	c_cgroups_subtree = mem_printf("%s%s", CGROUPS_FOLDER, cgroup_subtree);
	mem_free0(cgroup_subtree);

	char *cgroup_cmld = mem_printf("%s/cmld", c_cgroups_subtree);

	if (mkdir(cgroup_cmld, 0755) && errno != EEXIST) {
		FATAL_ERRNO("Could not create cgroup %s for cmld's main process!", cgroup_cmld);
	}

	if (c_cgroups_add_pid_by_path(cgroup_cmld, getpid()) == -1)
		FATAL("Could not move cmld to leaf cgroup '%s'", cgroup_cmld);

	// activate controllers
	char *controllers_path = mem_printf("%s/cgroup.controllers", c_cgroups_subtree);
	char *controllers = file_read_new(controllers_path, 4096);

	// remove possible newline
	if (controllers[strlen(controllers) - 1] == '\n')
		controllers[strlen(controllers) - 1] = '\0';

	char *controller = strtok(controllers, " ");
	str_t *activate = str_new_printf("+%s", controller);
	for (controller = strtok(NULL, " "); controller; controller = strtok(NULL, " "))
		str_append_printf(activate, " +%s", controller);

	INFO("activating controllers '%s'", str_buffer(activate));
	char *subtree_control_path = mem_printf("%s/cgroup.subtree_control", c_cgroups_subtree);
	if (-1 == file_printf(subtree_control_path, str_buffer(activate)))
		FATAL("Could not activate cgroup controllers for cmld!");

	str_free(activate, true);
	mem_free0(subtree_control_path);
	mem_free0(controllers_path);
	mem_free0(controllers);
	mem_free0(cgroup_cmld);
}
