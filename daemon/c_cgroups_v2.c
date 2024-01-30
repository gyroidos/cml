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
#include "common/event.h"
#include "common/proc.h"
#include "common/str.h"
#include "common/uuid.h"

#include <sched.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <unistd.h>

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#define CGROUPS_FOLDER "/sys/fs/cgroup"

/* Define timeout for freeze in milliseconds */
#define CGROUPS_FREEZER_TIMEOUT 5000
/* Define the time interval between status checks while freezing */
#define CGROUPS_FREEZER_RETRY_INTERVAL 100

#define CGROUPS_FREEZER_RETRIES CGROUPS_FREEZER_TIMEOUT / CGROUPS_FREEZER_RETRY_INTERVAL

char *c_cgroups_subtree = NULL; // in which containers are running in

typedef struct c_cgroups {
	container_t *container; // weak reference
	bool ns_cgroup;
	char *path;

	bool is_populated;
	bool is_frozen;
	event_inotify_t *inotify_cgroup_events;

	event_timer_t *freeze_timer; /* timer to handle a container freeze timeout */
	int freezer_retries;
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

	cgroups->is_populated = false;
	cgroups->is_frozen = false;
	cgroups->inotify_cgroup_events = NULL;
	cgroups->freeze_timer = NULL;
	cgroups->freezer_retries = 0;
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
c_cgroups_activate_controllers(const char *path)
{
	int ret = 0;

	IF_NULL_RETVAL(path, -1);

	// activate controllers
	char *controllers_path = mem_printf("%s/cgroup.controllers", path);
	char *controllers = file_read_new(controllers_path, 4096);

	// remove possible newline
	if (controllers[strlen(controllers) - 1] == '\n')
		controllers[strlen(controllers) - 1] = '\0';

	char *controller = strtok(controllers, " ");
	str_t *activate = str_new_printf("+%s", controller);
	for (controller = strtok(NULL, " "); controller; controller = strtok(NULL, " "))
		str_append_printf(activate, " +%s", controller);

	INFO("activating controllers '%s'", str_buffer(activate));
	char *subtree_control_path = mem_printf("%s/cgroup.subtree_control", path);
	if (-1 == file_printf(subtree_control_path, str_buffer(activate))) {
		ERROR("Could not activate cgroup controllers for cgroup '%s'!", path);
		ret = -1;
	}

	str_free(activate, true);
	mem_free0(subtree_control_path);
	mem_free0(controllers_path);
	mem_free0(controllers);
	return ret;
}

static int
c_cgroups_add_pid_by_path(const char *path, pid_t pid)
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
	 * A subcgroup in 'user.slice' seams to be appropriate for this. Otherwise
	 * processes would be added to a subcgroup of the container's 'root'
	 * cgroup.
	 * In the 'start_pre_exec' hook we apply another indirection (subcgroup
	 * for container child). This is at least needed to run systemd as
	 * container payload. We have to consider this intermediate cgroup here,
	 * too.
	 */

	char *cgroups_child_path = mem_printf("%s/child", cgroups->path);
	char *user_slice = mem_printf("%s/user.slice", cgroups_child_path);

	char *cgroups_leaf_path = mem_printf(
		"%s/cmld-injected", file_is_dir(user_slice) ? user_slice : cgroups_child_path);

	if (dir_mkdir_p(cgroups_leaf_path, 0755)) {
		ERROR("Cannot create leaf cgroup %s for pid=%d in container %s", cgroups_leaf_path,
		      pid, container_get_name(cgroups->container));
		ret = -1;
		goto out;
	}

	int u_g_id = container_get_pid(cgroups->container);
	if (chown(cgroups_leaf_path, u_g_id, u_g_id)) {
		ERROR_ERRNO("Cannot chown leaf cgroup %s for pid=%d in container %s",
			    cgroups_leaf_path, pid, container_get_name(cgroups->container));
		ret = -1;
		goto out;
	}

	ret = c_cgroups_add_pid_by_path(cgroups_leaf_path, pid);

out:
	mem_free0(cgroups_leaf_path);
	mem_free0(user_slice);
	mem_free0(cgroups_child_path);
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
	if (mem_max_string)
		mem_free0(mem_max_string);
	return ret;
}

/**
 * This functions gets the allowed cpus for the container from its associated container
 * object and configures the cgroups cpuset subsystem to restrict access to that cpus.
 */
static int
c_cgroups_set_cpus_allowed(const c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	if (NULL == container_get_cpus_allowed(cgroups->container)) {
		INFO("Setting no CPU restrictions for container %s",
		     container_get_description(cgroups->container));
		return 0;
	}

	int ret = -1;
	char *cpuset_cpus_path = mem_printf("%s/cpuset.cpus", cgroups->path);
	char *cpuset_mems_path = mem_printf("%s/cpuset.mems", cgroups->path);

	if (!file_exists(cpuset_cpus_path)) {
		ERROR("%s file not found (cgroups or cgroups cpuset subsystem not mounted?)",
		      cpuset_cpus_path);
		goto out;
	}
	if (file_printf(cpuset_cpus_path, "%s", container_get_cpus_allowed(cgroups->container)) ==
	    -1) {
		ERROR("Could not write to cgroups cpuset file in %s", cpuset_cpus_path);
		goto out;
	}

	if (!file_exists(cpuset_mems_path)) {
		ERROR("%s file not found (cgroups or cgroups cpuset subsystem not mounted?)",
		      cpuset_mems_path);
		goto out;
	}
	if (file_printf(cpuset_mems_path, "0") == -1) {
		ERROR("Could not write to cgroups cpuset file in %s", cpuset_mems_path);
		goto out;
	}

	INFO("Successfully set CPU restriction of container %s to cores %s",
	     container_get_description(cgroups->container),
	     container_get_cpus_allowed(cgroups->container));

	ret = 0;
out:
	mem_free0(cpuset_cpus_path);
	mem_free0(cpuset_mems_path);

	return ret;
}

static void
c_cgroups_event_populated(c_cgroups_t *cgroups, bool is_populated)
{
	ASSERT(cgroups);

	cgroups->is_populated = is_populated;

	DEBUG("Cgroup for container %s is %s", container_get_description(cgroups->container),
	      is_populated ? "populated" : "empty");
}

static void
c_cgroups_cleanup_freeze_timer(c_cgroups_t *cgroups)
{
	ASSERT(cgroups);

	if (cgroups->freeze_timer) {
		DEBUG("Remove container freeze timer for %s",
		      container_get_description(cgroups->container));
		event_remove_timer(cgroups->freeze_timer);
		event_timer_free(cgroups->freeze_timer);
		cgroups->freeze_timer = NULL;
	}
	cgroups->freezer_retries = 0;
}

static void
c_cgroups_event_freezer(c_cgroups_t *cgroups, bool is_frozen)
{
	ASSERT(cgroups);

	cgroups->is_frozen = is_frozen;

	DEBUG("State of freezer for container %s is %s",
	      container_get_description(cgroups->container), is_frozen ? "frozen" : "thawed");

	compartment_state_t compartment_state = container_get_state(cgroups->container);

	if (!is_frozen && (compartment_state == COMPARTMENT_STATE_FREEZING ||
			   compartment_state == COMPARTMENT_STATE_FROZEN)) {
		INFO("Container %s thawed from freezing or frozen state",
		     container_get_description(cgroups->container));
		c_cgroups_cleanup_freeze_timer(cgroups);
		container_set_state(cgroups->container, COMPARTMENT_STATE_RUNNING);
	} else if (is_frozen && (compartment_state != COMPARTMENT_STATE_FROZEN)) {
		INFO("Container %s frozen", container_get_description(cgroups->container));
		c_cgroups_cleanup_freeze_timer(cgroups);
		container_set_state(cgroups->container, COMPARTMENT_STATE_FROZEN);
	}
}

static void
c_cgroups_events_cb(UNUSED const char *path, UNUSED uint32_t mask, UNUSED event_inotify_t *inotify,
		    void *data)
{
	c_cgroups_t *cgroups = data;

	ASSERT(cgroups);

	char *cgroup_events_path = mem_printf("%s/cgroup.events", cgroups->path);
	char *state_str = file_read_new(cgroup_events_path, 1024);
	mem_free0(cgroup_events_path);

	int frozen = 0, populated = 0;
	char *event_line = strtok(state_str, "\n");
	while (event_line) {
		if (sscanf(event_line, "populated %d", &populated) == 1) {
			bool is_populated = populated ? true : false;
			if (is_populated != cgroups->is_populated)
				c_cgroups_event_populated(cgroups, is_populated);
		}
		if (sscanf(event_line, "frozen %d", &frozen) == 1) {
			bool is_frozen = frozen ? true : false;
			if (is_frozen != cgroups->is_frozen)
				c_cgroups_event_freezer(cgroups, is_frozen);
		}
		event_line = strtok(NULL, "\n");
	}
	mem_free0(state_str);
}

static int
c_cgroups_unfreeze(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	char *freezer_state_path = mem_printf("%s/cgroup.freeze", cgroups->path);
	if (file_write(freezer_state_path, "0", -1) == -1) {
		ERROR_ERRNO("Failed to write to freezer file %s", freezer_state_path);
		mem_free0(freezer_state_path);
		return -1;
	}
	mem_free0(freezer_state_path);
	return 0;
}

static void
c_cgroups_freeze_timeout_cb(UNUSED event_timer_t *timer, void *data)
{
	ASSERT(data);

	c_cgroups_t *cgroups = data;

	DEBUG("Checking state of the freezing process (try no. %d)", cgroups->freezer_retries + 1);

	if (cgroups->freezer_retries < CGROUPS_FREEZER_RETRIES) {
		cgroups->freezer_retries++;
		// trigger state update of container
		c_cgroups_event_freezer(cgroups, cgroups->is_frozen);
		return;
	}

	compartment_state_t compartment_state = container_get_state(cgroups->container);
	if (compartment_state == COMPARTMENT_STATE_FREEZING) {
		WARN("Hit timeout for freezing container %s, aborting freeze...",
		     container_get_description(cgroups->container));

		if (c_cgroups_unfreeze(cgroups) < 0) {
			WARN("Could not abort freeze for container %s",
			     container_get_description(cgroups->container));
		} else {
			WARN("Freeze for container %s aborted",
			     container_get_description(cgroups->container));
		}
	}

	c_cgroups_cleanup_freeze_timer(cgroups);
}

static int
c_cgroups_freeze(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	compartment_state_t state = container_get_state(cgroups->container);
	switch (state) {
	case COMPARTMENT_STATE_FROZEN:
	case COMPARTMENT_STATE_FREEZING:
		DEBUG("Container already frozen or freezing, doing nothing...");
		return 0;
	case COMPARTMENT_STATE_RUNNING:
	case COMPARTMENT_STATE_SETUP:
		break; // actually do freeze
	default:
		WARN("Container not running");
		return -1;
	}

	char *freezer_state_path = mem_printf("%s/cgroup.freeze", cgroups->path);
	if (file_write(freezer_state_path, "1", -1) == -1) {
		ERROR_ERRNO("Failed to write to freezer file %s", freezer_state_path);
		mem_free0(freezer_state_path);
		return -1;
	}

	/* register a timer to stop the freeze if it does not complete in time */
	cgroups->freeze_timer = event_timer_new(CGROUPS_FREEZER_RETRY_INTERVAL, -1,
						&c_cgroups_freeze_timeout_cb, cgroups);
	event_add_timer(cgroups->freeze_timer);

	container_set_state(cgroups->container, COMPARTMENT_STATE_FREEZING);

	mem_free0(freezer_state_path);
	return 0;
}

static int
c_cgroups_start_post_clone(void *cgroupsp)
{
	c_cgroups_t *cgroups = cgroupsp;
	ASSERT(cgroups);

	int ret = -COMPARTMENT_ERROR_CGROUPS;
	char *cgroups_child_path = NULL;

	INFO("Creating cgroup %s", cgroups->path);

	/* the cgroup is created simply by creating a directory in our default hierarchy */
	if (mkdir(cgroups->path, 0755) && errno != EEXIST) {
		ERROR_ERRNO("Could not create cgroup %s for container %s", cgroups->path,
			    container_get_description(cgroups->container));
		goto out;
	}

	/* initialize memory subsystem to limit ram to cgroups->ram_limit */
	if (c_cgroups_set_ram_limit(cgroups) < 0) {
		ERROR("Could not configure cgroup maximum ram for container %s",
		      container_get_description(cgroups->container));
		goto out;
	}

	/* initialize cpuset child subsystem to limit access to allowed cpus */
	if (c_cgroups_set_cpus_allowed(cgroups) < 0) {
		ERROR("Could not configure cgroup to restrict cpus of container %s",
		      container_get_description(cgroups->container));
		goto out;
	}

	/* initialize events handling, e.g., for freezer subsystem */
	char *events_path = mem_printf("%s/cgroup.events", cgroups->path);
	cgroups->inotify_cgroup_events =
		event_inotify_new(events_path, IN_MODIFY, &c_cgroups_events_cb, cgroups);
	int error = event_add_inotify(cgroups->inotify_cgroup_events);
	if (error && error != -EEXIST) {
		ERROR("Could not register inotify event for cgroups events!");
		goto out;
	}

	mem_free0(events_path);

	// activate controllers
	if (c_cgroups_activate_controllers(cgroups->path)) {
		ERROR("Could not activate cgroup controllers for intermediate cgroup!");
		goto out;
	}

	/*
	 * apply another indirection (subcgroup for container child) This is at
	 * least needed to run systmd as container payload:
	 *
	 * "A container manager that is itself a payload of a host systemd
	 *  which wants to run a systemd as its own container payload instead
	 *  hence needs to insert an extra level in the hierarchy in between,
	 *  so that the systemd on the host and the one in the container won’t
	 *  fight for the attributes" [https://systemd.io/CGROUP_DELEGATION/]
	 */
	cgroups_child_path = mem_printf("%s/child", cgroups->path);

	if (mkdir(cgroups_child_path, 0755) && errno != EEXIST) {
		ERROR_ERRNO("Could not create cgroup %s for container %s", cgroups_child_path,
			    container_get_description(cgroups->container));
		goto out;
	}

	if (c_cgroups_add_pid_by_path(cgroups_child_path, container_get_pid(cgroups->container))) {
		ERROR("Could not join container to child cgroup!");
		goto out;
	}

	if (container_shift_ids(cgroups->container, cgroups_child_path, cgroups_child_path, NULL)) {
		ERROR("Could not shift ids of cgroup '%s' for userns", cgroups_child_path);
		goto out;
	}

	ret = 0;
out:
	if (cgroups_child_path)
		mem_free0(cgroups_child_path);
	return ret;
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

	/* remove inotify events handling */
	if (cgroups->inotify_cgroup_events) {
		event_remove_inotify(cgroups->inotify_cgroup_events);
		event_inotify_free(cgroups->inotify_cgroup_events);
		cgroups->inotify_cgroup_events = NULL;
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
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = c_cgroups_start_pre_exec_child,
	.stop = NULL,
	.cleanup = c_cgroups_cleanup,
	.join_ns = NULL,
};

void
c_cgroups_deinit(void)
{
	// free global memory alloctaions
	if (c_cgroups_subtree)
		mem_free0(c_cgroups_subtree);
}

static void INIT
c_cgroups_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_cgroups_module);

	// register relevant handlers implemented by this module
	container_register_add_pid_to_cgroups_handler(MOD_NAME, c_cgroups_add_pid);
	container_register_freeze_handler(MOD_NAME, c_cgroups_freeze);
	container_register_unfreeze_handler(MOD_NAME, c_cgroups_unfreeze);

	// register cleanup on exit handler
	if (atexit(&c_cgroups_deinit))
		WARN("Could not register on exit deinit method 'c_cgroups_deinit()'");

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
	if (c_cgroups_activate_controllers(c_cgroups_subtree))
		FATAL("Could not activate cgroup controllers for cmld!");

	mem_free0(cgroup_cmld);
}
