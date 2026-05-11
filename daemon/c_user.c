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

#define _GNU_SOURCE

#define MOD_NAME "c_user"

#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <sys/mount.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/ns.h"
#include "container.h"
#include "cmld.h"

#define UID_RANGE 100000
#define UID_RANGES_START 100000

#define MAX_UID_RANGES ((int)((UINT_MAX - UID_RANGES_START) / UID_RANGE))

/* Paths for controling mappings */
#define C_USER_UID_MAP_PATH "/proc/%d/uid_map"
#define C_USER_GID_MAP_PATH "/proc/%d/gid_map"

#define C_USER_MAP_FORMAT "%d %d %d"

/* User structure with specific usernamespace mappings */
typedef struct c_user {
	container_t *container; //!< container which the c_user struct is associated to
	int offset;		//!< gives information about the uid mapping to be set
	int uid_start;		//!< this is the start of uids and gids in the root namespace
	list_t *marks;		//marks to be mounted in userns
	int mark_index;
	int fd_userns;
} c_user_t;

/**
 * bool array, which globally holds assigend ranges in order to
 * determine a new offset for a starting container.
 * uid_offsets[i]==true means that a container holds this offset to get its
 * specific uid range
 */
static bool *uid_offsets = NULL;

/**
 * sets the offset at the specified position to false.
 * indicates that a container releases its addresses.
 */
static void
c_user_unset_offset(int offset)
{
	ASSERT(offset < MAX_UID_RANGES);
	TRACE("UID offset %d released by a container", offset);
	IF_TRUE_RETURN(offset == -1);

	uid_offsets[offset] = false;
}

/**
 * determines first free slot and occupies it. Also responsible for allocating the offsets array.
 * @return failure, return -1, else return first free offset
 */
static int
c_user_set_next_offset(void)
{
	if (!uid_offsets) {
		uid_offsets = mem_new0(bool, MAX_UID_RANGES);
		uid_offsets[0] = true;
		TRACE("UID offset 0 ocupied by a container");
		return 0;
	}

	for (int i = 0; i < MAX_UID_RANGES; i++) {
		if (!uid_offsets[i]) {
			TRACE("UID offset %d occupied by a container", i);
			uid_offsets[i] = true;
			return i;
		}
	}

	DEBUG("Unable to provide a valid uid/gid range for c_user");
	return -1;
}

/**
 * determines first free slot and occupies it. Also responsible for allocating the offsets array.
 * @return failure, return -1, else return the requested offest if its free
 */
static int
c_user_set_offset(int offset)
{
	if (!uid_offsets)
		uid_offsets = mem_new0(bool, MAX_UID_RANGES);

	if (uid_offsets[offset]) {
		ERROR("UID offset %d allready taken by a container", offset);
		return -1;
	}

	TRACE("UID offset %d now occupied by a container", offset);
	uid_offsets[offset] = true;
	return offset;
}

static char *
c_user_uid_file_new(c_user_t *user)
{
	ASSERT(user);
	return mem_printf("%s.uid", container_get_images_dir(user->container));
}

/**
 * This function determines and sets the next available uid range, depending on the container offset.
 */
static int
c_user_set_next_uid_range_start(c_user_t *user)
{
	ASSERT(user);

	char *file_name_uid = c_user_uid_file_new(user);
	int offset = -1;
	if (file_exists(file_name_uid)) {
		if (file_read(file_name_uid, (char *)&offset, sizeof(offset)) < 0) {
			WARN("Failed to restore uid for container %s",
			     uuid_string(container_get_uuid(user->container)));
		}
	}

	// try to use stored uid
	if (offset > -1)
		offset = c_user_set_offset(offset);

	if (offset == -1) {
		INFO("Restored uid already taken, generating new one");
		offset = c_user_set_next_offset();
		IF_TRUE_RETVAL(offset < 0, -1);
		if (file_write(file_name_uid, (char *)&offset, sizeof(offset)) < 0) {
			WARN("Failed to store uid %d for container %s", offset,
			     uuid_string(container_get_uuid(user->container)));
		}
	}
	user->offset = offset;

	user->uid_start = UID_RANGES_START + (user->offset * UID_RANGE);
	DEBUG("Next free uid/gid map start is: %u", user->uid_start);

	mem_free0(file_name_uid);
	return 0;
}

/**
 * This function allocates a new c_user_t instance, associated to a specific container object.
 * @return the c_user_t user structure which holds user namespace information for a container.
 */
static void *
c_user_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_user_t *user = mem_new0(c_user_t, 1);
	user->container = compartment_get_extension_data(compartment);

	user->uid_start = 0;

	TRACE("new c_user struct was allocated");

	return user;
}

/**
 * Setup mappings for uids and gids
 */
static int
c_user_setup_mapping(pid_t pid, int uid_start, int uid_range)
{
	char *uid_mapping = mem_printf(C_USER_MAP_FORMAT, 0, uid_start, uid_range);
	INFO("mapping: '%s'", uid_mapping);

	char *uid_map_path = mem_printf(C_USER_UID_MAP_PATH, pid);
	char *gid_map_path = mem_printf(C_USER_GID_MAP_PATH, pid);

	// write mapping to proc
	if (file_printf(uid_map_path, "%s", uid_mapping) == -1) {
		ERROR_ERRNO("Failed to write to %s", uid_map_path);
		goto error;
	}
	if (file_printf(gid_map_path, "%s", uid_mapping) == -1) {
		ERROR_ERRNO("Failed to write to %s", gid_map_path);
		goto error;
	}

	mem_free0(uid_mapping);
	mem_free0(uid_map_path);
	mem_free0(gid_map_path);
	return 0;
error:
	mem_free0(uid_mapping);
	mem_free0(uid_map_path);
	mem_free0(gid_map_path);
	return -1;
}

/**
 * Cleans up the c_user_t struct.
 */
static void
c_user_cleanup(void *usr, bool is_rebooting)
{
	c_user_t *user = usr;
	ASSERT(user);

	/* We can skip this in case the container has no user ns */
	if (!container_has_userns(user->container))
		return;

	/* skip on reboots of c0 */
	if (is_rebooting && (cmld_containers_get_c0() == user->container))
		return;

	c_user_unset_offset(user->offset);
}

/**
 * Frees the c_user_t structure
 */
static void
c_user_free(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);
	mem_free0(user);
}

static void
c_user_destroy(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);

	char *file_name_uid = c_user_uid_file_new(user);
	if (file_exists(file_name_uid))
		if (0 != unlink(file_name_uid)) {
			ERROR_ERRNO("Can't delete %s file!", file_name_uid);
		}
	mem_free0(file_name_uid);
}

static int
c_user_get_uid(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);
	return user->uid_start;
}

/**
 * Become root in new userns
 */
static int
c_user_setuid0(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);

	/* Skip this, if the container doesn't have a user namespace */
	if (!container_has_userns(user->container))
		return 0;

	return namespace_setuid0();
}

static int
c_user_start_child(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);
	if (c_user_setuid0(user) < 0)
		return -COMPARTMENT_ERROR_USER;
	return 0;
}

/**
 * Reserves a mapping for uids and gids of the user namespace in rootns
 */
static int
c_user_start_pre_clone(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);

	/* Skip this, if the container doesn't have a user namespace */
	if (!container_has_userns(user->container))
		return 0;

	/* skip on reboots of c0 */
	if ((cmld_containers_get_c0() == user->container) &&
	    (container_get_prev_state(user->container) == COMPARTMENT_STATE_REBOOTING))
		return 0;

	// reserve a new mapping
	if (c_user_set_next_uid_range_start(user)) {
		ERROR("Reserving uid range for userns");
		return -COMPARTMENT_ERROR_USER;
	}
	return 0;
}

/**
 * Setup mapping for uids and gids of the user namespace in rootns
 */
static int
c_user_start_post_clone(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);

	/* Skip this, if the container doesn't have a user namespace */
	if (!container_has_userns(user->container))
		return 0;

	/* skip on reboots of c0 */
	if ((cmld_containers_get_c0() == user->container) &&
	    (container_get_prev_state(user->container) == COMPARTMENT_STATE_REBOOTING))
		return 0;

	pid_t container_pid = container_get_pid(user->container);

	if (c_user_setup_mapping(container_pid, user->uid_start, UID_MAX) < 0)
		return -COMPARTMENT_ERROR_USER;

	INFO("uid/gid mapping '%d %d' for %s activated", user->uid_start, UID_MAX,
	     container_get_name(user->container));

	// open userns to keep ns alive during reboot
	char *ns_path = mem_printf("/proc/%d/ns/user", container_pid);
	user->fd_userns = open(ns_path, O_RDONLY);
	if (user->fd_userns < 0)
		WARN("Could not keep userns active for reboot!");

	mem_free(ns_path);
	return 0;
}

static int
c_user_stop(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);

	// release reference to userns
	if (user->fd_userns > 0) {
		close(user->fd_userns);
		user->fd_userns = -1;
	}
	return 0;
}

static int
c_user_join_userns(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);

	IF_TRUE_RETVAL_ERROR(user->fd_userns < 0, -COMPARTMENT_ERROR_USER);

	if (setns(user->fd_userns, 0) == -1) {
		ERROR_ERRNO("Could not join namespace by fd %d!", user->fd_userns);
		close(user->fd_userns);
		return -COMPARTMENT_ERROR_USER;
	}

	return 0;
}

#define CLONE_STACK_SIZE 8192

static int
c_user_dummy_userns_child(UNUSED void *data)
{
	return kill(getpid(), SIGSTOP);
}

static int
c_user_open_userns(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);

	int userns_fd = -1;
	char *userns_path = NULL;
	pid_t userns_child = -1;
	int status = -1;

	void *stack = alloca(CLONE_STACK_SIZE);
	IF_NULL_GOTO(stack, error);

	void *stack_high = (void *)((const char *)stack + CLONE_STACK_SIZE);

	userns_child = clone(c_user_dummy_userns_child, stack_high, CLONE_NEWUSER | SIGCHLD, NULL);
	IF_TRUE_GOTO(userns_child < 0, error);

	if (c_user_setup_mapping(userns_child, user->uid_start, UID_MAX) < 0) {
		ERROR("Could not set mapping for dummy userns");
		goto error;
	}

	userns_path = mem_printf("/proc/%d/ns/user", userns_child);
	if ((userns_fd = open(userns_path, O_RDONLY | O_CLOEXEC)) == -1) {
		ERROR_ERRNO("Could not open userns_fd '%s' for container start",
			    userns_path ? userns_path : "null");
		goto error;
	}

	kill(userns_child, SIGKILL);
	while (waitpid(userns_child, &status, WNOHANG) != userns_child) {
		continue;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		WARN("userns dummy child terminated abnormally/with error");
	}

	mem_free0(userns_path);
	return userns_fd;
error:
	if (userns_path)
		mem_free0(userns_path);
	return -1;
}

static compartment_module_t c_user_module = {
	.name = MOD_NAME,
	.compartment_new = c_user_new,
	.compartment_free = c_user_free,
	.compartment_destroy = c_user_destroy,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = c_user_start_pre_clone,
	.start_post_clone = c_user_start_post_clone,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = c_user_start_child,
	.start_pre_exec_child = NULL,
	.stop = c_user_stop,
	.cleanup = c_user_cleanup,
	.join_ns = c_user_join_userns,
};

static void INIT
c_user_init(void)
{
	// register this module in container.c
	container_register_compartment_module(&c_user_module);

	// register relevant handlers implemented by this module
	container_register_setuid0_handler(MOD_NAME, c_user_setuid0);
	container_register_get_uid_handler(MOD_NAME, c_user_get_uid);
	container_register_open_userns_handler(MOD_NAME, c_user_open_userns);
}
