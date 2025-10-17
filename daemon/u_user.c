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

#define MOD_NAME "c_user"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/ns.h"
#include "unit.h"

#define UID_RANGE 2
#define UID_RANGES_START 65537

#define MAX_UID_RANGES ((int)((100000 - UID_RANGES_START) / UID_RANGE))

/* Paths for controling mappings */
#define U_USER_UID_MAP_PATH "/proc/%d/uid_map"
#define U_USER_GID_MAP_PATH "/proc/%d/gid_map"

#define U_USER_MAP_FORMAT "%d %d %d\n%d %d %d"

/* User structure with specific usernamespace mappings */
typedef struct u_user {
	unit_t *unit;  //!< unit which the u_user struct is associated to
	int offset;    //!< gives information about the uid mapping to be set
	int uid_start; //!< this is the start of uids and gids in the root namespace
} u_user_t;

/**
 * bool array, which globally holds assigend ranges in order to
 * determine a new offset for a starting container.
 * uid_offsets[i]==true means that a container holds this offset to get its
 * specific uid range
 */
static bool *uid_offsets = NULL;

/**
 * sets the offset at the specified position to false.
 * indicates that a unit releases its mappings.
 */
static void
u_user_unset_offset(int offset)
{
	ASSERT(offset < MAX_UID_RANGES);
	TRACE("UID offset %d released by an unit", offset);
	IF_TRUE_RETURN(offset == -1);

	uid_offsets[offset] = false;
}

/**
 * determines first free slot and occupies it. Also responsible for allocating the offsets array.
 * @return failure, return -1, else return first free offset
 */
static int
u_user_set_next_offset(void)
{
	if (!uid_offsets) {
		uid_offsets = mem_new0(bool, MAX_UID_RANGES);
		uid_offsets[0] = true;
		TRACE("UID offset 0 ocupied by an unit");
		return 0;
	}

	for (int i = 0; i < MAX_UID_RANGES; i++) {
		if (!uid_offsets[i]) {
			TRACE("UID offset %d occupied by an unit", i);
			uid_offsets[i] = true;
			return i;
		}
	}

	DEBUG("Unable to provide a valid uid/gid range for u_user");
	return -1;
}

/**
 * This function determines and sets the next available uid range, depending on the unit offset.
 */
static int
u_user_set_next_uid_range_start(u_user_t *user)
{
	ASSERT(user);

	int offset = -1;

	offset = u_user_set_next_offset();
	IF_TRUE_RETVAL(offset < 0, -1);
	user->offset = offset;

	user->uid_start = UID_RANGES_START + (user->offset * UID_RANGE);
	DEBUG("Next free uid/gid map start is: %u", user->uid_start);

	return 0;
}

/**
 * This function allocates a new u_user_t instance, associated to a specific unit object.
 * @return the u_user_t user structure which holds user namespace information for a unit.
 */
static void *
u_user_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	u_user_t *user = mem_new0(u_user_t, 1);
	user->unit = compartment_get_extension_data(compartment);

	user->uid_start = 0;

	TRACE("new u_user struct was allocated");

	return user;
}

/**
 * Setup mappings for uids and gids
 */
static int
u_user_setup_mapping(pid_t pid, int uid_start)
{
	char *uid_mapping = mem_printf(U_USER_MAP_FORMAT, 0, uid_start, 1, 100, uid_start + 1, 1);
	INFO("mapping: \n'%s'", uid_mapping);

	char *uid_map_path = mem_printf(U_USER_UID_MAP_PATH, pid);
	char *gid_map_path = mem_printf(U_USER_GID_MAP_PATH, pid);

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
 * Cleans up the u_user_t struct.
 */
static void
u_user_cleanup(void *usr, UNUSED bool is_rebooting)
{
	u_user_t *user = usr;
	ASSERT(user);

	u_user_unset_offset(user->offset);
}

/**
 * Frees the u_user_t structure
 */
static void
u_user_free(void *usr)
{
	u_user_t *user = usr;
	ASSERT(user);

	mem_free0(user);
}

/**
 * Become root in new userns
 */
static int
u_user_setuid0(void)
{
	return namespace_setuid0();
}

static int
u_user_start_child(void *usr)
{
	u_user_t *user = usr;
	ASSERT(user);

	if (u_user_setuid0() < 0) {
		return -COMPARTMENT_ERROR_USER;
	}
	return 0;
}

/**
 * Reserves a mapping for uids and gids of the user namespace in rootns
 */
static int
u_user_start_pre_clone(void *usr)
{
	u_user_t *user = usr;
	ASSERT(user);

	// reserve a new mapping
	if (u_user_set_next_uid_range_start(user)) {
		ERROR("Reserving uid range for userns for unit %s", unit_get_name(user->unit));
		return -COMPARTMENT_ERROR_USER;
	}
	return 0;
}

/**
 * Setup mapping for uids and gids of the user namespace in rootns
 */
static int
u_user_start_post_clone(void *usr)
{
	u_user_t *user = usr;
	ASSERT(user);

	pid_t unit_pid = unit_get_pid(user->unit);

	if (u_user_setup_mapping(unit_pid, user->uid_start) < 0)
		return -COMPARTMENT_ERROR_USER;

	INFO("uid/gid mapping '%d %d' for %s activated", user->uid_start, UID_RANGE,
	     unit_get_name(user->unit));

	return 0;
}

static compartment_module_t u_user_module = {
	.name = MOD_NAME,
	.compartment_new = u_user_new,
	.compartment_free = u_user_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = u_user_start_pre_clone,
	.start_post_clone = u_user_start_post_clone,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = u_user_start_child,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = u_user_cleanup,
	.join_ns = NULL,
};

static void INIT
u_user_init(void)
{
	// register this module in unit.c
	unit_register_compartment_module(&u_user_module);
}
