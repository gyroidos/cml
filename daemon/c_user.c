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
#include "c_user.h"

#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <sys/mount.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
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
#define UID_MAX 65535
#define MAX_UID_RANGES ((int)((UINT_MAX - UID_RANGES_START) / UID_RANGE))

/* Paths for controling mappings */
#define C_USER_UID_MAP_PATH "/proc/%d/uid_map"
#define C_USER_GID_MAP_PATH "/proc/%d/gid_map"

#define C_USER_MAP_FORMAT "%d %d %d"

#define SHIFTFS_DIR "/tmp/shiftfs"

struct c_user_shift {
	char *target;
	char *mark;
	bool is_root;
};

/* User structure with specific usernamespace mappings */
struct c_user {
	container_t *container; //!< container which the c_user struct is associated to
	bool ns_usr;		//!< indicates if the c_user structure has an user namespace
	int offset;		//!< gives information about the uid mapping to be set
	int uid_start;		//!< this is the start of uids and gids in the root namespace
	list_t *marks;		//marks to be mounted in userns
	int mark_index;
};

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

/**
 * This function determines and sets the next available uid range, depending on the container offset.
 */
static int
c_user_set_next_uid_range_start(c_user_t *user)
{
	ASSERT(user);

	char *file_name_uid = mem_printf("%s.uid", container_get_images_dir(user->container));
	if (!file_exists(file_name_uid)) {
		user->offset = c_user_set_next_offset();
		IF_TRUE_RETVAL((user->offset < 0), -1);
		if (file_write(file_name_uid, (char *)&user->offset, sizeof(user->offset)) < 0) {
			WARN("Failed to store uid %d for container %s", user->offset,
			     uuid_string(container_get_uuid(user->container)));
		}
	} else {
		int offset;
		if (file_read(file_name_uid, (char *)&offset, sizeof(offset)) < 0) {
			WARN("Failed to restore uid for container %s",
			     uuid_string(container_get_uuid(user->container)));
		}
		user->offset = c_user_set_offset(offset);
		IF_TRUE_RETVAL((user->offset != offset), -1);
	}

	user->uid_start = UID_RANGES_START + (user->offset * UID_RANGE);
	DEBUG("Next free uid/gid map start is: %u", user->uid_start);

	return 0;
}

/**
 * This function allocates a new c_user_t instance, associated to a specific container object.
 * @return the c_user_t user structure which holds user namespace information for a container.
 */
c_user_t *
c_user_new(container_t *container, bool user_ns)
{
	ASSERT(container);

	c_user_t *user = mem_new0(c_user_t, 1);
	user->container = container;
	user->ns_usr = user_ns;
	user->uid_start = 0;

	TRACE("new c_user struct was allocated");

	return user;
}

/**
 * Setup mappings for uids and gids
 */
static int
c_user_setup_mapping(const c_user_t *user)
{
	ASSERT(user);

	char *uid_mapping = mem_printf(C_USER_MAP_FORMAT, 0, user->uid_start, UID_MAX);
	INFO("mapping: '%s'", uid_mapping);

	char *uid_map_path = mem_printf(C_USER_UID_MAP_PATH, container_get_pid(user->container));
	char *gid_map_path = mem_printf(C_USER_GID_MAP_PATH, container_get_pid(user->container));

	// write mapping to proc
	if (file_printf(uid_map_path, "%s", uid_mapping) == -1) {
		ERROR_ERRNO("Failed to write to %s", uid_map_path);
		goto error;
	}
	if (file_printf(gid_map_path, "%s", uid_mapping) == -1) {
		ERROR_ERRNO("Failed to write to %s", gid_map_path);
		goto error;
	}

	INFO("uid/gid mapping '%s' for %s activated", uid_mapping,
	     container_get_name(user->container));

	mem_free(uid_mapping);
	mem_free(uid_map_path);
	mem_free(gid_map_path);
	return 0;
error:
	mem_free(uid_mapping);
	mem_free(uid_map_path);
	mem_free(gid_map_path);
	return -1;
}

/**
 * Cleans up the c_user_t struct.
 */
void
c_user_cleanup(c_user_t *user)
{
	ASSERT(user);

	/* We can skip this in case the container has no user ns */
	if (!user->ns_usr)
		return;

	c_user_unset_offset(user->offset);

	// cleanup shifted mounts in reverse order
	for (list_t *l = list_tail(user->marks); l; l = l->prev) {
		struct c_user_shift *shift = l->data;
		if (shift->is_root) {
			char *dev_dir = mem_printf("%s/dev", shift->target);
			if (umount(dev_dir) < 0)
				WARN_ERRNO("Could not umount dev on %s", dev_dir);
			mem_free(dev_dir);
		}
		if (umount(shift->target) < 0) {
			if (umount2(shift->target, MNT_DETACH) < 0) {
				WARN_ERRNO("Could not umount shift target on '%s'", shift->target);
			}
		}
		if (umount(shift->mark) < 0)
			WARN_ERRNO("Could not umount shift mark on %s", shift->mark);
		mem_free(shift->mark);
		mem_free(shift->target);
		mem_free(shift);
	}
	list_delete(user->marks);
	user->marks = NULL;
}

/**
 * Frees the c_user_t structure
 */
void
c_user_free(c_user_t *user)
{
	ASSERT(user);
	mem_free(user);
}

int
c_user_get_uid(const c_user_t *user)
{
	ASSERT(user);
	return user->uid_start;
}

static int
c_user_chown_dev_cb(const char *path, const char *file, void *data)
{
	struct stat s;
	int ret = 0;
	c_user_t *user = data;
	ASSERT(user);

	char *file_to_chown = mem_printf("%s/%s", path, file);
	if (lstat(file_to_chown, &s) == -1) {
		mem_free(file_to_chown);
		return -1;
	}

	uid_t uid = s.st_uid + user->uid_start;
	gid_t gid = s.st_gid + user->uid_start;

	// avoid shifting twice
	uid_t uid_overflow = user->uid_start + UID_MAX;
	if (uid > uid_overflow) {
		mem_free(file_to_chown);
		return 0;
	}

	if (file_is_dir(file_to_chown)) {
		TRACE("Path %s is dir", file_to_chown);
		if (dir_foreach(file_to_chown, &c_user_chown_dev_cb, user) < 0) {
			ERROR_ERRNO("Could not chown all dir contents in '%s'", file_to_chown);
			ret--;
		}
		if (chown(file_to_chown, uid, gid) < 0) {
			ERROR_ERRNO("Could not chown dir '%s' to (%d:%d)", file_to_chown, uid, gid);
			ret--;
		}
	} else {
		if (lchown(file_to_chown, uid, gid) < 0) {
			ERROR_ERRNO("Could not chown file '%s' to (%d:%d)", file_to_chown, uid,
				    gid);
			ret--;
		}
	}
	// chown .
	if (chown(path, uid, gid) < 0) {
		ERROR_ERRNO("Could not chown dir '%s' to (%d:%d)", path, uid, gid);
		ret--;
	}
	mem_free(file_to_chown);
	return ret;
}

/**
 * Become root in new userns
 */
int
c_user_setuid0(const c_user_t *user)
{
	ASSERT(user);

	/* Skip this, if the container doesn't have a user namespace */
	if (!user->ns_usr)
		return 0;

	return namespace_setuid0();
}

int
c_user_start_child(const c_user_t *user)
{
	ASSERT(user);
	return c_user_setuid0(user);
}

/**
 * Shifts or sets uid/gids of path using the parent ids for this c_user_t
 *
 * Call this inside the parent user_ns.
 */
int
c_user_shift_ids(c_user_t *user, const char *path, bool is_root)
{
	ASSERT(user);

	/* We can skip this in case the container has no user ns */
	if (!user->ns_usr)
		return 0;

	TRACE("uid %d, euid %d", getuid(), geteuid());

	// if kernel does not support shiftfs just chown the files
	if (!cmld_is_shiftfs_supported()) {
		if (chown(path, user->uid_start, user->uid_start) < 0) {
			ERROR_ERRNO("Could not chown mnt point '%s' to (%d:%d)", path,
				    user->uid_start, user->uid_start);
			goto error;
		}
		if (dir_foreach(path, &c_user_chown_dev_cb, user) < 0) {
			ERROR("Could not chown %s to target uid:gid (%d:%d)", path, user->uid_start,
			      user->uid_start);
			goto error;
		}
		goto success;
	}

	// if we just got a single file chown this and return
	if (file_exists(path) && !file_is_dir(path)) {
		if (lchown(path, user->uid_start, user->uid_start) < 0) {
			ERROR_ERRNO("Could not chown file '%s' to (%d:%d)", path, user->uid_start,
				    user->uid_start);
			goto error;
		}
		goto success;
	}

	// if dev or a cgroup subsys just chown the files
	if ((strlen(path) >= 4 && !strcmp(strrchr(path, '\0') - 4, "/dev")) ||
	    (strstr(path, "/cgroup") != NULL)) {
		if (dir_foreach(path, &c_user_chown_dev_cb, user) < 0) {
			ERROR("Could not chown %s to target uid:gid (%d:%d)", path, user->uid_start,
			      user->uid_start);
			goto error;
		}
		goto success;
	}

	// create mountpoints for lower and upper dev
	if (dir_mkdir_p(SHIFTFS_DIR, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir %s", SHIFTFS_DIR);
		return -1;
	}
	if (chmod(SHIFTFS_DIR, 00777) < 0) {
		ERROR_ERRNO("Could not chmod %s", SHIFTFS_DIR);
		goto error;
	}

	struct c_user_shift *shift_mark = mem_new0(struct c_user_shift, 1);
	shift_mark->target = mem_strdup(path);
	shift_mark->mark =
		mem_printf("%s/%s/mark/%d", SHIFTFS_DIR,
			   uuid_string(container_get_uuid(user->container)), user->mark_index++);
	shift_mark->is_root = is_root;
	if (dir_mkdir_p(shift_mark->mark, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir shiftfs dir %s", shift_mark->mark);
		goto error;
	}
	if (mount(path, shift_mark->mark, "shiftfs", 0, "mark") < 0) {
		ERROR_ERRNO("Could not mark shiftfs origin %s on mark %s", path, shift_mark->mark);
		goto error;
	}

	user->marks = list_append(user->marks, shift_mark);

success:

	INFO("Successfully shifted uids for '%s'", path);
	return 0;
error:
	return -1;
}

/**
 * Reserves a mapping for uids and gids of the user namespace in rootns
 */
int
c_user_start_pre_clone(c_user_t *user)
{
	ASSERT(user);

	/* Skip this, if the container doesn't have a user namespace */
	if (!user->ns_usr)
		return 0;

	// reserve a new mapping
	if (c_user_set_next_uid_range_start(user)) {
		ERROR("Reserving uid range for userns");
		return -1;
	}
	return 0;
}

int
c_user_start_post_clone(const c_user_t *user)
{
	ASSERT(user);

	/* Skip this, if the container doesn't have a user namespace */
	if (!user->ns_usr)
		return 0;

	return c_user_setup_mapping(user);
}

int
c_user_shift_mounts(const c_user_t *user)
{
	ASSERT(user);

	/* Skip this, if the container doesn't have a user namespace */
	if (!user->ns_usr)
		return 0;

	if (!cmld_is_shiftfs_supported())
		return 0;

	char *target_dev, *saved_dev;
	target_dev = saved_dev = NULL;

	TRACE("uid %d, euid %d", getuid(), geteuid());
	for (list_t *l = user->marks; l; l = l->next) {
		struct c_user_shift *shift_mark = l->data;

		// save already mounted dev to remount after new rootfs mount
		if (shift_mark->is_root) {
			target_dev = mem_printf("%s/dev", shift_mark->target);
			saved_dev = mem_printf("%s/%s/dev", SHIFTFS_DIR,
					       uuid_string(container_get_uuid(user->container)));
			if (dir_mkdir_p(saved_dev, 0777) < 0) {
				ERROR_ERRNO("Could not mkdir temporary dev dir '%s'", saved_dev);
				goto error;
			}
			if (mount(target_dev, saved_dev, NULL, MS_BIND, NULL) < 0) {
				ERROR_ERRNO("Could not move dev '%s' to saved_dev '%s'", target_dev,
					    saved_dev);
			}
		}

		// mount the shifted user ids to new root
		if (mount(shift_mark->mark, shift_mark->target, "shiftfs", 0, NULL) < 0) {
			ERROR_ERRNO("Could not remount shiftfs mark %s to %s", shift_mark->mark,
				    shift_mark->target);
			goto error;
		} else {
			INFO("Successfully shifted root uid/gid for userns mount %s",
			     shift_mark->target);
		}

		// remount saved dev location at new shifted rootfs
		if (shift_mark->is_root) {
			if (mount(saved_dev, target_dev, NULL, MS_BIND, NULL) < 0) {
				ERROR_ERRNO("Could mount dev '%s' in new root", target_dev);
			}
			INFO("Successfully moved dev to shifted rootfs at '%s'", target_dev);
		}
	}

	if (target_dev)
		mem_free(target_dev);
	if (saved_dev)
		mem_free(saved_dev);
	return 0;
error:
	if (target_dev)
		mem_free(target_dev);
	if (saved_dev)
		mem_free(saved_dev);
	return -1;
}
