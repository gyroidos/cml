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

#define MOD_NAME "c_user"

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
typedef struct c_user {
	container_t *container; //!< container which the c_user struct is associated to
	int offset;		//!< gives information about the uid mapping to be set
	int uid_start;		//!< this is the start of uids and gids in the root namespace
	list_t *marks;		//marks to be mounted in userns
	int mark_index;
	int fd_userns;
	char *ns_path;
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

/**
 * This function determines and sets the next available uid range, depending on the container offset.
 */
static int
c_user_set_next_uid_range_start(c_user_t *user)
{
	ASSERT(user);

	char *file_name_uid = mem_printf("%s.uid", container_get_images_dir(user->container));
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

static void
c_user_shift_free(struct c_user_shift *s)
{
	IF_NULL_RETURN_ERROR(s);
	mem_free0(s->target);
	mem_free0(s->mark);
	mem_free0(s);
}

/**
 * This function allocates a new c_user_t instance, associated to a specific container object.
 * @return the c_user_t user structure which holds user namespace information for a container.
 */
static void *
c_user_new(container_t *container)
{
	ASSERT(container);

	c_user_t *user = mem_new0(c_user_t, 1);
	user->container = container;
	user->uid_start = 0;

	// path to bind userns (used for reboots)
	dir_mkdir_p("/var/run/userns", 00755);
	user->ns_path =
		mem_printf("/var/run/userns/%s", uuid_string(container_get_uuid(container)));

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

static int
c_user_cleanup_marks_cb(const char *path, const char *file, UNUSED void *data)
{
	char *mark = mem_printf("%s/%s", path, file);
	if (file_is_mountpoint(mark)) {
		if (umount2(mark, MNT_DETACH) < 0) {
			WARN_ERRNO("Could not umount shift mark on %s", mark);
			mem_free0(mark);
			return -1;
		}
		if (rmdir(mark) < 0)
			TRACE("Unable to remove %s", mark);
		INFO("Cleanup mark '%s' done.", mark);
	}
	mem_free0(mark);
	return 0;
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

	// remove bound to filesystem
	if (user->fd_userns > 0) {
		close(user->fd_userns);
		user->fd_userns = -1;
	}
	ns_unbind(user->ns_path);

	c_user_unset_offset(user->offset);

	// cleanup left-over marks in main cmld process
	const char *uuid = uuid_string(container_get_uuid(user->container));
	char *path = mem_printf("%s/%s/mark", SHIFTFS_DIR, uuid);
	if (dir_foreach(path, &c_user_cleanup_marks_cb, NULL) < 0)
		WARN("Could not release marks in '%s'", path);
	if (rmdir(path) < 0)
		TRACE("Unable to remove %s", path);
	mem_free0(path);
}

/**
 * Frees the c_user_t structure
 */
static void
c_user_free(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);
	mem_free0(user->ns_path);
	mem_free0(user);
}

static int
c_user_get_uid(void *usr)
{
	c_user_t *user = usr;
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
		mem_free0(file_to_chown);
		return -1;
	}

	// modulo operation avoids shifting twice
	uid_t uid = s.st_uid % UID_RANGE + user->uid_start;
	gid_t gid = s.st_gid % UID_RANGE + user->uid_start;

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
	TRACE("Chown file '%s' to (%d:%d) (uid_start %d)", file_to_chown, uid, gid,
	      user->uid_start);

	// chown .
	if (chown(path, uid, gid) < 0) {
		ERROR_ERRNO("Could not chown dir '%s' to (%d:%d)", path, uid, gid);
		ret--;
	}
	mem_free0(file_to_chown);
	return ret;
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
		return -CONTAINER_ERROR_USER;
	return 0;
}

/**
 * Shifts or sets uid/gids of path using the parent ids for this c_user_t
 *
 * Call this inside the parent user_ns.
 */
static int
c_user_shift_ids(void *usr, const char *path, bool is_root)
{
	c_user_t *user = usr;
	ASSERT(user);

	/* We can skip this in case the container has no user ns */
	if (!container_has_userns(user->container))
		return 0;

	TRACE("uid %d, euid %d", getuid(), geteuid());

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

	// if kernel does not support shiftfs just chown the files
	// and do bind mounts (see jump mark shift)
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
		goto shift;
	}

shift:
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
		c_user_shift_free(shift_mark);
		goto error;
	}
	/*
	 * In case shiftfs is not supported we use MS_BIND flag to just bind
	 * mount the chowned directories to the new mount tree.
	 * If MS_BIND flag is used, fs paramter and other options are ignored
	 * by the mount system call.
	 */
	if (mount(path, shift_mark->mark, "shiftfs", cmld_is_shiftfs_supported() ? 0 : MS_BIND,
		  "mark") < 0) {
		ERROR_ERRNO("Could not mark shiftfs origin %s on mark %s", path, shift_mark->mark);
		c_user_shift_free(shift_mark);
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
	    (container_get_prev_state(user->container) == CONTAINER_STATE_REBOOTING))
		return 0;

	// reserve a new mapping
	if (c_user_set_next_uid_range_start(user)) {
		ERROR("Reserving uid range for userns");
		return -CONTAINER_ERROR_USER;
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
	    (container_get_prev_state(user->container) == CONTAINER_STATE_REBOOTING))
		return 0;

	// bind userns to file
	if (ns_bind("user", container_get_pid(user->container), user->ns_path) == -1) {
		WARN("Could not bind userns of %s into filesystem!",
		     container_get_name(user->container));
	}
	user->fd_userns = open(user->ns_path, O_RDONLY);
	if (user->fd_userns < 0)
		WARN("Could not keep userns active for reboot!");

	if (c_user_setup_mapping(user) < 0)
		return -CONTAINER_ERROR_USER;

	return 0;
}

static int
c_user_shift_mounts(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);

	/* Skip this, if the container doesn't have a user namespace */
	if (!container_has_userns(user->container))
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
		if (mount(shift_mark->mark, shift_mark->target, "shiftfs",
			  cmld_is_shiftfs_supported() ? 0 : MS_BIND, NULL) < 0) {
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
		mem_free0(target_dev);
	if (saved_dev)
		mem_free0(saved_dev);
	return 0;
error:
	if (target_dev)
		mem_free0(target_dev);
	if (saved_dev)
		mem_free0(saved_dev);
	return -1;
}

static int
c_user_join_userns(void *usr)
{
	c_user_t *user = usr;
	ASSERT(user);
	IF_FALSE_RETVAL(file_exists(user->ns_path), -1);

	if (ns_join_by_path(user->ns_path) < 0)
		return -CONTAINER_ERROR_USER;

	return 0;
}

static container_module_t c_user_module = {
	.name = MOD_NAME,
	.container_new = c_user_new,
	.container_free = c_user_free,
	.container_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = c_user_start_pre_clone,
	.start_post_clone = c_user_start_post_clone,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = c_user_start_child,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_user_cleanup,
	.join_ns = c_user_join_userns,
};

static void INIT
c_user_init(void)
{
	// register this module in container.c
	container_register_module(&c_user_module);

	// register relevant handlers implemented by this module
	container_register_setuid0_handler(MOD_NAME, c_user_setuid0);
	container_register_get_uid_handler(MOD_NAME, c_user_get_uid);
	container_register_shift_ids_handler(MOD_NAME, c_user_shift_ids);
	container_register_shift_mounts_handler(MOD_NAME, c_user_shift_mounts);
}
