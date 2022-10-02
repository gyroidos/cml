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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#define MOD_NAME "c_shiftid"

#include <sys/mount.h>
#include <unistd.h>

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/dir.h"
#include "cmld.h"
#include "container.h"

#define SHIFTFS_DIR "/tmp/shiftfs"
#define UID_RANGE 100000

struct c_shiftid_mnt {
	char *target;
	char *mark;
	bool is_root;
};

/* shiftid structure with specific directory mappings */
typedef struct c_shiftid {
	container_t *container; //!< container which the c_user struct is associated to
	list_t *marks;		//marks (c_shiftid_mnt) to be mounted in userns
	int mark_index;
} c_shiftid_t;

static void
c_shiftid_mnt_free(struct c_shiftid_mnt *mnt)
{
	IF_NULL_RETURN_ERROR(mnt);
	mem_free0(mnt->target);
	mem_free0(mnt->mark);
	mem_free0(mnt);
}

/**
 * This function allocates a new c_shiftid_t instance, associated to a specific container object.
 * @return the c_shiftid_t structure which holds shifted mounts for a container.
 */
static void *
c_shiftid_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_shiftid_t *shiftid = mem_new0(c_shiftid_t, 1);
	shiftid->container = compartment_get_extension_data(compartment);

	TRACE("new c_shiftid struct was allocated");

	return shiftid;
}

static int
c_shiftid_cleanup_marks_cb(const char *path, const char *file, UNUSED void *data)
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
 * Cleans up the c_shiftid_t struct.
 */
static void
c_shiftid_cleanup(void *shiftidp, bool is_rebooting)
{
	c_shiftid_t *shiftid = shiftidp;
	ASSERT(shiftid);

	/* We can skip this in case the container has no user ns */
	if (!container_has_userns(shiftid->container))
		return;

	/* skip on reboots of c0 */
	if (is_rebooting && (cmld_containers_get_c0() == shiftid->container))
		return;

	// cleanup left-over marks in main cmld process
	const char *uuid = uuid_string(container_get_uuid(shiftid->container));
	char *path = mem_printf("%s/%s/mark", SHIFTFS_DIR, uuid);
	if (dir_foreach(path, &c_shiftid_cleanup_marks_cb, NULL) < 0)
		WARN("Could not release marks in '%s'", path);
	if (rmdir(path) < 0)
		TRACE("Unable to remove %s", path);
	mem_free0(path);
}

/**
 * Frees the c_shiftid_t structure
 */
static void
c_shiftid_free(void *shiftidp)
{
	c_shiftid_t *shiftid = shiftidp;
	ASSERT(shiftid);
	mem_free0(shiftid);
}

static int
c_shiftid_chown_dir_cb(const char *path, const char *file, void *data)
{
	struct stat s;
	int ret = 0;
	c_shiftid_t *shiftid = data;
	ASSERT(shiftid);

	char *file_to_chown = mem_printf("%s/%s", path, file);
	if (lstat(file_to_chown, &s) == -1) {
		mem_free0(file_to_chown);
		return -1;
	}

	int container_uid = container_get_uid(shiftid->container);

	// modulo operation avoids shifting twice
	uid_t uid = s.st_uid % UID_RANGE + container_uid;
	gid_t gid = s.st_gid % UID_RANGE + container_uid;

	if (file_is_dir(file_to_chown)) {
		TRACE("Path %s is dir", file_to_chown);
		if (dir_foreach(file_to_chown, &c_shiftid_chown_dir_cb, shiftid) < 0) {
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
	TRACE("Chown file '%s' to (%d:%d) (uid_start %d)", file_to_chown, uid, gid, container_uid);

	// chown .
	if (chown(path, uid, gid) < 0) {
		ERROR_ERRNO("Could not chown dir '%s' to (%d:%d)", path, uid, gid);
		ret--;
	}
	mem_free0(file_to_chown);
	return ret;
}

/**
 * Shifts or sets uid/gids of path using the parent ids for this c_shiftid_t
 *
 * Call this inside the parent user_ns.
 */
static int
c_shiftid_shift_ids(void *shiftidp, const char *path, bool is_root)
{
	c_shiftid_t *shiftid = shiftidp;
	ASSERT(shiftid);

	/* We can skip this in case the container has no user ns */
	if (!container_has_userns(shiftid->container))
		return 0;

	TRACE("uid %d, euid %d", getuid(), geteuid());

	int container_uid = container_get_uid(shiftid->container);

	// if we just got a single file chown this and return
	if (file_exists(path) && !file_is_dir(path)) {
		if (lchown(path, container_uid, container_uid) < 0) {
			ERROR_ERRNO("Could not chown file '%s' to (%d:%d)",
				    path, container_uid, container_uid);
			goto error;
		}
		goto success;
	}

	// if cgroup subsys or dev just chown the files
	if ((strlen(path) >= 5 && !strcmp(strrchr(path, '\0') - 4, "/dev")) ||
	    (strstr(path, "/cgroup") != NULL)) {
		if (dir_foreach(path, &c_shiftid_chown_dir_cb, shiftid) < 0) {
			ERROR("Could not chown %s to target uid:gid (%d:%d)", path, container_uid,
			      container_uid);
			goto error;
		}
		goto success;
	}

	// if kernel does not support shiftfs just chown the files
	// and do bind mounts
	if (!cmld_is_shiftfs_supported()) {
		if (chown(path, container_uid, container_uid) < 0) {
			ERROR_ERRNO("Could not chown mnt point '%s' to (%d:%d)", path,
				    container_uid, container_uid);
			goto error;
		}
		if (dir_foreach(path, &c_shiftid_chown_dir_cb, shiftid) < 0) {
			ERROR("Could not chown %s to target uid:gid (%d:%d)",
			      path, container_uid, container_uid);
			goto error;
		}
	}

	// create mountpoints for lower and upper dev
	if (dir_mkdir_p(SHIFTFS_DIR, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir %s", SHIFTFS_DIR);
		goto error;
	}
	if (chmod(SHIFTFS_DIR, 00777) < 0) {
		ERROR_ERRNO("Could not chmod %s", SHIFTFS_DIR);
		goto error;
	}

	struct c_shiftid_mnt *mnt = mem_new0(struct c_shiftid_mnt, 1);
	mnt->target = mem_strdup(path);
	mnt->mark =
		mem_printf("%s/%s/mark/%d", SHIFTFS_DIR,
			   uuid_string(container_get_uuid(shiftid->container)), shiftid->mark_index++);
	mnt->is_root = is_root;
	if (dir_mkdir_p(mnt->mark, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir shiftfs dir %s", mnt->mark);
		c_shiftid_mnt_free(mnt);
		goto error;
	}
	/*
	 * In case shiftfs is not supported we use MS_BIND flag to just bind
	 * mount the chowned directories to the new mount tree.
	 * If MS_BIND flag is used, fs paramter and other options are ignored
	 * by the mount system call.
	 */
	if (mount(path, mnt->mark, "shiftfs", cmld_is_shiftfs_supported() ? 0 : MS_BIND,
		  "mark") < 0) {
		ERROR_ERRNO("Could not mark shiftfs origin %s on mark %s", path, mnt->mark);
		c_shiftid_mnt_free(mnt);
		goto error;
	}

	shiftid->marks = list_append(shiftid->marks, mnt);

success:

	INFO("Successfully shifted uids for '%s'", path);
	return 0;
error:
	return -1;
}

static int
c_shiftid_shift_mounts(void *shiftidp)
{
	c_shiftid_t *shiftid = shiftidp;
	ASSERT(shiftid);

	/* Skip this, if the container doesn't have a user namespace */
	if (!container_has_userns(shiftid->container))
		return 0;

	TRACE("uid %d, euid %d", getuid(), geteuid());
	for (list_t *l = shiftid->marks; l; l = l->next) {
		struct c_shiftid_mnt *mnt = l->data;

		// mount the shifted user ids to new root
		IF_TRUE_RETVAL(dir_mkdir_p(mnt->target, 0777) < 0, -1);
		if (mount(mnt->mark, mnt->target, "shiftfs",
			  cmld_is_shiftfs_supported() ? 0 : MS_BIND, NULL) < 0) {
			ERROR_ERRNO("Could not remount shiftfs mark %s to %s", mnt->mark,
				    mnt->target);
			return -1;
		} else {
			INFO("Successfully shifted root uid/gid for userns mount %s",
			     mnt->target);
		}
	}

	return 0;
}



static compartment_module_t c_shiftid_module = {
	.name = MOD_NAME,
	.compartment_new = c_shiftid_new,
	.compartment_free = c_shiftid_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_shiftid_cleanup,
	.join_ns = NULL,
};

static void INIT
c_shiftid_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_shiftid_module);

	// register relevant handlers implemented by this module
	container_register_shift_ids_handler(MOD_NAME, c_shiftid_shift_ids);
	container_register_shift_mounts_handler(MOD_NAME, c_shiftid_shift_mounts);
}
