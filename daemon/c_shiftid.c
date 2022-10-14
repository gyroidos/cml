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

#define _GNU_SOURCE

#define MOD_NAME "c_shiftid"

#include <linux/magic.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
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
	char *ovl_lower;
};

/* shiftid structure with specific directory mappings */
typedef struct c_shiftid {
	container_t *container; //!< container which the c_user struct is associated to
	list_t *marks;		//marks (c_shiftid_mnt) to be mounted in userns
	int mark_index;
	bool is_dev_mounted; // checks if the bind mount for dev is already performed
} c_shiftid_t;

static void
c_shiftid_mnt_free(struct c_shiftid_mnt *mnt)
{
	IF_NULL_RETURN_ERROR(mnt);
	mem_free0(mnt->target);
	mem_free0(mnt->mark);
	if (mnt->ovl_lower)
		mem_free0(mnt->ovl_lower);
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
	shiftid->is_dev_mounted = false;

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

static int
c_shiftid_mount_ovl(const char *overlayfs_mount_dir, const char *target_dir, const char *ovl_lower,
		    bool in_child)
{
	char *lower_dir = mem_printf("%s/lower", overlayfs_mount_dir);
	char *upper_dir = mem_printf("%s/upper", overlayfs_mount_dir);
	char *work_dir = mem_printf("%s/work", overlayfs_mount_dir);

	DEBUG("Mounting overlayfs: work_dir=%s, upper_dir=%s, lower_dir=%s, target dir=%s",
	      work_dir, upper_dir, ovl_lower, target_dir);

	struct statfs ovl_statfs;
	statfs(overlayfs_mount_dir, &ovl_statfs);

	// overmount tmpfs within user namespace
	if (in_child && (TMPFS_MAGIC == ovl_statfs.f_type)) {
		INFO("overmounting existing tmpfs with tmpfs in userns on '%s'.",
		     overlayfs_mount_dir);
		if (mount(NULL, overlayfs_mount_dir, "tmpfs", 0, NULL) < 0) {
			ERROR_ERRNO("Could not mount tmpfs to %s", overlayfs_mount_dir);
			goto error;
		}
	}

	// needed for tmpfs in user namespace (child) as well as tmpfs of
	// fallback mechanism where lower image is read only and a temporary
	// upper tmpfs for chowning is used
	if (dir_mkdir_p(upper_dir, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir upper dir %s", upper_dir);
		goto error;
	}
	if (dir_mkdir_p(work_dir, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir work dir %s", work_dir);
		goto error;
	}

	// try to hide absolute paths (if just overmounting existing lower dir)
	if (file_is_link(lower_dir))
		unlink(lower_dir);
	if (symlink(ovl_lower, lower_dir) < 0) {
		ERROR_ERRNO("link lowerdir failed");
		mem_free0(lower_dir);
		lower_dir = mem_strdup(ovl_lower);
	}
	if (file_is_link(lower_dir))
		INFO("Sucessfully created link to %s on %s", ovl_lower, lower_dir);
	else
		ERROR("Failed to created link to %s on %s", ovl_lower, lower_dir);

	DEBUG("Mounting overlayfs: work_dir=%s, upper_dir=%s, lower_dir=%s, target dir=%s",
	      work_dir, upper_dir, lower_dir, target_dir);
	// create mount option string (try to mask absolute paths)
	char *cwd = get_current_dir_name();
	char *overlayfs_options;
	if (chdir(overlayfs_mount_dir)) {
		overlayfs_options = mem_printf("lowerdir=%s,upperdir=%s,workdir=%s,metacopy=on",
					       lower_dir, upper_dir, work_dir);
		INFO("chdir failed: old_wdir: %s, mount_cwd: %s, overlay_options: %s ", cwd,
		     overlayfs_mount_dir, overlayfs_options);
	} else {
		overlayfs_options =
			mem_strdup("lowerdir=lower,upperdir=upper,workdir=work,metacopy=on");
		INFO("old_wdir: %s, mount_cwd: %s, overlay_options: %s ", cwd, overlayfs_mount_dir,
		     overlayfs_options);
	}
	INFO("mount_dir: %s", target_dir);
	// mount overlayfs to dir
	if (mount("overlay", target_dir, "overlay", 0, overlayfs_options) < 0) {
		ERROR_ERRNO("Could not mount overlay");
		mem_free0(overlayfs_options);
		if (chdir(cwd))
			WARN("Could not change back to former cwd %s", cwd);
		mem_free0(cwd);
		goto error;
	}
	mem_free0(overlayfs_options);

	if (chmod(target_dir, 0755) < 0) {
		ERROR_ERRNO("Could not set permissions of overlayfs mount point at %s", target_dir);
		goto error;
	}
	DEBUG("Changed permissions of %s to 0755", target_dir);

	if (chdir(cwd))
		WARN("Could not change back to former cwd %s", cwd);
	mem_free0(cwd);
	mem_free0(lower_dir);
	mem_free0(upper_dir);
	mem_free0(work_dir);
	return 0;
error:
	if (file_is_link(lower_dir)) {
		if (unlink(lower_dir))
			WARN_ERRNO("could not remove temporary link %s", lower_dir);
	}
	mem_free0(lower_dir);
	mem_free0(upper_dir);
	mem_free0(work_dir);
	return -1;
}

static int
c_shiftid_prepare_dir(c_shiftid_t *shiftid, struct c_shiftid_mnt *mnt, const char *dir)
{
	// if kernel does not support shiftfs just chown the files
	// and do bind mounts
	int container_uid = container_get_uid(shiftid->container);
	struct statfs dir_statfs;
	statfs(dir, &dir_statfs);

	if (!cmld_is_shiftfs_supported()) {
		if (dir_statfs.f_flags & MS_RDONLY) {
			char *tmpfs_dir =
				mem_printf("%s/%s/tmp%d", SHIFTFS_DIR,
					   uuid_string(container_get_uuid(shiftid->container)),
					   shiftid->mark_index);
			if (dir_mkdir_p(tmpfs_dir, 0777) < 0) {
				ERROR_ERRNO("Could not mkdir shiftfs dir %s", tmpfs_dir);
				mem_free0(tmpfs_dir);
				return -1;
			}
			if (mount(NULL, tmpfs_dir, "tmpfs", 0, NULL) < 0) {
				ERROR_ERRNO("Could not mount tmpfs to %s", tmpfs_dir);
				mem_free0(tmpfs_dir);
				return -1;
			}
			if (c_shiftid_mount_ovl(tmpfs_dir, dir, dir, false)) {
				ERROR("Failed to mount ovl '%s' (lower='%s') in userns on '%s'",
				      tmpfs_dir, dir, dir);
				mem_free0(tmpfs_dir);
				return -1;
			}
			mem_free0(tmpfs_dir);
		}
		if (chown(dir, container_uid, container_uid) < 0) {
			ERROR_ERRNO("Could not chown mnt point '%s' to (%d:%d)", dir, container_uid,
				    container_uid);
			return -1;
		}
		if (dir_foreach(dir, &c_shiftid_chown_dir_cb, shiftid) < 0) {
			ERROR("Could not chown %s to target uid:gid (%d:%d)", dir, container_uid,
			      container_uid);
			return -1;
		}

		if (dir_statfs.f_flags & MS_RDONLY) {
			if (mount("none", dir, "none", MS_REMOUNT | MS_RDONLY, NULL) < 0) {
				ERROR_ERRNO("Could not remount tmpfs on %s", dir);
				return -1;
			}
		}
	}

	mnt->mark = mem_printf("%s/%s/mark/%d", SHIFTFS_DIR,
			       uuid_string(container_get_uuid(shiftid->container)),
			       shiftid->mark_index++);

	if (dir_mkdir_p(mnt->mark, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir shiftfs dir %s", mnt->mark);
		return -1;
	}

	/*
	 * In case of dev, we cannot use user namespace mounts since the kernel
	 * always implcitly sets the SB_I_NODEV flag for filesystems mounted
	 * in non-inital userns. Thus, we just bind mount it.
	 */
	if (strlen(mnt->target) >= 4 && !strcmp(strrchr(mnt->target, '\0') - 4, "/dev")) {
		if (mount(dir, mnt->mark, NULL, MS_BIND, NULL) < 0) {
			ERROR_ERRNO("Could not bind dev '%s' on mark %s", dir, mnt->mark);
			return -1;
		}
		if (chown(dir, container_uid, container_uid) < 0) {
			ERROR_ERRNO("Could not chown mnt point '%s' to (%d:%d)", dir, container_uid,
				    container_uid);
			return -1;
		}
		shiftid->is_dev_mounted = true;
		return 0;
	}

	/*
	 * In case shiftfs is not supported we use MS_BIND flag to just bind
	 * mount the chowned directories to the new mount tree.
	 * If MS_BIND flag is used, fs paramter and other options are ignored
	 * by the mount system call.
	 */
	if (mount(dir, mnt->mark, "shiftfs", cmld_is_shiftfs_supported() ? 0 : MS_BIND, "mark") <
	    0) {
		ERROR_ERRNO("Could not mark shiftfs origin %s on mark %s", dir, mnt->mark);
		return -1;
	}

	return 0;
}

static bool
kernel_version_check(char *version)
{
	struct utsname buf;
	char ignore[65];
	int main, major, main_to_check, major_to_check;

	uname(&buf);

	ASSERT(sscanf(version, "%d.%d%s", &main_to_check, &major_to_check, ignore) >= 2);
	ASSERT(sscanf(buf.release, "%d.%d.%s", &main, &major, ignore) == 3);

	return (main == main_to_check) ? major >= major_to_check : main >= main_to_check;
}

static int
c_shiftid_mount_shifted(c_shiftid_t *shiftid, const char *src, const char *dst,
			const char *ovl_lower)
{
	struct c_shiftid_mnt *mnt = NULL;
	struct c_shiftid_mnt *mnt_lower = NULL;

	if (ovl_lower) {
		// mount ovl in rootns if kernel is to old
		if (!kernel_version_check("5.12")) {
			if (c_shiftid_mount_ovl(src, src, ovl_lower, false)) {
				ERROR("Failed to mount ovl '%s' (lower='%s') in rootns on '%s'",
				      src, ovl_lower, dst);
				goto error;
			}
			if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
				ERROR_ERRNO("Could not bind ovl in rootns '%s' on %s", src, dst);
				goto error;
			}
			mnt = mem_new0(struct c_shiftid_mnt, 1);
			mnt->target = mem_strdup(dst);
			// set shifted lower as ovl_lower
			mnt->ovl_lower = NULL;
			IF_TRUE_GOTO(c_shiftid_prepare_dir(shiftid, mnt, src) < 0, error);

			shiftid->marks = list_append(shiftid->marks, mnt);
			return 0;
		}
		// mount lower shifted if not over mounting lower dir itself
		if (!strcmp(ovl_lower, dst))
			mnt->ovl_lower = mem_strdup(dst);
		else {
			mnt_lower = mem_new0(struct c_shiftid_mnt, 1);
			mnt_lower->target =
				mem_printf("%s/%s/ovl%d", SHIFTFS_DIR,
					   uuid_string(container_get_uuid(shiftid->container)),
					   shiftid->mark_index);
			if (dir_mkdir_p(mnt_lower->target, 0777) < 0) {
				ERROR_ERRNO("Could not mkdir shifted lower dir %s",
					    mnt_lower->target);
				goto error;
			}
			mnt_lower->ovl_lower = NULL;
			IF_TRUE_GOTO(c_shiftid_prepare_dir(shiftid, mnt_lower, ovl_lower) < 0,
				     error);

			shiftid->marks = list_append(shiftid->marks, mnt_lower);
		}
	}

	mnt = mem_new0(struct c_shiftid_mnt, 1);
	mnt->target = mem_strdup(dst);
	// set shifted lower as ovl_lower
	mnt->ovl_lower = (ovl_lower) ? mnt_lower->target : NULL;
	IF_TRUE_GOTO(c_shiftid_prepare_dir(shiftid, mnt, src) < 0, error);

	shiftid->marks = list_append(shiftid->marks, mnt);

	return 0;
error:
	if (mnt)
		c_shiftid_mnt_free(mnt);
	if (mnt_lower)
		c_shiftid_mnt_free(mnt_lower);
	return -1;
}

/**
 * Shifts or sets uid/gids of path using the parent ids for this c_shiftid_t
 *
 * Call this inside the parent user_ns.
 */
static int
c_shiftid_shift_ids(void *shiftidp, const char *src, const char *dst, const char *ovl_lower)
{
	c_shiftid_t *shiftid = shiftidp;
	ASSERT(shiftid);

	/* We can skip this in case the container has no user ns */
	if (!container_has_userns(shiftid->container))
		return 0;

	TRACE("uid %d, euid %d", getuid(), geteuid());

	int container_uid = container_get_uid(shiftid->container);

	// if we just got a single file chown this and return
	if (file_exists(src) && !file_is_dir(src)) {
		if (lchown(src, container_uid, container_uid) < 0) {
			ERROR_ERRNO("Could not chown file '%s' to (%d:%d)", src, container_uid,
				    container_uid);
			goto error;
		}
		goto success;
	}

	bool is_dev = strlen(src) >= 5 && !strcmp(strrchr(src, '\0') - 4, "/dev");
	bool is_cgroup = strstr(src, "/cgroup") != NULL;

	// if cgroup subsys or dev just chown the files
	if (is_dev || is_cgroup) {
		if (dir_foreach(src, &c_shiftid_chown_dir_cb, shiftid) < 0) {
			ERROR("Could not chown %s to target uid:gid (%d:%d)", src, container_uid,
			      container_uid);
			goto error;
		}
		if ((is_dev && shiftid->is_dev_mounted) || is_cgroup)
			goto success;
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

	IF_TRUE_GOTO(c_shiftid_mount_shifted(shiftid, src, dst, ovl_lower) < 0, error);
success:

	INFO("Successfully shifted uids for '%s'", src);
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

		if (mnt->ovl_lower) {
			if (c_shiftid_mount_ovl(mnt->mark, mnt->target, mnt->ovl_lower, true)) {
				ERROR("Failed to mount ovl '%s' (lower='%s') in userns on '%s'",
				      mnt->mark, mnt->ovl_lower, mnt->target);
				return -1;
			}
			continue;
		}

		// always bind mount dev
		bool is_dev =
			strlen(mnt->target) >= 4 && !strcmp(strrchr(mnt->target, '\0') - 4, "/dev");

		// mount the shifted user ids to new root
		IF_TRUE_RETVAL(dir_mkdir_p(mnt->target, 0777) < 0, -1);
		if (mount(mnt->mark, mnt->target, "shiftfs",
			  (cmld_is_shiftfs_supported() && !is_dev) ? 0 : MS_BIND, NULL) < 0) {
			ERROR_ERRNO("Could not remount shiftfs mark %s to %s", mnt->mark,
				    mnt->target);
		} else {
			INFO("Successfully shifted root uid/gid for userns mount %s", mnt->target);
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
