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

#define _GNU_SOURCE

#define MOD_NAME "c_idmapped"

#include <fcntl.h>
#include <linux/magic.h>
#include <linux/types.h>
#include <sys/mount.h>
#include <linux/mount.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/kernel.h"
#include "container.h"

#define IDMAPPED_SRC_DIR "/tmp/idmapped_mnts"
#define UID_RANGE 100000

/**************************/
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif

#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID 0x00000002
#endif

#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC 0x00000008
#endif

#ifndef MOUNT_ATTR_NODIRATIME
#define MOUNT_ATTR_NODIRATIME 0x00000080
#endif

#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME 0x00000070
#endif

#ifndef MOUNT_ATTR_RELATIME
#define MOUNT_ATTR_RELATIME 0x00000000
#endif

#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME 0x00000010
#endif

#ifndef MOUNT_ATTR_STRICTATIME
#define MOUNT_ATTR_STRICTATIME 0x00000020
#endif

#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP 0x00100000
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

// clang-format off
#ifndef __NR_mount_setattr
	#if defined __alpha__
		#define __NR_mount_setattr 552
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32        /* o32 */
			#define __NR_mount_setattr (442 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32       /* n32 */
			#define __NR_mount_setattr (442 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64        /* n64 */
			#define __NR_mount_setattr (442 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_mount_setattr (442 + 1024)
	#else
		#define __NR_mount_setattr 442
	#endif
// clang-format on

struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};
#endif

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif

#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

// clang-format off
#ifndef __NR_open_tree
	#if defined __alpha__
		#define __NR_open_tree 538
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32        /* o32 */
			#define __NR_open_tree 4428
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32       /* n32 */
			#define __NR_open_tree 6428
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64        /* n64 */
			#define __NR_open_tree 5428
		#endif
	#elif defined __ia64__
		#define __NR_open_tree (428 + 1024)
	#else
		#define __NR_open_tree 428
	#endif
#endif
// clang-format on

#ifndef MOVE_MOUNT_F_SYMLINKS
#define MOVE_MOUNT_F_SYMLINKS 0x00000001
#endif

#ifndef MOVE_MOUNT_F_AUTOMOUNTS
#define MOVE_MOUNT_F_AUTOMOUNTS 0x00000002
#endif

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

#ifndef MOVE_MOUNT_T_SYMLINKS
#define MOVE_MOUNT_T_SYMLINKS 0x00000010
#endif

#ifndef MOVE_MOUNT_T_AUTOMOUNTS
#define MOVE_MOUNT_T_AUTOMOUNTS 0x00000020
#endif

#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#endif

#ifndef MOVE_MOUNT__MASK
#define MOVE_MOUNT__MASK 0x00000077
#endif

// clang-format off
#ifndef __NR_move_mount
	#if defined __alpha__
		#define __NR_move_mount 539
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32
			#define __NR_move_mount 4429
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32
			#define __NR_move_mount 6429
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64
			#define __NR_move_mount 5429
		#endif
	#elif defined __ia64__
		#define __NR_move_mount (428 + 1024)
	#else
		#define __NR_move_mount 429
	#endif
#endif
// clang-format on

int
mount_setattr(int dirfd, const char *path, unsigned int flags, struct mount_attr *attr, size_t size)
{
	return syscall(__NR_mount_setattr, dirfd, path, flags, attr, size);
}

int
open_tree(int dirfd, const char *path, unsigned int flags)
{
	return syscall(__NR_open_tree, dirfd, path, flags);
}

int
move_mount(int from_dirfd, const char *from_path, int to_dirfd, const char *to_path,
	   unsigned int flags)
{
	return syscall(__NR_move_mount, from_dirfd, from_path, to_dirfd, to_path, flags);
}
/**************************/

struct c_idmapped_mnt {
	char *target;
	char *src;
	int mapped_tree_fd;
	char *ovl_lower;
	char *ovl_upper;
	bool bind_in_child;
};

/* idmapped structure with specific directory mappings */
typedef struct c_idmapped {
	container_t *container; //!< container which the c_idmapped struct is associated to
	list_t *mapped_mnts;	//idmapped mounts (c_idmapped_mnt) to be mounted in userns
	int src_index;
	bool is_dev_mounted; // checks if the bind mount for dev is already performed
} c_idmapped_t;

struct c_idmapped_chown_dir_cbdata {
	int uid;
	int gid;
};

static void
c_idmapped_mnt_free(struct c_idmapped_mnt *mnt)
{
	IF_NULL_RETURN_ERROR(mnt);
	mem_free0(mnt->src);
	mem_free0(mnt->target);
	if (mnt->ovl_lower)
		mem_free0(mnt->ovl_lower);
	if (mnt->ovl_upper)
		mem_free0(mnt->ovl_upper);
	mem_free0(mnt);
}

/**
 * This function allocates a new c_idmapped_t instance, associated to a specific container object.
 * @return the c_idmapped_t idmapped structure which holds idmapped mounts for a container.
 */
static void *
c_idmapped_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_idmapped_t *idmapped = mem_new0(c_idmapped_t, 1);
	idmapped->container = compartment_get_extension_data(compartment);
	idmapped->is_dev_mounted = false;
	idmapped->src_index = 0;

	TRACE("new c_idmapped struct was allocated");

	return idmapped;
}

static void
c_idmapped_free(void *idmappedp)
{
	c_idmapped_t *idmapped = idmappedp;
	ASSERT(idmapped);
	mem_free0(idmapped);
}

static int
c_idmapped_chown_dir_cb(const char *path, const char *file, void *data)
{
	struct stat s;
	int ret = 0;
	struct c_idmapped_chown_dir_cbdata *cbdata = data;
	ASSERT(cbdata);

	char *file_to_chown = mem_printf("%s/%s", path, file);
	if (lstat(file_to_chown, &s) == -1) {
		mem_free0(file_to_chown);
		return -1;
	}

	// modulo operation avoids shifting twice
	uid_t uid = s.st_uid % UID_RANGE + cbdata->uid;
	gid_t gid = s.st_gid % UID_RANGE + cbdata->gid;

	if (file_is_dir(file_to_chown)) {
		TRACE("Path %s is dir", file_to_chown);
		if (dir_foreach(file_to_chown, &c_idmapped_chown_dir_cb, cbdata) < 0) {
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
	TRACE("Chown file '%s' to (%d:%d) (uid_start %d)", file_to_chown, uid, gid, cbdata->uid);

	// chown .
	if (chown(path, uid, gid) < 0) {
		ERROR_ERRNO("Could not chown dir '%s' to (%d:%d)", path, uid, gid);
		ret--;
	}
	mem_free0(file_to_chown);
	return ret;
}

static int
c_idmapped_mnt_apply_mapping(struct c_idmapped_mnt *mnt, int userns_fd)
{
	ASSERT(mnt);

	/*
	 * Revert mapping done by chown of previously running container
	 * without idmapping support.
	 */
	struct stat s;
	if (lstat(mnt->src, &s) == -1) {
		return -1;
	}
	if (s.st_uid != 0) {
		struct c_idmapped_chown_dir_cbdata cbdata = { .uid = 0, .gid = 0 };
		if (dir_foreach(mnt->src, &c_idmapped_chown_dir_cb, &cbdata) < 0) {
			ERROR("Could not revert mapping done by chown %s to target uid:gid (%d:%d)",
			      mnt->src, cbdata.uid, cbdata.gid);
			return -1;
		}
		DEBUG("Reverted mapping done by chown %s from %d to target uid:gid (%d:%d)",
		      mnt->src, s.st_uid, cbdata.uid, cbdata.gid);
	}

	struct mount_attr attr = { 0 };
	attr.userns_fd = userns_fd;
	attr.attr_set = MOUNT_ATTR_IDMAP;

	if ((mnt->mapped_tree_fd = open_tree(
		     -1, mnt->src, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH)) < 0) {
		ERROR_ERRNO("Could not open_tree dir '%s' for container start", mnt->src);
		goto error;
	}

	if (mount_setattr(mnt->mapped_tree_fd, "", AT_EMPTY_PATH, &attr,
			  sizeof(struct mount_attr))) {
		ERROR_ERRNO("Could not setattr for the new dir '%s' for container start", mnt->src);
		close(mnt->mapped_tree_fd);
		goto error;
	}

	INFO("Sucessfully applied idmapping from src dir %s on fd=%d for %s", mnt->src,
	     mnt->mapped_tree_fd, mnt->target);

	close(userns_fd);
	return 0;

error:
	if (userns_fd > 0)
		close(userns_fd);
	return -1;
}

static int
c_idmapped_mount_ovl(const char *overlayfs_mount_dir, const char *target, const char *ovl_lower)
{
	char *lower_dir = mem_printf("%s/lower", overlayfs_mount_dir);
	char *upper_dir = mem_printf("%s/upper", overlayfs_mount_dir);
	char *work_dir = mem_printf("%s/work", overlayfs_mount_dir);

	DEBUG("Mounting overlayfs: work_dir=%s, upper_dir=%s, lower_dir=%s, target dir=%s",
	      work_dir, upper_dir, ovl_lower, target);

	// needed for tmpfs of fallback mechanism where lower image is read only and a temporary
	// upper tmpfs for chowning is used
	if (dir_mkdir_p(upper_dir, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir upper dir %s", upper_dir);
		goto error;
	}
	if (dir_mkdir_p(work_dir, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir work dir %s", work_dir);
		goto error;
	}

	if (strcmp(ovl_lower, lower_dir) != 0) {
		if (file_is_link(lower_dir))
			unlink(lower_dir);
		if (symlink(ovl_lower, lower_dir) < 0) {
			ERROR_ERRNO("Failed to created link to %s on %s", ovl_lower, lower_dir);
			mem_free0(lower_dir);
			lower_dir = mem_strdup(ovl_lower);
		}
		if (file_is_link(lower_dir))
			INFO("Sucessfully created link to %s on %s", ovl_lower, lower_dir);
	}

	DEBUG("Mounting overlayfs: work_dir=%s, upper_dir=%s, lower_dir=%s, target dir=%s",
	      work_dir, upper_dir, lower_dir, target);
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
	INFO("mount_dir: %s", target);
	// mount overlayfs to dir
	if (mount("overlay", target, "overlay", 0, overlayfs_options) < 0) {
		ERROR_ERRNO("Could not mount overlay");
		mem_free0(overlayfs_options);
		if (chdir(cwd))
			WARN("Could not change back to former cwd %s", cwd);
		mem_free0(cwd);
		goto error;
	}
	mem_free0(overlayfs_options);
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

static bool
is_idmapping_supported()
{
	return kernel_version_check("6.3");
}

static int
c_idmapped_prepare_dir(c_idmapped_t *idmapped, struct c_idmapped_mnt *mnt, const char *dir)
{
	ASSERT(idmapped && mnt && dir);

	// if kernel is to old and does not support idmapped mounts just chown the files
	// and do bind mounts
	int container_uid = container_get_uid(idmapped->container);
	struct statfs dir_statfs;
	statfs(dir, &dir_statfs);

	if (!is_idmapping_supported()) {
		if (dir_statfs.f_flags & MS_RDONLY) {
			char *tmpfs_dir =
				mem_printf("%s/%s/tmp%d", IDMAPPED_SRC_DIR,
					   uuid_string(container_get_uuid(idmapped->container)),
					   idmapped->src_index);
			if (dir_mkdir_p(tmpfs_dir, 0777) < 0) {
				ERROR_ERRNO("Could not mkdir idmapped dir %s", tmpfs_dir);
				mem_free0(tmpfs_dir);
				return -1;
			}
			if (mount(NULL, tmpfs_dir, "tmpfs", 0, NULL) < 0) {
				ERROR_ERRNO("Could not mount tmpfs to %s", tmpfs_dir);
				mem_free0(tmpfs_dir);
				return -1;
			}
			if (c_idmapped_mount_ovl(tmpfs_dir, dir, dir)) {
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
		struct c_idmapped_chown_dir_cbdata cbdata = { .uid = container_uid,
							      .gid = container_uid };
		if (dir_foreach(dir, &c_idmapped_chown_dir_cb, &cbdata) < 0) {
			ERROR("Could not chown %s to target uid:gid (%d:%d)", dir, cbdata.uid,
			      cbdata.gid);
			return -1;
		}

		if (dir_statfs.f_flags & MS_RDONLY) {
			if (mount("none", dir, "none", MS_REMOUNT | MS_RDONLY, NULL) < 0) {
				ERROR_ERRNO("Could not remount tmpfs on %s", dir);
				return -1;
			}
		}
	}

	mnt->src = mem_printf("%s/%s/src/%d", IDMAPPED_SRC_DIR,
			      uuid_string(container_get_uuid(idmapped->container)),
			      idmapped->src_index++);

	if (dir_mkdir_p(mnt->src, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir mapped dir %s", mnt->src);
		return -1;
	}

	if (mount(dir, mnt->src, NULL, MS_BIND, NULL) < 0) {
		ERROR_ERRNO("Could not bind mount image origin %s on src %s", dir, mnt->src);
		return -1;
	}

	if (!is_idmapping_supported())
		return 0;

	/*
	 * In case of dev, we cannot use user namespace mounts since the kernel
	 * always implcitly sets the SB_I_NODEV flag for filesystems mounted
	 * in non-inital userns. Thus, we just bind mounted it and return here.
	 */
	if (strlen(mnt->target) >= 4 && !strcmp(strrchr(mnt->target, '\0') - 4, "/dev")) {
		if (chown(dir, container_uid, container_uid) < 0) {
			ERROR_ERRNO("Could not chown mnt point '%s' to (%d:%d)", dir, container_uid,
				    container_uid);
			return -1;
		}
		idmapped->is_dev_mounted = true;
		mnt->bind_in_child = true;
		mnt->mapped_tree_fd = -1;
		return 0;
	}

	if (mnt->ovl_lower && !strcmp(mnt->ovl_lower, mnt->target)) {
		mnt->mapped_tree_fd = -1;
		return 0;
	}

	int userns_fd = -1;
	if ((userns_fd = container_open_userns(idmapped->container)) == -1) {
		ERROR_ERRNO("Could not open userns_fd for container start");
		return -1;
	}

	int ret = c_idmapped_mnt_apply_mapping(mnt, userns_fd);

	if (mnt->ovl_lower)
		return ret;

	if (mnt->mapped_tree_fd > 0 &&
	    move_mount(mnt->mapped_tree_fd, "", -1, mnt->src, MOVE_MOUNT_F_EMPTY_PATH) == -1) {
		ERROR_ERRNO("Could not move_mount %d on %s for container start",
			    mnt->mapped_tree_fd, mnt->src);
		return -1;
	}

	// already shifted in init userns, bind mount in child
	mnt->mapped_tree_fd = -1;
	mnt->bind_in_child = true;

	return ret;
}

static int
c_idmapped_mount_idmapped(c_idmapped_t *idmapped, const char *src, const char *dst,
			  const char *ovl_lower)
{
	struct c_idmapped_mnt *mnt = NULL;
	struct c_idmapped_mnt *mnt_lower = NULL;
	struct c_idmapped_mnt *mnt_upper = NULL;

	mnt = mem_new0(struct c_idmapped_mnt, 1);
	mnt->target = mem_strdup(dst);

	if (ovl_lower) {
		// mount ovl in rootns if kernel is to old
		if (!is_idmapping_supported()) {
			if (c_idmapped_mount_ovl(src, src, ovl_lower)) {
				ERROR("Failed to mount ovl '%s' (lower='%s') in rootns on '%s'",
				      src, ovl_lower, dst);
				goto error;
			}
			if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
				ERROR_ERRNO("Could not bind ovl in rootns '%s' on %s", src, dst);
				goto error;
			}
			// set shifted lower as ovl_lower
			mnt->ovl_lower = NULL;
			IF_TRUE_GOTO(c_idmapped_prepare_dir(idmapped, mnt, src) < 0, error);

			idmapped->mapped_mnts = list_append(idmapped->mapped_mnts, mnt);
			return 0;
		}

		// mount lower idmapped if not over mounting lower dir itself
		if (!strcmp(ovl_lower, dst))
			mnt->ovl_lower = mem_strdup(dst);
		else {
			mnt_lower = mem_new0(struct c_idmapped_mnt, 1);
			mnt_lower->target =
				mem_printf("%s/%s/ovl%d", IDMAPPED_SRC_DIR,
					   uuid_string(container_get_uuid(idmapped->container)),
					   idmapped->src_index);
			if (dir_mkdir_p(mnt_lower->target, 0777) < 0) {
				ERROR_ERRNO("Could not mkdir idmapped lower dir %s",
					    mnt_lower->target);
				goto error;
			}

			mnt_lower->ovl_lower = NULL;
			IF_TRUE_GOTO(c_idmapped_prepare_dir(idmapped, mnt_lower, ovl_lower) < 0,
				     error);

			idmapped->mapped_mnts = list_append(idmapped->mapped_mnts, mnt_lower);

			// set idmapped lower as ovl_lower
			mnt->ovl_lower = mem_strdup(mnt_lower->target);
		}

		// mount upper idmapped
		mnt->ovl_upper = mem_printf("%s/%s/ovl%d", IDMAPPED_SRC_DIR,
					    uuid_string(container_get_uuid(idmapped->container)),
					    idmapped->src_index);
		if (dir_mkdir_p(mnt->ovl_upper, 0777) < 0) {
			ERROR_ERRNO("Could not mkdir idmapped upper dir %s", mnt->ovl_upper);
			goto error;
		}
		mnt_upper = mem_new0(struct c_idmapped_mnt, 1);
		mnt_upper->target = mem_strdup(mnt->ovl_upper);

		IF_TRUE_GOTO(c_idmapped_prepare_dir(idmapped, mnt_upper, src) < 0, error);
		idmapped->mapped_mnts = list_append(idmapped->mapped_mnts, mnt_upper);
	}

	IF_TRUE_GOTO(c_idmapped_prepare_dir(idmapped, mnt, src) < 0, error);
	idmapped->mapped_mnts = list_append(idmapped->mapped_mnts, mnt);

	return 0;

error:
	if (mnt)
		c_idmapped_mnt_free(mnt);
	if (mnt_lower)
		c_idmapped_mnt_free(mnt_lower);
	if (mnt_upper)
		c_idmapped_mnt_free(mnt_upper);
	return -1;
}

/**
 * Shifts or sets uid/gids of path using the parent ids for this c_idmapped_t
 *
 * Call this inside the parent user_ns.
 */
static int
c_idmapped_shift_ids(void *idmappedp, const char *src, const char *dst, const char *ovl_lower)
{
	c_idmapped_t *idmapped = idmappedp;
	ASSERT(idmapped);

	/* We can skip this in case the container has no user ns */
	if (!container_has_userns(idmapped->container))
		return 0;

	TRACE("uid %d, euid %d", getuid(), geteuid());

	int uid = container_get_uid(idmapped->container);

	// if we just got a single file chown this and return
	if (file_exists(src) && !file_is_dir(src)) {
		if (lchown(src, uid, uid) < 0) {
			ERROR_ERRNO("Could not chown file '%s' to (%d:%d)", src, uid, uid);
			goto error;
		}
		goto success;
	}

	bool is_dev = strlen(dst) >= 5 && !strcmp(strrchr(dst, '\0') - 4, "/dev");
	bool is_cgroup = strstr(src, "/cgroup") != NULL;

	// if cgroup subsys or dev just chown the files
	if (is_dev || is_cgroup) {
		struct c_idmapped_chown_dir_cbdata cbdata = { .uid = uid, .gid = uid };
		if (dir_foreach(src, &c_idmapped_chown_dir_cb, &cbdata) < 0) {
			ERROR("Could not chown %s to target uid:gid (%d:%d)", src, cbdata.uid,
			      cbdata.gid);
			return -1;
		}
		if ((is_dev && idmapped->is_dev_mounted) || is_cgroup)
			goto success;
	}

	if (dir_mkdir_p(IDMAPPED_SRC_DIR, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir %s", IDMAPPED_SRC_DIR);
		return -1;
	}
	if (chmod(IDMAPPED_SRC_DIR, 00777) < 0) {
		ERROR_ERRNO("Could not chmod %s", IDMAPPED_SRC_DIR);
		goto error;
	}

	IF_TRUE_GOTO(c_idmapped_mount_idmapped(idmapped, src, dst, ovl_lower) < 0, error);
success:

	INFO("Successfully idmapped uids for '%s'", src);
	return 0;
error:
	return -1;
}

static int
c_idmapped_start_child(void *idmappedp)
{
	c_idmapped_t *idmapped = idmappedp;
	ASSERT(idmapped);

	/* We can skip this in case the container has no user ns */
	if (!container_has_userns(idmapped->container))
		return 0;

	for (list_t *l = idmapped->mapped_mnts; l; l = l->next) {
		struct c_idmapped_mnt *mnt = l->data;
		ASSERT(mnt->src && mnt->target);

		INFO("mounting mnt in usrns src='%s', target='%s', ovl_lower='%s', ovl_upper='%s'",
		     mnt->src, mnt->target, mnt->ovl_lower ? mnt->ovl_lower : "-",
		     mnt->ovl_upper ? mnt->ovl_upper : "-");

		// if explictly set to bind inchild (e.g. /dev on tmpfs) or
		// kernel does not support idmapped mounts just do bind mount
		if (mnt->bind_in_child || (!is_idmapping_supported())) {
			if (!file_exists(mnt->target))
				dir_mkdir_p(mnt->target, 0755);

			if (mount(mnt->src, mnt->target, NULL, MS_BIND, NULL) < 0) {
				ERROR_ERRNO("Could not bind mount src %s to %s", mnt->src,
					    mnt->target);
				goto error;
			}
			continue;
		}

		if (mnt->mapped_tree_fd > 0 &&
		    move_mount(mnt->mapped_tree_fd, "", -1,
			       mnt->ovl_upper ? mnt->ovl_upper : mnt->target,
			       MOVE_MOUNT_F_EMPTY_PATH) == -1) {
			ERROR_ERRNO("Could not move_mount %s on %s for container start", mnt->src,
				    mnt->ovl_upper ? mnt->ovl_upper : mnt->target);
			goto error;
		} else {
			INFO("Successfully move_mount %s on %s for container start", mnt->src,
			     mnt->ovl_upper ? mnt->ovl_upper : mnt->target);
		}

		if (mnt->ovl_lower) {
			if (c_idmapped_mount_ovl(mnt->ovl_upper, mnt->target, mnt->ovl_lower)) {
				ERROR("Failed to mount ovl '%s' in userns on '%s'", mnt->ovl_upper,
				      mnt->target);
				goto error;
			}
		}
	}

	INFO("Mounting with idmapped user and gids succseeded.");
	return 0;
error:
	return -COMPARTMENT_ERROR_USER;
}

static int
c_idmapped_umount_dir_cb(const char *path, const char *file, UNUSED void *data)
{
	char *file_to_umount = mem_printf("%s/%s", path, file);
	bool was_mnt = file_is_mountpoint(file_to_umount);
	bool is_mnt = was_mnt;

	while (is_mnt) {
		if (umount(file_to_umount) < 0) {
			WARN_ERRNO("Could not release bind mount on '%s'", file_to_umount);
			break;
		} else {
			DEBUG("Released bind mount on '%s'", file_to_umount);
		}
		is_mnt = file_is_mountpoint(file_to_umount);
	}
	IF_TRUE_GOTO_TRACE(was_mnt, out);

	if (file_is_dir(file_to_umount)) {
		if (dir_foreach(file_to_umount, &c_idmapped_umount_dir_cb, NULL) < 0) {
			WARN("Could not umount srcs on %s", file_to_umount);
		}
	} else {
		DEBUG("No mount point '%s'", file_to_umount);
	}
out:
	mem_free0(file_to_umount);
	return 0;
}

/**
 * Cleans up the c_idmapped_t struct.
 */
static void
c_idmapped_cleanup(void *idmappedp, UNUSED bool is_rebooting)
{
	c_idmapped_t *idmapped = idmappedp;
	ASSERT(idmapped);

	char *src_compartment_dir =
		mem_printf("%s/%s/src", IDMAPPED_SRC_DIR,
			   uuid_string(container_get_uuid(idmapped->container)));

	// release bindmounts to src directories in root ns
	if (dir_foreach(src_compartment_dir, &c_idmapped_umount_dir_cb, NULL) < 0) {
		WARN("Could not umount srcs on %s", src_compartment_dir);
	}

	for (list_t *l = idmapped->mapped_mnts; l; l = l->next) {
		struct c_idmapped_mnt *mnt = l->data;
		c_idmapped_mnt_free(mnt);
	}
	list_delete(idmapped->mapped_mnts);
	idmapped->mapped_mnts = NULL;

	idmapped->is_dev_mounted = false;
	idmapped->src_index = 0;

	mem_free0(src_compartment_dir);
}

static compartment_module_t c_idmapped_module = {
	.name = MOD_NAME,
	.compartment_new = c_idmapped_new,
	.compartment_free = c_idmapped_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = c_idmapped_start_child,
	.start_pre_exec_child_early = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_idmapped_cleanup,
	.join_ns = NULL,
};

static void INIT
c_idmapped_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_idmapped_module);

	// register relevant handlers implemented by this module
	container_register_shift_ids_handler(MOD_NAME, c_idmapped_shift_ids);
}
