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

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define _LARGEFILE64_SOURCE

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "c_vol.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/loopdev.h"
#include "common/cryptfs.h"
#include "common/dir.h"
#include "common/proc.h"
#include "common/sock.h"
#include "common/str.h"

#include "cmld.h"
#include "hardware.h"
#include "guestos.h"
#include "smartcard.h"
#include "lxcfs.h"
#include "audit.h"

#include <unistd.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>

#define MAKE_EXT4FS "mkfs.ext4"
#define BTRFSTUNE "btrfstune"
#define MAKE_BTRFS "mkfs.btrfs"
#define MDEV "mdev"

#define SHARED_FILES_PATH DEFAULT_BASE_PATH "/files_shared"
#define SHARED_FILES_STORE_SIZE 100

#define BUSYBOX_PATH "/bin/busybox"

#ifndef FALLOC_FL_ZERO_RANGE
#define FALLOC_FL_ZERO_RANGE 0x10
#endif

struct c_vol {
	const container_t *container;
	char *root;
	int overlay_count;
};

/******************************************************************************/

/**
 * Allocate a new string with the full image path for one mount point.
 * TODO store img_path in mount_entry_t instances themselves?
 * @return A newly allocated string with the image path.
 */
static char *
c_vol_image_path_new(c_vol_t *vol, const mount_entry_t *mntent)
{
	const char *dir;

	ASSERT(vol);
	ASSERT(mntent);

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_SHARED:
	case MOUNT_TYPE_SHARED_RW:
	case MOUNT_TYPE_FLASH:
	case MOUNT_TYPE_OVERLAY_RO:
		dir = guestos_get_dir(container_get_os(vol->container));
		break;
	case MOUNT_TYPE_DEVICE:
	case MOUNT_TYPE_DEVICE_RW:
	case MOUNT_TYPE_EMPTY:
	case MOUNT_TYPE_COPY:
	case MOUNT_TYPE_OVERLAY_RW:
		// Note: this is the upper img for overlayfs
		dir = container_get_images_dir(vol->container);
		break;
	case MOUNT_TYPE_BIND_FILE:
	case MOUNT_TYPE_BIND_FILE_RW:
		return mem_printf("%s/%s", SHARED_FILES_PATH, mount_entry_get_img(mntent));
	default:
		ERROR("Unsupported operating system mount type %d for %s",
		      mount_entry_get_type(mntent), mount_entry_get_img(mntent));
		return NULL;
	}

	return mem_printf("%s/%s.img", dir, mount_entry_get_img(mntent));
}

static char *
c_vol_meta_image_path_new(c_vol_t *vol, const mount_entry_t *mntent)
{
	const char *dir;

	ASSERT(vol);
	ASSERT(mntent);

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_DEVICE:
	case MOUNT_TYPE_DEVICE_RW:
	case MOUNT_TYPE_EMPTY:
	case MOUNT_TYPE_COPY:
	case MOUNT_TYPE_OVERLAY_RW:
		// Note: this is the upper img for overlayfs
		dir = container_get_images_dir(vol->container);
		break;
	default:
		ERROR("Unsupported operating system mount type %d for %s (intergity meta_device)",
		      mount_entry_get_type(mntent), mount_entry_get_img(mntent));
		return NULL;
	}

	return mem_printf("%s/%s.meta.img", dir, mount_entry_get_img(mntent));
}

/**
 * Check wether a container image is ready to be mounted.
 * @return On error -1 is returned, otherwise 0.
 */
static int
c_vol_check_image(c_vol_t *vol, const char *img)
{
	int ret;

	ASSERT(vol);
	ASSERT(img);

	ret = access(img, F_OK);

	if (ret < 0)
		DEBUG_ERRNO("Could not access image file %s", img);
	else
		DEBUG("Image file %s seems to be fine", img);

	return ret;
}

static char *
c_vol_create_loopdev_new(int *fd, const char *img)
{
	char *dev = loopdev_new();
	if (!dev) {
		ERROR("Could not get free loop device for %s", img);
		return NULL;
	}

	// wait until the devie appears...
	// TODO: how was this timeout chosen?
	// TODO: maybe better wait for the uevent?
	if (loopdev_wait(dev, 10) < 0) {
		ERROR("Device %s for image %s was not created", dev, img);
		goto error;
	}

	// TODO: there might be another process trying to setup a device for dev
	*fd = loopdev_setup_device(img, dev);
	if (*fd < 0) {
		ERROR("Could not setup loop device %s for %s", dev, img);
		goto error;
	}
	return dev;
error:
	mem_free0(dev);
	return NULL;
}

static int
c_vol_create_sparse_file(const char *img, off64_t storage_size)
{
	int fd;

	ASSERT(img);

	INFO("Creating empty image file %s with %llu bytes", img, (unsigned long long)storage_size);

	fd = open(img, O_LARGEFILE | O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		ERROR_ERRNO("Could not open image file %s", img);
		return -1;
	}

	// create a sparse file without writing any data
	if (ftruncate64(fd, storage_size) < 0) {
		ERROR_ERRNO("Could not ftruncate image file %s", img);
		close(fd);
		return -1;
	}

	if (lseek64(fd, storage_size - 1, SEEK_SET) < 0) {
		ERROR_ERRNO("Could not lseek image file %s", img);
		close(fd);
		return -1;
	}

	if (write(fd, "\0", 1) < 1) {
		ERROR_ERRNO("Could not write to image file %s", img);
		close(fd);
		return -1;
	}

	// also allocate with  zeros for dm-integrity
	if (fallocate(fd, FALLOC_FL_ZERO_RANGE, 0, storage_size)) {
		ERROR_ERRNO("Could not write to image file %s", img);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int
c_vol_create_image_empty(const char *img, const char *img_meta, uint64_t size)
{
	off64_t storage_size;
	ASSERT(img);

	// minimal storage size is 10 MB
	storage_size = MAX(size, 10);
	storage_size *= 1024 * 1024;

	IF_TRUE_RETVAL(-1 == c_vol_create_sparse_file(img, storage_size), -1);

	if (img_meta) {
		off64_t meta_size = storage_size / 10;
		IF_TRUE_RETVAL(-1 == c_vol_create_sparse_file(img_meta, meta_size), -1);
	}

	return 0;
}

static int
c_vol_btrfs_regen_uuid(const char *dev)
{
	const char *const argv_regen[] = { BTRFSTUNE, "-f", "-u", dev, NULL };
	return proc_fork_and_execvp(argv_regen);
}

static int
c_vol_create_image_copy(c_vol_t *vol, const char *img, const mount_entry_t *mntent)
{
	const char *dir;
	char *src;
	int ret;

	dir = guestos_get_dir(container_get_os(vol->container));
	if (!dir) {
		ERROR("Could not get directory with operating system images");
		return -1;
	}

	src = mem_printf("%s/%s.img", dir, mount_entry_get_img(mntent));

	DEBUG("Copying file %s to %s", src, img);
	ret = file_copy(src, img, -1, 512, 0);
	if (ret < 0)
		ERROR("Could not copy file %s to %s", src, img);

	if (!strcmp("btrfs", mount_entry_get_fs(mntent))) {
		INFO("Regenerate UUID for btrfs filesystem on %s", img);
		ret = c_vol_btrfs_regen_uuid(img);
	}

	mem_free0(src);
	return ret;
}

static int
c_vol_create_image_device(c_vol_t *vol, const char *img, const mount_entry_t *mntent)
{
	const char *dir;
	char *dev;
	int ret;

	ASSERT(vol);
	ASSERT(img);
	ASSERT(mntent);

	dir = hardware_get_block_by_name_path();
	if (!dir) {
		ERROR("Could not get block by name path for hardware");
		return -1;
	}

	// example for dev: /dev/block/platform/msm_sdcc.1/by-name/efs
	dev = mem_printf("%s/%s", dir, mount_entry_get_img(mntent));

	ret = file_copy(dev, img, -1, 512, 0);
	if (ret < 0)
		ERROR("Could not copy file %s to %s", dev, img);

	mem_free0(dev);
	return ret;
}

static int
c_vol_create_image(c_vol_t *vol, const char *img, const mount_entry_t *mntent)
{
	INFO("Creating image %s", img);

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_SHARED:
		return 0;
	case MOUNT_TYPE_SHARED_RW:
	case MOUNT_TYPE_OVERLAY_RW:
	case MOUNT_TYPE_EMPTY: {
		char *img_meta = c_vol_meta_image_path_new(vol, mntent);
		int ret = c_vol_create_image_empty(img, img_meta, mount_entry_get_size(mntent));
		mem_free0(img_meta);
		return ret;
	}
	case MOUNT_TYPE_FLASH:
		return -1; // we cannot create such image files
	case MOUNT_TYPE_COPY:
		return c_vol_create_image_copy(vol, img, mntent);
	case MOUNT_TYPE_DEVICE:
	case MOUNT_TYPE_DEVICE_RW:
		return c_vol_create_image_device(vol, img, mntent);
	default:
		ERROR("Unsupported operating system mount type %d for %s",
		      mount_entry_get_type(mntent), mount_entry_get_img(mntent));
		return -1;
	}

	return 0;
}

static int
c_vol_format_image(const char *dev, const char *fs)
{
	const char *mkfs_bin = NULL;
	if (0 == strcmp("ext4", fs)) {
		mkfs_bin = MAKE_EXT4FS;
	} else if (0 == strcmp("btrfs", fs)) {
		mkfs_bin = MAKE_BTRFS;
	} else {
		ERROR("Could not create filesystem of type %s on %s", fs, dev);
		return -1;
	}
	const char *const argv_mkfs[] = { mkfs_bin, dev, NULL };
	return proc_fork_and_execvp(argv_mkfs);
}

static int
c_vol_btrfs_create_subvol(const char *dev, const char *mount_data)
{
	IF_NULL_RETVAL(mount_data, -1);

	int ret = 0;
	char *token = mem_strdup(mount_data);
	char *subvol = strtok(token, "=");
	subvol = strtok(NULL, "=");
	if (NULL == subvol) {
		mem_free0(token);
		return -1;
	}

	char *subvol_path = NULL;
	char *tmp_mount = mem_strdup("/tmp/tmp.XXXXXX");
	tmp_mount = mkdtemp(tmp_mount);
	if (NULL == tmp_mount) {
		ret = -1;
		goto out;
	}
	if (-1 == (ret = mount(dev, tmp_mount, "btrfs", 0, 0))) {
		ERROR_ERRNO("temporary mount of btrfs root volume %s failed", dev);
		goto out;
	}
	subvol_path = mem_printf("%s/%s", tmp_mount, subvol);

	const char *const argv_list[] = { "btrfs", "subvol", "list", subvol_path, NULL };
	if (-1 == (ret = proc_fork_and_execvp(argv_list))) {
		const char *const argv_create[] = { "btrfs", "subvol", "create", subvol_path,
						    NULL };
		if (-1 == (ret = proc_fork_and_execvp(argv_create))) {
			ERROR_ERRNO("Could not create btrfs subvol %s", subvol);
		} else {
			INFO("Created new suvol %s on btrfs device %s", subvol, dev);
		}
	}
	if (-1 == (ret = umount(tmp_mount))) {
		ERROR_ERRNO("Could not umount temporary mount of btrfs root volume %s!", dev);
	}
out:
	if (tmp_mount)
		unlink(tmp_mount);
	if (subvol_path)
		mem_free0(subvol_path);
	if (tmp_mount)
		mem_free0(tmp_mount);
	if (token)
		mem_free0(token);
	return ret;
}

static int
c_vol_mount_overlay(const char *target_dir, const char *upper_fstype, const char *lowerfs_type,
		    int mount_flags, const char *mount_data, const char *upper_dev,
		    const char *lower_dev, const char *overlayfs_mount_dir)
{
	char *lower_dir, *upper_dir, *work_dir;
	lower_dir = upper_dir = work_dir = NULL;
	upper_dev = (upper_dev) ? upper_dev : "tmpfs";

	// create mountpoints for lower and upper dev
	if (dir_mkdir_p(overlayfs_mount_dir, 0755) < 0) {
		ERROR_ERRNO("Could not mkdir overlayfs dir %s", overlayfs_mount_dir);
		return -1;
	}
	lower_dir = mem_printf("%s/lower", overlayfs_mount_dir);
	upper_dir = mem_printf("%s/upper", overlayfs_mount_dir);
	work_dir = mem_printf("%s/work", overlayfs_mount_dir);

	/*
	 * mount backing fs image for overlayfs upper and work dir
	 * (at least upper and work need to be on the same fs)
	 */
	if (mount(upper_dev, overlayfs_mount_dir, upper_fstype, mount_flags, mount_data) < 0) {
		ERROR_ERRNO("Could not mount %s to %s", upper_dev, overlayfs_mount_dir);
		goto error;
	}
	DEBUG("Successfully mounted %s to %s", upper_dev, overlayfs_mount_dir);

	// create mountpoint for upper dev
	if (dir_mkdir_p(upper_dir, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir upper dir %s", upper_dir);
		goto error;
	}
	if (dir_mkdir_p(work_dir, 0777) < 0) {
		ERROR_ERRNO("Could not mkdir work dir %s", work_dir);
		goto error;
	}
	// create mountpoint for lower dev
	if (lower_dev) {
		if (dir_mkdir_p(lower_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir lower dir %s", lower_dir);
			goto error;
		}
		// mount ro image lower
		if (mount(lower_dev, lower_dir, lowerfs_type, mount_flags | MS_RDONLY, mount_data) <
		    0) {
			ERROR_ERRNO("Could not mount %s to %s", lower_dev, lower_dir);
			goto error;
		}
		DEBUG("Successfully mounted %s to %s", lower_dev, lower_dir);
	} else {
		// try to hide absolute paths (if just overmounting existing lower dir)
		if (file_is_link(lower_dir))
			unlink(lower_dir);
		if (symlink(target_dir, lower_dir) < 0) {
			ERROR_ERRNO("link lowerdir failed");
			mem_free0(lower_dir);
			lower_dir = mem_strdup(target_dir);
		}
	}
	DEBUG("Mounting overlayfs: work_dir=%s, upper_dir=%s, lower_dir=%s, target dir=%s",
	      work_dir, upper_dir, lower_dir, target_dir);
	// create mount option string (try to mask absolute paths)
	char *cwd = get_current_dir_name();
	char *overlayfs_options;
	if (chdir(overlayfs_mount_dir)) {
		overlayfs_options = mem_printf("lowerdir=%s,upperdir=%s,workdir=%s,metacopy=on",
					       lower_dir, upper_dir, work_dir);
	} else {
		overlayfs_options =
			mem_strdup("lowerdir=lower,upperdir=upper,workdir=work,metacopy=on");
		TRACE("old_wdir: %s, mount_cwd: %s, overlay_options: %s ", cwd, overlayfs_mount_dir,
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
c_vol_mount_file_bind(const char *src, const char *dst, unsigned long flags)
{
	char *_src = mem_strdup(src);
	char *_dst = mem_strdup(dst);
	char *dir_src = dirname(_src);
	char *dir_dst = dirname(_dst);

	if (!(flags & MS_BIND)) {
		errno = EINVAL;
		ERROR_ERRNO("bind mount flag is not set!");
		goto err;
	}

	if (dir_mkdir_p(dir_src, 0755) < 0) {
		DEBUG_ERRNO("Could not mkdir %s", dir_src);
		goto err;
	}
	if (dir_mkdir_p(dir_dst, 0755) < 0) {
		DEBUG_ERRNO("Could not mkdir %s", dir_dst);
		goto err;
	}
	if (file_touch(src) == -1) {
		ERROR("Failed to touch source file \"%s\" for bind mount", src);
		goto err;
	}
	if (file_touch(dst) == -1) {
		ERROR("Failed to touch target file \"%s\"for bind mount", dst);
		goto err;
	}
	if (mount(src, dst, "bind", flags, NULL) < 0) {
		ERROR_ERRNO("Failed to bind mount %s to %s", src, dst);
		goto err;
	}
	/*
	 * ro bind mounts do not work directly, so we need to remount it manually
	 * see, https://lwn.net/Articles/281157/
	 */
	if (flags & MS_RDONLY) { // ro bind mounts do not work directly
		if (mount("none", dst, "bind", flags | MS_RDONLY | MS_REMOUNT, NULL) < 0) {
			ERROR_ERRNO("Failed to remount bind"
				    " mount %s to %s read-only",
				    src, dst);
		}
	}
	DEBUG("Sucessfully bind mounted %s to %s", src, dst);

	mem_free0(_src);
	mem_free0(_dst);
	return 0;
err:
	mem_free0(_src);
	mem_free0(_dst);
	return -1;
}

static char *
c_vol_get_tmpfs_opts_new(const char *mount_data, int uid, int gid)
{
	str_t *opts = str_new(NULL);

	// Only mount tmpfs with uid, gid options if shiftfs is not supported
	// since later one it would be shifted by shiftfs twice.
	if (!cmld_is_shiftfs_supported())
		str_append_printf(opts, "uid=%d,gid=%d", uid, gid);

	if (mount_data)
		str_append_printf(opts, ",%s", mount_data);

	return str_free(opts, false);
}

/*
 * Copy busybox binary to target_base directory.
 * Remeber, this will only succeed if targetfs is writable.
 */
static int
c_vol_setup_busybox_copy(const char *target_base)
{
	int ret = 0;
	char *target_bin = mem_printf("%s%s", target_base, BUSYBOX_PATH);
	char *target_dir = mem_strdup(target_bin);
	char *target_dir_p = dirname(target_dir);
	if ((ret = dir_mkdir_p(target_dir_p, 0755)) < 0) {
		WARN_ERRNO("Could not mkdir '%s' dir", target_dir_p);
	} else if (file_exists("/bin/busybox")) {
		file_copy("/bin/busybox", target_bin, -1, 512, 0);
		INFO("Copied %s to container", target_bin);
		if (chmod(target_bin, 0755)) {
			WARN_ERRNO("Could not set %s executable", target_bin);
			ret = -1;
		}
	} else {
		WARN_ERRNO("Could not copy %s to container", target_bin);
		ret = -1;
	}

	mem_free0(target_bin);
	mem_free0(target_dir);
	return ret;
}

static int
c_vol_setup_busybox_install(void)
{
	// skip if busybox was not coppied
	IF_FALSE_RETVAL_TRACE(file_exists("/bin/busybox"), 0);

	IF_TRUE_RETVAL(dir_mkdir_p("/bin", 0755) < 0, -1);
	IF_TRUE_RETVAL(dir_mkdir_p("/sbin", 0755) < 0, -1);

	const char *const argv[] = { "busybox", "--install", "-s", NULL };
	return proc_fork_and_execvp(argv);
}

/**
 * Mount an image file. This function will take some time. So call it in a
 * thread or child process.
 * @param vol The vol struct for the container.
 * @param root The directory where the root file system should be mounted.
 * @param mntent The information for this mount.
 * @return -1 on error else 0.
 */
static int
c_vol_mount_image(c_vol_t *vol, const char *root, const mount_entry_t *mntent)
{
	char *img, *dev, *img_meta, *dev_meta, *dir;
	int fd = 0, fd_meta = 0;
	bool new_image = false;
	bool encrypted = mount_entry_is_encrypted(mntent);
	bool overlay = false;
	bool shiftids = false;
	bool is_root = strcmp(mount_entry_get_dir(mntent), "/") == 0;
	bool setup_mode = container_has_setup_mode(vol->container);
	int uid = container_get_uid(vol->container);

	// default mountflags for most image types
	unsigned long mountflags = setup_mode ? MS_NOATIME : MS_NOATIME | MS_NODEV;

	img = dev = img_meta = dev_meta = dir = NULL;

	if (mount_entry_get_dir(mntent)[0] == '/')
		dir = mem_printf("%s%s", root, mount_entry_get_dir(mntent));
	else
		dir = mem_printf("%s/%s", root, mount_entry_get_dir(mntent));

	img = c_vol_image_path_new(vol, mntent);
	if (!img)
		goto error;

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_SHARED:
	case MOUNT_TYPE_DEVICE:
		mountflags |= MS_RDONLY; // add read-only flag for shared or device images types
		break;
	case MOUNT_TYPE_OVERLAY_RO:
		mountflags |= MS_RDONLY; // add read-only flag for upper image
		overlay = true;
		break;
	case MOUNT_TYPE_SHARED_RW:
	case MOUNT_TYPE_OVERLAY_RW:
		overlay = true;
		shiftids = true;
		break;
	case MOUNT_TYPE_DEVICE_RW:
	case MOUNT_TYPE_EMPTY:
		shiftids = true;
		break; // stick to defaults
	case MOUNT_TYPE_BIND_FILE:
		mountflags |= MS_RDONLY; // Fallthrough
	case MOUNT_TYPE_BIND_FILE_RW:
		if (container_has_userns(vol->container)) // skip
			goto final;
		mountflags |= MS_BIND; // use bind mount
		IF_TRUE_GOTO(-1 == c_vol_mount_file_bind(img, dir, mountflags), error);
		goto final;
	case MOUNT_TYPE_COPY: // deprecated
		//WARN("Found deprecated MOUNT_TYPE_COPY");
		shiftids = true;
		break;
	case MOUNT_TYPE_FLASH:
		DEBUG("Skipping mounting of FLASH type image %s", mount_entry_get_img(mntent));
		goto final;
	default:
		ERROR("Unsupported operating system mount type %d for %s",
		      mount_entry_get_type(mntent), mount_entry_get_img(mntent));
		goto error;
	}

	// try to create mount point before mount, usually not necessary...
	if (dir_mkdir_p(dir, 0777) < 0)
		DEBUG_ERRNO("Could not mkdir %s", dir);

	if (strcmp(mount_entry_get_fs(mntent), "tmpfs") == 0) {
		const char *mount_data = mount_entry_get_mount_data(mntent);
		char *tmpfs_opts = c_vol_get_tmpfs_opts_new(mount_data, uid, uid);
		if (mount(mount_entry_get_fs(mntent), dir, mount_entry_get_fs(mntent), mountflags,
			  tmpfs_opts) >= 0) {
			DEBUG("Sucessfully mounted %s to %s", mount_entry_get_fs(mntent), dir);
			mem_free0(tmpfs_opts);
			if (is_root && setup_mode && c_vol_setup_busybox_copy(dir) < 0)
				WARN("Cannot copy busybox for setup mode!");
			goto final;
		} else {
			ERROR_ERRNO("Cannot mount %s to %s", mount_entry_get_fs(mntent), dir);
			mem_free0(tmpfs_opts);
			goto error;
		}
	}

	if (c_vol_check_image(vol, img) < 0) {
		new_image = true;
		if (c_vol_create_image(vol, img, mntent) < 0) {
			goto error;
		}
	}

	dev = c_vol_create_loopdev_new(&fd, img);
	IF_NULL_GOTO(dev, error);

	if (encrypted) {
		char *label, *crypt;

		label = mem_printf("%s-%s", uuid_string(container_get_uuid(vol->container)),
				   mount_entry_get_img(mntent));

		if (!container_get_key(vol->container)) {
			audit_log_event(container_get_uuid(vol->container), FSA, CMLD,
					CONTAINER_MGMT, "setup-crypted-volume-no-key",
					uuid_string(container_get_uuid(vol->container)), 2, "label",
					label);
			ERROR("Trying to mount encrypted volume without key...");
			mem_free0(label);
			goto error;
		}

		crypt = cryptfs_get_device_path_new(label);
		if (file_is_blk(crypt)) {
			INFO("Using existing mapper device: %s", crypt);
		} else {
			DEBUG("Setting up cryptfs volume %s for %s", label, dev);

			img_meta = c_vol_meta_image_path_new(vol, mntent);
			dev_meta = c_vol_create_loopdev_new(&fd_meta, img_meta);

			IF_NULL_GOTO(dev_meta, error);

			mem_free0(crypt);
			crypt = cryptfs_setup_volume_new(
				label, dev, container_get_key(vol->container), dev_meta);

			// release loopdev fd (crypt device should keep it open now)
			close(fd_meta);
			mem_free0(img_meta);

			if (!crypt) {
				audit_log_event(container_get_uuid(vol->container), FSA, CMLD,
						CONTAINER_MGMT, "setup-crypted-volume",
						uuid_string(container_get_uuid(vol->container)), 2,
						"label", label);
				ERROR("Setting up cryptfs volume %s for %s failed", label, dev);
				mem_free0(label);
				goto error;
			}
			audit_log_event(container_get_uuid(vol->container), SSA, CMLD,
					CONTAINER_MGMT, "setup-crypted-volume",
					uuid_string(container_get_uuid(vol->container)), 2, "label",
					label);
		}

		mem_free0(label);
		mem_free0(dev);
		dev = crypt;

		// TODO: timeout?
		while (access(dev, F_OK) < 0) {
			NANOSLEEP(0, 10000000)
			DEBUG("Waiting for %s", dev);
		}
	}

	if (overlay) {
		const char *upper_fstype = NULL;
		const char *lower_fstype = NULL;
		char *upper_dev = NULL;
		char *lower_dev = NULL;
		const char *mount_data = mount_entry_get_mount_data(mntent);

		switch (mount_entry_get_type(mntent)) {
		case MOUNT_TYPE_OVERLAY_RW: {
			upper_dev = dev;
			upper_fstype = mount_entry_get_fs(mntent);
			if (new_image) {
				if (c_vol_format_image(dev, upper_fstype) < 0) {
					ERROR("Could not format image %s using %s", img, dev);
					goto error;
				}
				DEBUG("Successfully formatted new image %s using %s", img, dev);
			}
			if (!strcmp("btrfs", upper_fstype) &&
			    !strncmp("subvol", mount_entry_get_mount_data(mntent), 6)) {
				c_vol_btrfs_create_subvol(dev, mount_entry_get_mount_data(mntent));
			}
		} break;

		case MOUNT_TYPE_OVERLAY_RO: {
			upper_dev = dev;
			upper_fstype = mount_entry_get_fs(mntent);
			mountflags |= MS_RDONLY;
		} break;

		case MOUNT_TYPE_SHARED_RW: {
			upper_fstype = "tmpfs";
			lower_fstype = mount_entry_get_fs(mntent);
			lower_dev = dev;
		} break;

		default:
			ERROR_ERRNO("Mounttype does not support overlay mounting!");
			goto error;
		}

		char *overlayfs_mount_dir =
			mem_printf("/tmp/overlayfs/%s/%d",
				   uuid_string(container_get_uuid(vol->container)),
				   ++vol->overlay_count);
		if (c_vol_mount_overlay(dir, upper_fstype, lower_fstype, mountflags, mount_data,
					upper_dev, lower_dev, overlayfs_mount_dir) < 0) {
			ERROR_ERRNO("Could not mount %s to %s", img, dir);
			mem_free0(overlayfs_mount_dir);
			goto error;
		}
		DEBUG("Successfully mounted %s using overlay to %s", img, dir);
		mem_free0(overlayfs_mount_dir);
		goto final;
	}

	DEBUG("Mounting image %s %s using %s to %s", img, mountflags & MS_RDONLY ? "ro" : "rw", dev,
	      dir);

	if (mount(dev, dir, mount_entry_get_fs(mntent), mountflags,
		  mount_entry_get_mount_data(mntent)) >= 0) {
		DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);
		goto final;
	}

	// retry with default options
	if (mount(dev, dir, mount_entry_get_fs(mntent), mountflags, NULL) >= 0) {
		DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);
		goto final;
	}

	if (errno != EINVAL) {
		ERROR_ERRNO("Could not mount image %s using %s to %s", img, dev, dir);
		goto error;
	}

	INFO("Could not mount image %s using %s to %s because an invalid "
	     "superblock was detected.",
	     img, dev, dir);

	if (mount_entry_get_type(mntent) != MOUNT_TYPE_EMPTY)
		goto error;

	/* TODO better password handling before in order to remove this condition. */
	if (encrypted && !new_image) {
		DEBUG("Possibly the wrong password was specified. Abort container start.");
		goto error;
	}

	INFO("Formating image %s using %s as %s", img, dev, mount_entry_get_fs(mntent));

	if (c_vol_format_image(dev, mount_entry_get_fs(mntent)) < 0) {
		ERROR("Could not format image %s using %s", img, dev);
		goto error;
	}

	DEBUG("Mounting image %s using %s to %s (2nd try)", img, dev, dir);

	// 2nd try to mount image...
	if (mount(dev, dir, mount_entry_get_fs(mntent), mountflags,
		  mount_entry_get_mount_data(mntent)) < 0) {
		ERROR("Could not mount image %s using %s to %s", img, dev, dir);
		goto error;
	}

	DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);

final:
	if (mount(NULL, dir, NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
		ERROR_ERRNO("Could not mount '%s' MS_PRIVATE", dir);
		goto error;
	}

	if (shiftids) {
		if (container_shift_ids(vol->container, dir, is_root) < 0) {
			ERROR_ERRNO("Shifting user and gids failed!");
			goto error;
		}
	}

	if (dev)
		loopdev_free(dev);
	if (dev_meta)
		loopdev_free(dev_meta);
	if (img)
		mem_free0(img);
	if (img_meta)
		mem_free0(img_meta);
	if (dir)
		mem_free0(dir);
	if (fd)
		close(fd);
	if (fd_meta)
		close(fd_meta);
	return 0;

error:
	if (dev)
		loopdev_free(dev);
	if (dev_meta)
		loopdev_free(dev_meta);
	if (img)
		mem_free0(img);
	if (img_meta)
		mem_free0(img_meta);
	if (dir)
		mem_free0(dir);
	if (fd)
		close(fd);
	if (fd_meta)
		close(fd_meta);
	return -1;
}

static int
c_vol_cleanup_dm(c_vol_t *vol)
{
	size_t i, n;

	n = mount_get_count(container_get_mount(vol->container));
	for (i = 0; i < n; i++) {
		const mount_entry_t *mntent;
		char *label;

		mntent = mount_get_entry(container_get_mount(vol->container), i);

		label = mem_printf("%s-%s", uuid_string(container_get_uuid(vol->container)),
				   mount_entry_get_img(mntent));
		DEBUG("Trying to delete dm %s", label);
		// we just try to delete all mounts and ignore their type...
		if (cryptfs_delete_blk_dev(label) < 0)
			DEBUG("Could not delete dm %s", label);
		mem_free0(label);
	}

	return 0;
}

static int
c_vol_umount_dir(const char *mount_dir)
{
	IF_NULL_RETVAL(mount_dir, -1);

	while (file_is_mountpoint(mount_dir)) {
		if (umount(mount_dir) < 0) {
			if (umount2(mount_dir, MNT_DETACH) < 0) {
				ERROR_ERRNO("Could not umount '%s'", mount_dir);
				return -1;
			}
		}
	}
	return 0;
}

static int
c_vol_cleanup_overlays_cb(const char *path, const char *file, UNUSED void *data)
{
	char *overlay = mem_printf("%s/%s", path, file);
	int ret = c_vol_umount_dir(overlay);
	if (rmdir(overlay) < 0)
		TRACE("Unable to remove %s", overlay);

	mem_free0(overlay);
	return ret;
}

/**
 * Umount all image files.
 * This function is called in the rootns, to cleanup stopped container.
 */
static int
c_vol_umount_all(c_vol_t *vol)
{
	int i, n;
	char *c_root = mem_printf("%s%s", vol->root, "/setup");
	bool setup_mode = container_has_setup_mode(vol->container);

	// umount /dev
	char *mount_dir = mem_printf("%s/dev", vol->root);
	if (c_vol_umount_dir(mount_dir) < 0)
		goto error;
	mem_free0(mount_dir);

	if (setup_mode) {
		// umount setup in revers order
		n = mount_get_count(container_get_mount_setup(vol->container));
		TRACE("n setup: %d", n);
		for (i = n - 1; i >= 0; i--) {
			const mount_entry_t *mntent;
			TRACE("i setup: %d", i);
			mntent = mount_get_entry(container_get_mount_setup(vol->container), i);
			mount_dir = mem_printf("%s/%s", c_root, mount_entry_get_dir(mntent));
			if (c_vol_umount_dir(mount_dir) < 0)
				goto error;
			mem_free0(mount_dir);
		}
	}

	// umount root in revers order
	n = mount_get_count(container_get_mount(vol->container));
	TRACE("n rootfs: %d", n);
	for (i = n - 1; i >= 0; i--) {
		const mount_entry_t *mntent;
		TRACE("i rootfs: %d", i);
		mntent = mount_get_entry(container_get_mount(vol->container), i);
		mount_dir = mem_printf("%s/%s", vol->root, mount_entry_get_dir(mntent));
		if (c_vol_umount_dir(mount_dir) < 0)
			goto error;
		mem_free0(mount_dir);
	}
	if (rmdir(vol->root) < 0)
		TRACE("Unable to remove %s", vol->root);

	// cleanup left-over overlay mounts in main cmld process
	mount_dir =
		mem_printf("/tmp/overlayfs/%s", uuid_string(container_get_uuid(vol->container)));
	if (dir_foreach(mount_dir, &c_vol_cleanup_overlays_cb, NULL) < 0)
		WARN("Could not release overlays in '%s'", mount_dir);
	if (rmdir(mount_dir) < 0)
		TRACE("Unable to remove %s", mount_dir);
	mem_free0(mount_dir);

	mem_free0(c_root);
	return 0;
error:
	mem_free0(mount_dir);
	mem_free0(c_root);
	return -1;
}

/**
 * Mount all image files.
 * This function is called in the rootns.
 */
static int
c_vol_mount_images(c_vol_t *vol)
{
	size_t i, n;

	ASSERT(vol);

	bool setup_mode = container_has_setup_mode(vol->container);

	// in setup mode mount container images under {root}/setup subfolder
	char *c_root = mem_printf("%s%s", vol->root, (setup_mode) ? "/setup" : "");

	if (setup_mode) {
		n = mount_get_count(container_get_mount_setup(vol->container));
		for (i = 0; i < n; i++) {
			const mount_entry_t *mntent;

			mntent = mount_get_entry(container_get_mount_setup(vol->container), i);

			if (c_vol_mount_image(vol, vol->root, mntent) < 0) {
				goto err;
			}
		}

		// create mount point for setup
		if (dir_mkdir_p(c_root, 0755) < 0)
			DEBUG_ERRNO("Could not mkdir %s", c_root);
	}

	n = mount_get_count(container_get_mount(vol->container));
	for (i = 0; i < n; i++) {
		const mount_entry_t *mntent;

		mntent = mount_get_entry(container_get_mount(vol->container), i);

		if (c_vol_mount_image(vol, c_root, mntent) < 0) {
			goto err;
		}
	}
	mem_free0(c_root);
	return 0;
err:
	c_vol_umount_all(vol);
	c_vol_cleanup_dm(vol);
	mem_free0(c_root);
	return -1;
}

static bool
c_vol_populate_dev_filter_cb(const char *dev_node, void *data)
{
	c_vol_t *vol = data;
	ASSERT(vol);

	// filter out mount points, to avoid copying private stuff, e.g, /dev/pts
	if (file_is_mountpoint(dev_node)) {
		TRACE("filter mountpoint '%s'", dev_node);
		return false;
	}

	struct stat s;
	IF_TRUE_RETVAL(stat(dev_node, &s), true);

	switch (s.st_mode & S_IFMT) {
	case S_IFBLK:
	case S_IFCHR:
		if (!container_is_device_allowed(vol->container, major(s.st_rdev),
						 minor(s.st_rdev))) {
			TRACE("filter device %s (%d:%d)", dev_node, major(s.st_rdev),
			      minor(s.st_rdev));
			return false;
		}
		// Fallthrough
	default:
		return true;
	}
	return true;
}

static int
c_vol_mount_dev(c_vol_t *vol)
{
	ASSERT(vol);

	int ret = -1;
	char *dev_mnt = mem_printf("%s/%s", vol->root, "dev");
	int uid = container_get_uid(vol->container);
	char *tmpfs_opts = c_vol_get_tmpfs_opts_new(NULL, uid, uid);
	if ((ret = mkdir(dev_mnt, 0755)) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir /dev");
		goto error;
	}
	if ((ret = mount("tmpfs", dev_mnt, "tmpfs", MS_RELATIME | MS_NOSUID, tmpfs_opts)) < 0) {
		ERROR_ERRNO("Could not mount /dev");
		goto error;
	}

	if ((ret = mount(NULL, dev_mnt, NULL, MS_SHARED, NULL)) < 0) {
		ERROR_ERRNO("Could not apply MS_SHARED to %s", dev_mnt);
	} else {
		DEBUG("Applied MS_SHARED to %s", dev_mnt);
	}

	ret = 0;
error:
	mem_free0(dev_mnt);
	mem_free0(tmpfs_opts);
	return ret;
}

/**
 * This Function verifes integrity of base images as part of
 * TSF.CML.SecureCompartmentInit.
 */
static bool
c_vol_verify_mount_entries(const c_vol_t *vol)
{
	ASSERT(vol);

	int n = mount_get_count(container_get_mount(vol->container));
	for (int i = 0; i < n; i++) {
		const mount_entry_t *mntent;
		mntent = mount_get_entry(container_get_mount(vol->container), i);
		if (mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED ||
		    mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED_RW ||
		    mount_entry_get_type(mntent) == MOUNT_TYPE_OVERLAY_RO) {
			if (guestos_check_mount_image_block(container_get_os(vol->container),
							    mntent, true) != CHECK_IMAGE_GOOD) {
				ERROR("Cannot verify image %s: image file is corrupted",
				      mount_entry_get_img(mntent));
				return false;
			}
		}
	}
	return true;
}

/******************************************************************************/

c_vol_t *
c_vol_new(const container_t *container)
{
	ASSERT(container);

	c_vol_t *vol = mem_new0(c_vol_t, 1);
	vol->container = container;
	vol->root = mem_printf("/tmp/%s", uuid_string(container_get_uuid(container)));
	vol->overlay_count = 0;

	return vol;
}

void
c_vol_free(c_vol_t *vol)
{
	ASSERT(vol);

	mem_free0(vol->root);
	mem_free0(vol);
}

static int
c_vol_do_shared_bind_mounts(const c_vol_t *vol)
{
	ASSERT(vol);
	char *bind_img_path = NULL;
	char *bind_dev = NULL;
	int loop_fd = 0;
	bool contains_bind = false;

	int n = mount_get_count(container_get_mount(vol->container));
	for (int i = 0; i < n; i++) {
		const mount_entry_t *mntent;
		mntent = mount_get_entry(container_get_mount(vol->container), i);
		if (mount_entry_get_type(mntent) == MOUNT_TYPE_BIND_FILE_RW ||
		    mount_entry_get_type(mntent) == MOUNT_TYPE_BIND_FILE) {
			contains_bind = true;
		}
	}
	// if no bind mount nothing to do
	IF_FALSE_RETVAL(contains_bind, 0);

	if (!file_is_dir(SHARED_FILES_PATH)) {
		if (dir_mkdir_p(SHARED_FILES_PATH, 0755) < 0) {
			DEBUG_ERRNO("Could not mkdir %s", SHARED_FILES_PATH);
			return -1;
		}
	}
	// if already mounted nothing to be done
	IF_TRUE_RETVAL(file_is_mountpoint(SHARED_FILES_PATH), 0);

	// setup persitent image as date store for shared objects
	bind_img_path = mem_printf("%s/_store.img", SHARED_FILES_PATH);
	if (!file_exists(bind_img_path)) {
		if (c_vol_create_image_empty(bind_img_path, NULL, SHARED_FILES_STORE_SIZE) < 0) {
			goto err;
		}
		if (c_vol_format_image(bind_img_path, "ext4") < 0) {
			goto err;
		}
		INFO("Succesfully created image for %s", SHARED_FILES_PATH);
	}
	bind_dev = c_vol_create_loopdev_new(&loop_fd, bind_img_path);
	IF_NULL_GOTO(bind_dev, err);
	if (mount(bind_dev, SHARED_FILES_PATH, "ext4", MS_NOATIME | MS_NODEV | MS_NOEXEC, NULL) <
	    0) {
		ERROR_ERRNO("Failed to mount %s to %s", bind_img_path, SHARED_FILES_PATH);
		goto err;
	}

	close(loop_fd);
	mem_free0(bind_img_path);
	mem_free0(bind_dev);
	return 0;
err:
	if (loop_fd)
		close(loop_fd);
	if (bind_img_path)
		mem_free0(bind_img_path);
	if (bind_dev)
		mem_free0(bind_dev);
	return -1;
}

char *
c_vol_get_rootdir(c_vol_t *vol)
{
	ASSERT(vol);
	return vol->root;
}

static int
c_vol_bind_token(c_vol_t *vol)
{
	if (CONTAINER_TOKEN_TYPE_USB != container_get_token_type(vol->container)) {
		DEBUG("Token type is not USB, not binding relay socket");
		return 0;
	}

	int ret = -1;
	uid_t uid = container_get_uid(vol->container);

	char *src_path = mem_printf("%s/%s.sock", SCD_TOKENCONTROL_SOCKET,
				    uuid_string(container_get_uuid(vol->container)));
	char *dest_dir = mem_printf("%s/dev/tokens", vol->root);
	char *dest_path = mem_printf("%s/token.sock", dest_dir);

	DEBUG("Binding token socket to %s", dest_path);

	if (!file_exists(dest_dir)) {
		if (dir_mkdir_p(dest_dir, 0755)) {
			ERROR_ERRNO("Failed to create containing directory for %s", dest_path);
			goto err;
		}

		if (chown(dest_dir, uid, uid)) {
			ERROR("Failed to chown token directory at %s to %d", dest_path, uid);
			goto err;
		} else {
			DEBUG("Successfully chowned token directory at %s to %d", dest_path, uid);
		}
	} else if (!file_is_dir(dest_dir)) {
		ERROR("Token path %s exists and is no directory", dest_dir);
		goto err;
	}

	if (file_touch(dest_path)) {
		ERROR_ERRNO("Failed to prepare target file for bind mount at %s", dest_path);
		goto err;
	}

	DEBUG("Binding token socket from %s to %s", src_path, dest_path);
	if (mount(src_path, dest_path, NULL, MS_BIND, NULL)) {
		ERROR_ERRNO("Failed to bind socket from %s to %s", src_path, dest_path);
		goto err;
	} else {
		DEBUG("Successfully bound token socket to %s", dest_path);
	}

	if (chown(dest_path, uid, uid)) {
		ERROR("Failed to chown token socket at %s to %d", dest_path, uid);
		goto err;
	} else {
		DEBUG("Successfully chowned token socket at %s to %d", dest_path, uid);
	}

	ret = 0;

err:
	mem_free0(src_path);
	mem_free0(dest_dir);
	mem_free0(dest_path);

	return ret;
}

int
c_vol_start_child_early(c_vol_t *vol)
{
	ASSERT(vol);

	INFO("Mounting rootfs to %s", vol->root);

	if (mkdir(container_get_images_dir(vol->container), 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Cound not mkdir container directory %s",
			    container_get_images_dir(vol->container));
		goto error;
	}

	if (mkdir("/tmp", 0700) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir /tmp dir for container start");
		goto error;
	}

	if (mkdir(vol->root, 0700) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir root dir %s for container start", vol->root);
		goto error;
	}

	DEBUG("Mounting images");
	if (c_vol_mount_images(vol) < 0) {
		ERROR("Could not mount images for container start");
		goto error;
	}

	//FIXME should be before mounting images, because it sets up storage for bound files!
	if (c_vol_do_shared_bind_mounts(vol) < 0) {
		ERROR("Could not do shared bind mounts for container start");
		goto error;
	}

	DEBUG("Mounting /dev");
	IF_TRUE_GOTO_ERROR(c_vol_mount_dev(vol) < 0, error);

	/*
	 * copy cml-service-container binary to target as defined in CSERVICE_TARGET
	 * Remeber, This will only succeed if targetfs is writable
	 */
	char *cservice_bin = mem_printf("%s/%s", vol->root, CSERVICE_TARGET);
	char *cservice_dir = mem_strdup(cservice_bin);
	char *cservice_dir_p = dirname(cservice_dir);
	if (dir_mkdir_p(cservice_dir_p, 0755) < 0) {
		WARN_ERRNO("Could not mkdir '%s' dir", cservice_dir_p);
	} else if (file_exists("/sbin/cml-service-container")) {
		file_copy("/sbin/cml-service-container", cservice_bin, -1, 512, 0);
		INFO("Copied %s to container", cservice_bin);
	} else if (file_exists("/usr/sbin/cml-service-container")) {
		file_copy("/usr/sbin/cml-service-container", cservice_bin, -1, 512, 0);
		INFO("Copied %s to container", cservice_bin);
	} else {
		WARN_ERRNO("Could not copy %s to container", cservice_bin);
	}

	if (chmod(cservice_bin, 0755))
		WARN_ERRNO("Could not set %s executable", cservice_bin);

	mem_free0(cservice_bin);
	mem_free0(cservice_dir);

	return 0;
error:
	ERROR("Failed to execute post clone hook for c_vol");
	return -1;
}

struct tty_cb_data {
	bool found;
	char *name;
};

static int
c_vol_dev_get_tty_cb(UNUSED const char *path, const char *file, void *data)
{
	struct tty_cb_data *tty_data = data;

	if (!tty_data->found && strlen(file) >= 4 && strstr(file, "tty")) {
		tty_data->name = mem_strdup(file);
		INFO("Found tty: %s", tty_data->name);
		tty_data->found = true;
	}
	return 0;
}

int
c_vol_start_pre_exec(c_vol_t *vol)
{
	INFO("Populating container's /dev.");
	char *dev_mnt = mem_printf("%s/%s", vol->root, "dev");
	if (dir_copy_folder("/dev", dev_mnt, &c_vol_populate_dev_filter_cb, vol) < 0) {
		ERROR_ERRNO("Could not populate /dev!");
		mem_free0(dev_mnt);
		return -1;
	}

	/* link first /dev/tty* to /dev/console for systemd containers */
	struct tty_cb_data tty_data = { .found = false, .name = NULL };
	dir_foreach(dev_mnt, c_vol_dev_get_tty_cb, &tty_data);
	if (tty_data.name != NULL) {
		char *lnk_path = mem_printf("%s/console", dev_mnt);
		if (symlink(tty_data.name, lnk_path))
			WARN_ERRNO("Could not link %s to /dev/console in container", tty_data.name);
		mem_free0(lnk_path);
		mem_free0(tty_data.name);
	}

	if (container_shift_ids(vol->container, dev_mnt, false) < 0)
		WARN("Failed to setup ids for %s in user namespace!", dev_mnt);

	if (c_vol_bind_token(vol) < 0) {
		ERROR_ERRNO("Failed to bind token to container");
		mem_free0(dev_mnt);
		return -1;
	}

	mem_free0(dev_mnt);
	return 0;
}
static int
c_vol_mount_proc_and_sys(const c_vol_t *vol, const char *dir)
{
	char *mnt_proc = mem_printf("%s/proc", dir);
	char *mnt_sys = mem_printf("%s/sys", dir);

	DEBUG("Mounting proc on %s", mnt_proc);
	if (mkdir(mnt_proc, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir %s", mnt_proc);
		goto error;
	}
	if (mount("proc", mnt_proc, "proc", 0, NULL) < 0) {
		ERROR_ERRNO("Could not mount %s", mnt_proc);
		goto error;
	}

	if (lxcfs_is_supported() && lxcfs_mount_proc_overlay(mnt_proc)) {
		ERROR_ERRNO("Could not apply lxcfs overlay on mount %s", mnt_proc);
		goto error;
	} else {
		INFO("lxfs not supported - not mounting overlay");
	}

	DEBUG("Mounting sys on %s", mnt_sys);
	unsigned long sysopts = MS_RELATIME | MS_NOSUID;
	if (container_has_userns(vol->container) && !container_has_netns(vol->container)) {
		sysopts |= MS_RDONLY;
	}
	if (mkdir(mnt_sys, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir %s", mnt_sys);
		goto error;
	}
	if (mount("sysfs", mnt_sys, "sysfs", sysopts, NULL) < 0) {
		ERROR_ERRNO("Could not mount %s", mnt_sys);
		goto error;
	}

	mem_free0(mnt_proc);
	mem_free0(mnt_sys);
	return 0;
error:
	mem_free0(mnt_proc);
	mem_free0(mnt_sys);
	return -1;
}

static int
c_vol_move_root(const c_vol_t *vol)
{
	if (chdir(vol->root) < 0) {
		ERROR_ERRNO("Could not chdir to root dir %s for container start", vol->root);
		goto error;
	}

	// mount namespace handles chroot jail breaks
	if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
		ERROR_ERRNO("Could not move mount for container start");
		goto error;
	}

	if (chroot(".") < 0) {
		ERROR_ERRNO("Could not chroot to . for container start");
		goto error;
	}

	if (chdir("/") < 0) {
		ERROR_ERRNO("Could not chdir to / for container start");
		goto error;
	}

	INFO("Sucessfully switched (move mount) to new root %s", vol->root);
	return 0;
error:
	return -1;
}

static int
pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}

static int
c_vol_pivot_root(const c_vol_t *vol)
{
	int old_root = -1, new_root = -1;

	if ((old_root = open("/", O_DIRECTORY | O_PATH)) < 0) {
		ERROR_ERRNO("Could not open '/' directory of the old filesystem");
		goto error;
	}

	if ((new_root = open(vol->root, O_DIRECTORY | O_PATH)) < 0) {
		ERROR_ERRNO("Could not open the root dir '%s' for container start", vol->root);
		goto error;
	}

	if (fchdir(new_root)) {
		ERROR_ERRNO("Could not fchdir to new root dir %s for container start", vol->root);
		goto error;
	}

	if (pivot_root(".", ".") == -1) {
		ERROR_ERRNO("Could not pivot root for container start");
		goto error;
	}

	if (fchdir(old_root) < 0) {
		ERROR_ERRNO("Could not fchdir to the root directory of the old filesystem");
		goto error;
	}

	if (umount2(".", MNT_DETACH) < 0) {
		ERROR_ERRNO("Could not unmount the old root filesystem");
		goto error;
	}

	if (fchdir(new_root) < 0) {
		ERROR_ERRNO("Could not switch back to the root directory of the new filesystem");
		goto error;
	}

	INFO("Sucessfully switched (pivot_root) to new root %s", vol->root);

	close(old_root);
	close(new_root);
	return 0;
error:
	if (old_root >= 0)
		close(old_root);
	if (new_root >= 0)
		close(new_root);
	return -1;
}

int
c_vol_start_child(c_vol_t *vol)
{
	ASSERT(vol);

	// check image integrity (this is blocking that is why we do this
	// in the child and not before mounting in the host process
	IF_FALSE_GOTO(c_vol_verify_mount_entries(vol), error);

	// remount proc to reflect namespace change
	if (!container_has_userns(vol->container)) {
		if (umount("/proc") < 0 && errno != ENOENT) {
			if (umount2("/proc", MNT_DETACH) < 0) {
				ERROR_ERRNO("Could not umount /proc");
				goto error;
			}
		}
	}
	if (mount("proc", "/proc", "proc", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not remount /proc");
		goto error;
	}

	if (container_get_type(vol->container) == CONTAINER_TYPE_KVM)
		return 0;

	INFO("Switching to new rootfs in '%s'", vol->root);

	if (container_shift_mounts(vol->container) < 0) {
		ERROR_ERRNO("Mounting of shifting user and gids failed!");
		goto error;
	}

	if (c_vol_mount_proc_and_sys(vol, vol->root) == -1) {
		ERROR_ERRNO("Could not mount proc and sys");
		goto error;
	}

	if (cmld_is_hostedmode_active())
		IF_TRUE_GOTO(c_vol_pivot_root(vol) < 0, error);
	else
		IF_TRUE_GOTO(c_vol_move_root(vol) < 0, error);

	if (!container_has_userns(vol->container) && file_exists("/proc/sysrq-trigger")) {
		if (mount("/proc/sysrq-trigger", "/proc/sysrq-trigger", NULL, MS_BIND, NULL) < 0) {
			ERROR_ERRNO("Could not bind mount /proc/sysrq-trigger protection");
			goto error;
		}
		if (mount(NULL, "/proc/sysrq-trigger", NULL, MS_BIND | MS_RDONLY | MS_REMOUNT,
			  NULL) < 0) {
			ERROR_ERRNO("Could not ro remount /proc/sysrq-trigger protection");
			goto error;
		}
	}

	DEBUG("Mounting /dev/pts");
	if (mkdir("/dev/pts", 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir /dev/pts");
		goto error;
	}
	if (mount("devpts", "/dev/pts", "devpts", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount /dev/pts");
		goto error;
	}

	DEBUG("Mounting /run");
	if (mkdir("/run", 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir /run");
		goto error;
	}
	if (mount("tmpfs", "/run", "tmpfs", MS_RELATIME | MS_NOSUID | MS_NODEV, NULL) < 0) {
		ERROR_ERRNO("Could not mount /run");
		goto error;
	}

	DEBUG("Mounting " CMLD_SOCKET_DIR);
	if (mkdir(CMLD_SOCKET_DIR, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir " CMLD_SOCKET_DIR);
		goto error;
	}
	if (mount("tmpfs", CMLD_SOCKET_DIR, "tmpfs", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount " CMLD_SOCKET_DIR);
		goto error;
	}

	if (container_has_setup_mode(vol->container) && c_vol_setup_busybox_install() < 0)
		WARN("Cannot install busybox symlinks for setup mode!");

	char *mount_output = file_read_new("/proc/self/mounts", 2048);
	INFO("Mounted filesystems:");
	INFO("%s", mount_output);
	mem_free0(mount_output);

	return 0;

error:
	return -1;
}

bool
c_vol_is_encrypted(c_vol_t *vol)
{
	size_t i, n;

	ASSERT(vol);
	ASSERT(vol->container);

	n = mount_get_count(container_get_mount(vol->container));
	for (i = 0; i < n; i++) {
		const mount_entry_t *mntent;
		mntent = mount_get_entry(container_get_mount(vol->container), i);
		if (mount_entry_is_encrypted(mntent))
			return true;
	}
	return false;
}

void
c_vol_cleanup(c_vol_t *vol, bool is_rebooting)
{
	ASSERT(vol);

	if (c_vol_umount_all(vol))
		WARN("Could not umount all images properly");

	// keep dm crypt/integrity device up for reboot
	if (!is_rebooting && c_vol_cleanup_dm(vol))
		WARN("Could not remove mounts properly");
}
