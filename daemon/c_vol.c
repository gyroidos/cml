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

#include "cmld.h"
#include "hardware.h"
#include "guestos.h"
#include "smartcard.h"

#include <unistd.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>

#include <selinux/selinux.h>

#ifdef ANDORID
#define MAKE_EXT4FS "make_ext4fs"
#else
#define MAKE_EXT4FS "mkfs.ext4"
#endif
#define BTRFSTUNE "btrfstune"
#define MAKE_BTRFS "mkfs.btrfs"
#define MDEV "mdev"

#if 0
#define ICC_SHARED_MOUNT "data/trustme-com"
#define TPM2D_SHARED_MOUNT ICC_SHARED_MOUNT "/tpm2d"
#define ICC_SHARED_DATA_TYPE "u:object_r:trustme-com:s0"
#endif

#define CSERVICE_TARGET "/sbin/cservice"
#define SHARED_FILES_PATH "/data/cml/files_shared"
#define SHARED_FILES_STORE_SIZE 100

#define is_selinux_disabled() !file_exists("/sys/fs/selinux")
#define is_selinux_enabled() file_exists("/sys/fs/selinux")

struct c_vol {
	const container_t *container;
	char *root;
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
	mem_free(dev);
	return NULL;
}

static int
c_vol_create_image_empty(const char *img, uint64_t size)
{
	off64_t storage_size;
	int fd;

	ASSERT(img);

	// minimal storage size is 10 MB
	storage_size = MAX(size, 10);
	storage_size *= 1024 * 1024;

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

	close(fd);
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

	mem_free(src);
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

	mem_free(dev);
	return ret;
}

static int
c_vol_create_image(c_vol_t *vol, const char *img, const mount_entry_t *mntent)
{
	INFO("Creating image %s", img);

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_SHARED:
	case MOUNT_TYPE_SHARED_RW:
	case MOUNT_TYPE_OVERLAY_RW:
		return c_vol_create_image_empty(img, mount_entry_get_size(mntent));
	case MOUNT_TYPE_FLASH:
		return -1; // we cannot create such image files
	case MOUNT_TYPE_EMPTY:
		return c_vol_create_image_empty(img, mount_entry_get_size(mntent));
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
	char *token = strdup(mount_data);
	char *subvol = strtok(token, "=");
	subvol = strtok(NULL, "=");
	if (NULL == subvol) {
		mem_free(token);
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
	unlink(tmp_mount);
	if (subvol_path)
		mem_free(subvol_path);
	mem_free(tmp_mount);
	mem_free(token);
	return ret;
}

static int
c_vol_mount_overlay(const char *target_dir, const char *upper_fstype, const char *lowerfs_type,
		    int mount_flags, char *mount_data, const char *upper_dev, const char *lower_dev)
{
	char *lower_dir, *upper_dir, *work_dir, *overlayfs_mount_dir;

	lower_dir = upper_dir = work_dir = overlayfs_mount_dir = NULL;
	upper_dev = (upper_dev) ? upper_dev : "tmpfs";

	// create mountpoints for lower and upper dev
	if (dir_mkdir_p("/tmp/overlayfs", 0755) < 0) {
		ERROR_ERRNO("Could not mkdir /tmp/overlayfs");
		return -1;
	}
	overlayfs_mount_dir = mem_printf("/tmp/overlayfs/tmp.XXXXXX");
	if (NULL == mkdtemp(overlayfs_mount_dir)) {
		ERROR_ERRNO("Could not mkdir overlayfs dir %s", overlayfs_mount_dir);
		mem_free(overlayfs_mount_dir);
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
		if (symlink(target_dir, lower_dir) < 0) {
			ERROR_ERRNO("link lowerdir failed");
			mem_free(lower_dir);
			lower_dir = mem_strdup(target_dir);
		}
	}
	DEBUG("Mounting overlayfs: work_dir=%s, upper_dir=%s, lower_dir=%s, target dir=%s",
	      work_dir, upper_dir, lower_dir, target_dir);
	// create mount option string (try to mask absolute paths)
	char *cwd = get_current_dir_name();
	char *overlayfs_options;
	if (chdir(overlayfs_mount_dir)) {
		overlayfs_options = mem_printf("lowerdir=%s,upperdir=%s,workdir=%s", lower_dir,
					       upper_dir, work_dir);
	} else {
		overlayfs_options = mem_strdup("lowerdir=lower,upperdir=upper,workdir=work");
		TRACE("old_wdir: %s, mount_cwd: %s, overlay_options: %s ", cwd, overlayfs_mount_dir,
		      overlayfs_options);
	}
	INFO("mount_dir: %s", target_dir);
	// mount overlayfs to dir
	if (mount("overlay", target_dir, "overlay", 0, overlayfs_options) < 0) {
		ERROR_ERRNO("Could not mount overlay");
		mem_free(overlayfs_options);
		if (chdir(cwd))
			WARN("Could not change back to former cwd %s", cwd);
		mem_free(cwd);
		goto error;
	}
	mem_free(overlayfs_options);
	if (chdir(cwd))
		WARN("Could not change back to former cwd %s", cwd);
	mem_free(cwd);
	return 0;
error:
	mem_free(overlayfs_mount_dir);
	if (file_is_link(lower_dir)) {
		if (unlink(lower_dir))
			WARN_ERRNO("could not remove temporary link %s", lower_dir);
	}
	mem_free(lower_dir);
	mem_free(upper_dir);
	mem_free(work_dir);
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

	mem_free(_src);
	mem_free(_dst);
	return 0;
err:
	mem_free(_src);
	mem_free(_dst);
	return -1;
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
	char *img, *dev, *dir;
	int fd = 0;
	bool new_image = false;
	bool encrypted = mount_entry_is_encrypted(mntent);
	bool overlay = false;
	bool shiftids = false;
	bool is_root = strcmp(mount_entry_get_dir(mntent), "/") == 0;
	bool setup_mode = container_get_state(vol->container) == CONTAINER_STATE_SETUP;

	// default mountflags for most image types
	unsigned long mountflags = setup_mode ? MS_NOATIME : MS_NOATIME | MS_NODEV;

	img = dev = dir = NULL;

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
	if (dir_mkdir_p(dir, 0755) < 0)
		DEBUG_ERRNO("Could not mkdir %s", dir);

	if (strcmp(mount_entry_get_fs(mntent), "tmpfs") == 0) {
		if (mount(mount_entry_get_fs(mntent), dir, mount_entry_get_fs(mntent), mountflags,
			  mount_entry_get_mount_data(mntent)) >= 0) {
			DEBUG("Sucessfully mounted %s to %s", mount_entry_get_fs(mntent), dir);
			goto final;
		} else {
			ERROR_ERRNO("Cannot mount %s to %s", mount_entry_get_fs(mntent), dir);
			goto error;
		}
	}

	if (c_vol_check_image(vol, img) < 0) {
		new_image = true;
		if (c_vol_create_image(vol, img, mntent) < 0) {
			goto error;
		}
	}
	if (mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED ||
	    mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED_RW ||
	    mount_entry_get_type(mntent) == MOUNT_TYPE_OVERLAY_RO) {
		if (guestos_check_mount_image_block(container_get_os(vol->container), mntent,
						    true) != CHECK_IMAGE_GOOD) {
			ERROR("Cannot mount image %s: image file is corrupted", img);
			goto error;
		}
	}

	dev = c_vol_create_loopdev_new(&fd, img);
	IF_NULL_GOTO(dev, error);

	if (encrypted) {
		char *label, *crypt;

		if (!container_get_key(vol->container)) {
			ERROR("Trying to mount encrypted volume without key...");
			goto error;
		}

		label = mem_printf("%s-%s", uuid_string(container_get_uuid(vol->container)),
				   mount_entry_get_img(mntent));

		crypt = cryptfs_get_device_path_new(label);
		if (file_is_blk(crypt)) {
			INFO("Using existing mapper device: %s", crypt);
		} else {
			DEBUG("Setting up cryptfs volume %s for %s", label, dev);

			mem_free(crypt);
			crypt = cryptfs_setup_volume_new(label, dev,
							 container_get_key(vol->container));

			if (!crypt) {
				ERROR("Setting up cryptfs volume %s for %s failed", label, dev);
				mem_free(label);
				goto error;
			}
		}

		mem_free(label);
		mem_free(dev);
		dev = crypt;

		// TODO: timeout?
		while (access(dev, F_OK) < 0) {
			usleep(1000 * 10);
			DEBUG("Waiting for %s", dev);
		}
	}

	if (overlay) {
		const char *upper_fstype = NULL;
		const char *lower_fstype = NULL;
		char *upper_dev = NULL;
		char *lower_dev = NULL;
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
			// check if its a feature mount and if the container has the feature enabled
			const char *img_name = mount_entry_get_img(mntent);
			size_t feature_len = strlen("feature_");
			if (strncmp(img_name, "feature_", feature_len) == 0) {
				if (!container_is_feature_enabled(vol->container,
								  img_name + feature_len)) {
					DEBUG("Feature %s not enabled, skipping...",
					      img_name + feature_len);
					goto final;
				}
				DEBUG("Going to mount feature %s", img_name + feature_len);
			}
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

		if (c_vol_mount_overlay(dir, upper_fstype, lower_fstype, mountflags,
					mount_entry_get_mount_data(mntent), upper_dev,
					lower_dev) < 0) {
			ERROR_ERRNO("Could not mount %s to %s", img, dir);
			goto error;
		}
		DEBUG("Successfully mounted %s using overlay to %s", img, dir);
		goto final;
	}

	DEBUG("Mounting image %s %s using %s to %s", img, mountflags & MS_RDONLY ? "ro" : "rw", dev,
	      dir);

	if (mount(dev, dir, mount_entry_get_fs(mntent), mountflags,
		  mount_entry_get_mount_data(mntent)) >= 0) {
		DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);
		goto final;
	}

	// retry with default options if selinux is disabled .. (e.g. context= will cause an EINVAL)
	if (is_selinux_disabled() &&
	    mount(dev, dir, mount_entry_get_fs(mntent), mountflags, NULL) >= 0) {
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
	if (shiftids)
		if (container_shift_ids(vol->container, dir, is_root) < 0) {
			ERROR_ERRNO("Shifting user and gids failed!");
			goto error;
		}

	if (dev)
		loopdev_free(dev);
	if (img)
		mem_free(img);
	if (dir)
		mem_free(dir);
	if (fd)
		close(fd);
	return 0;

error:
	if (dev)
		loopdev_free(dev);
	if (img)
		mem_free(img);
	if (dir)
		mem_free(dir);
	if (fd)
		close(fd);
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
		mem_free(label);
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

/**
 * Umount all image files.
 * This function is called in the rootns, to cleanup stopped container.
 */
static int
c_vol_umount_all(c_vol_t *vol)
{
	int i, n;
	char *c_root = mem_printf("%s%s", vol->root, "/setup");
	bool setup_mode = file_is_mountpoint(c_root);

	// umount /dev
	char *mount_dir = mem_printf("%s/dev", vol->root);
	if (c_vol_umount_dir(mount_dir) < 0)
		goto error;
	mem_free(mount_dir);

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
			mem_free(mount_dir);
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
		mem_free(mount_dir);
	}
	mem_free(c_root);
	return 0;
error:
	mem_free(mount_dir);
	mem_free(c_root);
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

	bool setup_mode = container_get_state(vol->container) == CONTAINER_STATE_SETUP;

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
	mem_free(c_root);
	return 0;
err:
	c_vol_umount_all(vol);
	c_vol_cleanup_dm(vol);
	mem_free(c_root);
	return -1;
}

static void
c_vol_fixup_logdev()
{
	char *log_buffers[4] = { "events", "main", "radio", "system" };
	for (int i = 0; i < 4; ++i) {
		char *log_buffer_src = mem_printf("/dev/log_%s", log_buffers[i]);
		if (file_exists(log_buffer_src)) {
			char *log_buffer_dest = mem_printf("/dev/log/%s", log_buffers[i]);
			if (mkdir("/dev/log", 0755) < 0 && errno != EEXIST)
				WARN_ERRNO("Could not mkdir /dev/log dir for container logging");
			if (file_move(log_buffer_src, log_buffer_dest, 0))
				WARN_ERRNO("Could not move %s log buffer to %s", log_buffer_src,
					   log_buffer_dest);
			mem_free(log_buffer_dest);
		}
		mem_free(log_buffer_src);
	}
}

static bool
c_vol_populate_dev_filter_cb(const char *dev_node, void *data)
{
	c_vol_t *vol = data;
	ASSERT(vol);

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

/******************************************************************************/

c_vol_t *
c_vol_new(const container_t *container)
{
	ASSERT(container);

	c_vol_t *vol = mem_new0(c_vol_t, 1);
	vol->container = container;
	vol->root = mem_printf("/tmp/%s", uuid_string(container_get_uuid(container)));

	return vol;
}

void
c_vol_free(c_vol_t *vol)
{
	ASSERT(vol);

	mem_free(vol->root);
	mem_free(vol);
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
		if (c_vol_create_image_empty(bind_img_path, SHARED_FILES_STORE_SIZE) < 0) {
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
	mem_free(bind_img_path);
	mem_free(bind_dev);
	return 0;
err:
	if (loop_fd)
		close(loop_fd);
	if (bind_img_path)
		mem_free(bind_img_path);
	if (bind_dev)
		mem_free(bind_dev);
	return -1;
}

char *
c_vol_get_rootdir(c_vol_t *vol)
{
	ASSERT(vol);
	return vol->root;
}

int
c_vol_start_pre_clone(c_vol_t *vol)
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
	const char *mount_data = is_selinux_enabled() ? "rootcontext=u:object_r:device:s0" : NULL;
	char *dev_mnt = mem_printf("%s/%s", vol->root, "dev");
	int uid = container_get_uid(vol->container);
	char *tmpfs_opts = (mount_data) ? mem_printf("uid=%d,gid=%d,%s", uid, uid, mount_data) :
					  mem_printf("uid=%d,gid=%d", uid, uid);
	if (mkdir(dev_mnt, 0755) < 0 && errno != EEXIST)
		WARN_ERRNO("Could not mkdir /dev");
	if (mount("tmpfs", dev_mnt, "tmpfs", MS_RELATIME | MS_NOSUID, tmpfs_opts) < 0)
		WARN_ERRNO("Could not mount /dev");

	mem_free(dev_mnt);
	mem_free(tmpfs_opts);

	/*
	 * copy cml-service-container binary to target as defined in CSERVICE_TARGET
	 * Remeber, This will only succeed if /sbin exists on a writable fs
	 */
	char *cservice_bin = mem_printf("%s/%s", vol->root, CSERVICE_TARGET);
	if (file_copy("/sbin/cml-service-container", cservice_bin, -1, 512, 0))
		WARN_ERRNO("Could not copy %s to container", cservice_bin);
	else if (chmod(cservice_bin, 0755))
		WARN_ERRNO("Could not set %s executable", cservice_bin);
	mem_free(cservice_bin);

#if 0
	/* Bind-mount shared mount for communication */
	// TODO: properly secure this against intercontainer attacks
	char *com_mnt = mem_printf("%s/%s/", root, ICC_SHARED_MOUNT);
	char *com_mnt_data = NULL;
	if(is_selinux_enabled())
		com_mnt_data = mem_printf("defcontext=%s", ICC_SHARED_DATA_TYPE);
	DEBUG("Mounting %s", com_mnt);
	if (mkdir(com_mnt, 0755) < 0 && errno != EEXIST)
		WARN_ERRNO("Could not mkdir %s", com_mnt);
	if (is_selinux_enabled()) {
		if (-1 == setfilecon(com_mnt, ICC_SHARED_DATA_TYPE))
			ERROR_ERRNO("Could not set selabel for dir %s to \"%s\"", com_mnt, ICC_SHARED_DATA_TYPE);
	}
	if (mount("/data/cml/communication", com_mnt, "bind", MS_BIND | MS_NOSUID, com_mnt_data) < 0)
		WARN_ERRNO("Could not mount %s", com_mnt);
	mem_free(com_mnt);

	if (guestos_is_privileged(container_get_guestos(vol->container))) {
		com_mnt = mem_printf("%s/%s/", root, TPM2D_SHARED_MOUNT);
		DEBUG("Mounting %s", com_mnt);
		if (mkdir(com_mnt, 0755) < 0 && errno != EEXIST)
			WARN_ERRNO("Could not mkdir %s", com_mnt);
		if (is_selinux_enabled()) {
			if (-1 == setfilecon(com_mnt, ICC_SHARED_DATA_TYPE))
				ERROR_ERRNO("Could not set selabel for dir %s to \"%s\"", com_mnt, ICC_SHARED_DATA_TYPE);
		}
		if (mount("/data/cml/tpm2d/communication", com_mnt, "bind", MS_BIND | MS_NOSUID, com_mnt_data) < 0)
			WARN_ERRNO("Could not mount %s", com_mnt);
		mem_free(com_mnt);
	}
	mem_free(com_mnt_data);
#endif
	return 0;
error:
	return -1;
}

int
c_vol_start_pre_exec(c_vol_t *vol)
{
	INFO("Populating container's /dev.");
	char *dev_mnt = mem_printf("%s/%s", vol->root, "dev");
	if (dir_copy_folder("/dev", dev_mnt, &c_vol_populate_dev_filter_cb, vol) < 0) {
		ERROR_ERRNO("Could not populate /dev!");
		mem_free(dev_mnt);
		return -1;
	}
	if (container_shift_ids(vol->container, dev_mnt, false) < 0)
		WARN("Failed to setup ids for %s in user namespace!", dev_mnt);

	mem_free(dev_mnt);
	return 0;
}

int
c_vol_start_child(c_vol_t *vol)
{
	ASSERT(vol);

	INFO("Switching to new rootfs in '%s'", vol->root);

	if (!container_has_userns(vol->container)) {
		// remount proc to reflect namespace change
		if (umount("/proc") < 0 && errno != ENOENT) {
			ERROR_ERRNO("Could not umount /proc");
			goto error;
		}
		if (mount("proc", "/proc", "proc", MS_RELATIME | MS_NOSUID, NULL) < 0) {
			ERROR_ERRNO("Could not remount /proc");
			goto error;
		}
	}

	if (container_get_type(vol->container) == CONTAINER_TYPE_KVM)
		return 0;

	if (container_shift_mounts(vol->container) < 0) {
		ERROR_ERRNO("Mounting of shifting user and gids failed!");
		goto error;
	}

	if (chdir(vol->root) < 0) {
		ERROR_ERRNO("Could not chdir to root dir %s for container start", vol->root);
		goto error;
	}

	// mount namespcae handles chroot jail breaks
	if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
		ERROR_ERRNO("Could not move mount for container start");
		goto error;
	}

	if (chroot(".") < 0) {
		ERROR_ERRNO("Could not chroot to . for container start");
		goto error;
	}

	if (chdir("/") < 0)
		ERROR_ERRNO("Could not chdir to / for container start");

	/* TODO: do we want this mounting configurabel somewhere? */

	DEBUG("Mounting /proc");
	if (mkdir("/proc", 0755) < 0 && errno != EEXIST)
		WARN_ERRNO("Could not mkdir /proc");
	if (mount("proc", "/proc", "proc", MS_RELATIME | MS_NOSUID, NULL) < 0)
		WARN_ERRNO("Could not mount /proc");

	DEBUG("Mounting /sys");
	unsigned long sysopts = MS_RELATIME | MS_NOSUID;
	if (container_has_userns(vol->container) && !container_has_netns(vol->container)) {
		sysopts |= MS_RDONLY;
	}
	if (mkdir("/sys", 0755) < 0 && errno != EEXIST)
		WARN_ERRNO("Could not mkdir /sys");
	if (mount("sys", "/sys", "sysfs", sysopts, NULL) < 0)
		WARN_ERRNO("Could not mount /sys");

	/* Normally this would be done by the policy loading code in the android init process 
	 * (system/core/init/init.c and external/libselinux/src/android.c) */
	if (is_selinux_enabled()) {
		DEBUG("Mounting /sys/fs/selinux");
		if (mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", MS_RELATIME | MS_NOSUID,
			  NULL) < 0)
			WARN_ERRNO("Could not mount /sys/fs/selinuxfs");
	}

	DEBUG("Mounting securityfs to /sys/kernel/security");
	if (mount("securityfs", "/sys/kernel/security", "securityfs", MS_RELATIME | MS_NOSUID,
		  NULL) < 0)
		WARN_ERRNO("Could not mount securityfs to /sys/kernel/security");

	c_vol_fixup_logdev();

	if (mkdir("/dev/pts", 0755) < 0 && errno != EEXIST)
		WARN_ERRNO("Could not mkdir /dev/pts");

	DEBUG("Mounting /dev/pts");
	if (mount("devpts", "/dev/pts", "devpts", MS_RELATIME | MS_NOSUID, NULL) < 0)
		WARN_ERRNO("Could not mount /dev/pts");

	DEBUG("Mounting /run");
	if (mkdir("/run", 0755) < 0 && errno != EEXIST)
		WARN_ERRNO("Could not mkdir /run");
	if (mount("tmpfs", "/run", "tmpfs", MS_RELATIME | MS_NOSUID | MS_NODEV, NULL) < 0)
		WARN_ERRNO("Could not mount /run");

	if (mkdir(CMLD_SOCKET_DIR, 0755) < 0 && errno != EEXIST)
		WARN_ERRNO("Could not mkdir " CMLD_SOCKET_DIR);
	if (mount("tmpfs", CMLD_SOCKET_DIR, "tmpfs", MS_RELATIME | MS_NOSUID, NULL) < 0)
		WARN_ERRNO("Could not mount " CMLD_SOCKET_DIR);

	char *mount_output = file_read_new("/proc/self/mounts", 2048);
	INFO("Mounted filesystems:");
	INFO("%s", mount_output);
	mem_free(mount_output);

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
c_vol_cleanup(c_vol_t *vol)
{
	ASSERT(vol);

	if (c_vol_umount_all(vol))
		WARN("Could not umount all images properly");

	// TODO: also tries to delete other directories (e.g. system), but doesn't succeed.
	// There is only an eror message thrown, not an error returned
	if (c_vol_cleanup_dm(vol))
		WARN("Could not remove mounts properly");
}
