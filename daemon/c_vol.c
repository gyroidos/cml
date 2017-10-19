/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
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

#include "c_vol.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/loopdev.h"
#include "common/cryptfs.h"
#include "common/dir.h"

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
#include <fcntl.h>
#include <errno.h>

#define MAKE_EXT4FS "make_ext4fs"

#define ICC_SHARED_MOUNT "data/trustme-com"
#define TPM2D_SHARED_MOUNT ICC_SHARED_MOUNT "/tpm2d"
#define ICC_SHARED_DATA_TYPE "u:object_r:trustme-com:s0"

#define is_selinux_disabled() !file_exists("/sys/fs/selinux")
#define is_selinux_enabled() file_exists("/sys/fs/selinux")

struct c_vol {
	const container_t *container;
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
	case MOUNT_TYPE_SHARED_DATA:
		// Note: this is the upper img for overlayfs
	case MOUNT_TYPE_EMPTY:
	case MOUNT_TYPE_COPY:
		dir = container_get_images_dir(vol->container);
		break;
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

static int
c_vol_create_image_empty(c_vol_t *vol, const char *img, const mount_entry_t *mntent)
{
	off64_t storage_size;
	int fd;

	ASSERT(vol);
	ASSERT(img);
	ASSERT(mntent);

	// minimal storage size is 10 MB
	storage_size = MAX(mount_entry_get_size(mntent), 10);
	storage_size *= 1024 * 1024;

	INFO("Creating empty image file %s with %llu bytes", img, (unsigned long long) storage_size);

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
	case MOUNT_TYPE_SHARED_DATA:
		return c_vol_create_image_empty(vol, img, mntent);
	case MOUNT_TYPE_FLASH:
		return -1; // we cannot create such image files
	case MOUNT_TYPE_EMPTY:
		return c_vol_create_image_empty(vol, img, mntent);
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
	pid_t pid;

	if (strcmp("ext4", fs)) {
		ERROR("Could not create filesystem of type %s on %s", fs, dev);
		return -1;
	}

	pid = fork();

	switch (pid) {
	case -1:
		ERROR_ERRNO("Could not fork to create filesystem for %s", dev);
		return -1;
	case 0:
		execlp("/sbin/"MAKE_EXT4FS, MAKE_EXT4FS, dev, (char *) NULL);
		ERROR_ERRNO("Could not execlp %s", MAKE_EXT4FS);
		return -1;
	default:
		if (waitpid(pid, NULL, 0) != pid) {
			ERROR_ERRNO("Could not waitpid for %s", MAKE_EXT4FS);
			return -1;
		}
		return 0;
	}

	return 0;
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
c_vol_mount_image(c_vol_t *vol, const char *root, const mount_entry_t* mntent)
{
	char *img, *dev, *dir, *lower_dir, *upper_dir, *lower_dev, *lower_img, *work_dir;
	int fd = 0;
	bool new_image = false;
	unsigned long mountflags = MS_NOATIME | MS_NODEV; // default mountflags for most image types
	bool encrypted = false;	    // TODO: should we encrypt all img files except shared images?

	img = dev = dir = lower_dir = upper_dir = lower_dev = lower_img = work_dir = NULL;

	switch (mount_entry_get_type(mntent)) {
	case MOUNT_TYPE_SHARED:
	case MOUNT_TYPE_SHARED_DATA:
	case MOUNT_TYPE_DEVICE:
	case MOUNT_TYPE_OVERLAY_RO:
		mountflags |= MS_RDONLY;    // add read-only flag for shared or device images types
		break;
	case MOUNT_TYPE_SHARED_RW:
	case MOUNT_TYPE_DEVICE_RW:
		break;	    // stick to defaults
	case MOUNT_TYPE_EMPTY:
		encrypted = true;	    // create as encrypted image
		break;
	case MOUNT_TYPE_COPY:		    // deprecated
		//WARN("Found deprecated MOUNT_TYPE_COPY");
		break;
	case MOUNT_TYPE_FLASH:
		DEBUG("Skipping mounting of FLASH type image %s", mount_entry_get_img(mntent));
		goto final;
	default:
		ERROR("Unsupported operating system mount type %d for %s",
				mount_entry_get_type(mntent), mount_entry_get_img(mntent));
		goto error;
	}

	if (mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED_DATA) {

		lower_img = mem_printf("%s/%s.img", cmld_get_shared_data_dir(),
				mount_entry_get_img(mntent));

		if (c_vol_check_image(vol, lower_img) < 0) {
			WARN("Shared data image %s not found. Ignoring.", lower_img);
			goto final;
		}

		// Setup a second device for the lower dir image for overlayfs
		lower_dev = loopdev_new();
		if (!lower_dev) {
			ERROR("Could not get free loop device for %s", lower_img);
			goto error;
		}

		if (loopdev_wait(lower_dev, 10) < 0) {
			ERROR("Device %s for image %s was not created", lower_dev, lower_img);
			goto error;
		}

		// TODO: there might be another process trying to setup a device for dev
		if (loopdev_setup_device(lower_img, lower_dev) < 0) {
			ERROR("Could not setup loop device %s for %s", lower_dev, lower_img);
			goto error;
		}
	}

	if (mount_entry_get_dir(mntent)[0] == '/')
		dir = mem_printf("%s%s", root, mount_entry_get_dir(mntent));
	else
		dir = mem_printf("%s/%s", root, mount_entry_get_dir(mntent));

	if (strcmp(mount_entry_get_fs(mntent), "tmpfs") == 0) {
		if (mount(mount_entry_get_fs(mntent), dir, mount_entry_get_fs(mntent), mountflags, mount_entry_get_mount_data(mntent)) >= 0) {
			DEBUG("Sucessfully mounted %s to %s", mount_entry_get_fs(mntent), dir);
			goto final;
		} else {
			ERROR_ERRNO("Cannot mount %s to %s", mount_entry_get_fs(mntent), dir);
			goto error;
		}
	}

	img = c_vol_image_path_new(vol, mntent);
	if (!img)
		goto error;

	if (c_vol_check_image(vol, img) < 0) {
		new_image = true;
		if (c_vol_create_image(vol, img, mntent) < 0) {
			goto error;
		}
	}

	// TODO if we introduce expand this to MOUNT_TYPE_SHARED_DATA images of
	// this type are checked if present and ignored if not, which could be a
	// way to go
	if (mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED
			|| mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED_RW
			|| mount_entry_get_type(mntent) == MOUNT_TYPE_OVERLAY_RO) {
		if (guestos_check_mount_image_block(container_get_os(vol->container), mntent, true)
				!= CHECK_IMAGE_GOOD) {
			ERROR("Cannot mount image %s: image file is corrupted", img);
			goto error;
		}
	}

	dev = loopdev_new();
	if (!dev) {
		ERROR("Could not get free loop device for %s", img);
		goto error;
	}

	// wait until the devie appears...
	// TODO: how was this timeout chosen?
	// TODO: maybe better wait for the uevent?
	if (loopdev_wait(dev, 10) < 0) {
		ERROR("Device %s for image %s was not created", dev, img);
		goto error;
	}

	// TODO: there might be another process trying to setup a device for dev
	fd = loopdev_setup_device(img, dev);
	if (fd < 0) {
		ERROR("Could not setup loop device %s for %s", dev, img);
		goto error;
	}

	if (encrypted) {
		char *label, *crypt;

		if (!container_get_key(vol->container)) {
		    ERROR("Trying to mount encrypted volume without key...");
		    goto error;
		}

		label = mem_printf("%s-%s", uuid_string(container_get_uuid(vol->container)),
				mount_entry_get_img(mntent));

		DEBUG("Setting up cryptfs volume %s for %s", label, dev);

		crypt = cryptfs_setup_volume_new(label, dev, container_get_key(vol->container));

		if (!crypt) {
			ERROR("Setting up cryptfs volume %s for %s failed", label, dev);
			mem_free(label);
			goto error;
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

	// try to create mount point before mount, usually not necessary...
	if (dir_mkdir_p(dir, 0755) < 0)
		DEBUG_ERRNO("Could not mkdir %s", dir);

	if (mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED_RW) {
		// create mountpoints for lower and upper dev
		char *overlayfs_mount_dir = mem_printf("/tmp/%s-overlayfs", uuid_string(container_get_uuid(vol->container)));
		lower_dir = mem_printf("%s/%s/lower", overlayfs_mount_dir, mount_entry_get_img(mntent));
		upper_dir = mem_printf("%s/%s/upper", overlayfs_mount_dir, mount_entry_get_img(mntent));
		work_dir = mem_printf("%s/%s/work", overlayfs_mount_dir, mount_entry_get_img(mntent));

		if (dir_mkdir_p(overlayfs_mount_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir overlayfs dir %s", overlayfs_mount_dir);
			mem_free(overlayfs_mount_dir);
			goto error;
		}

		// mount rw tmpfs for upper and work dir
		if (mount("tmpfs", overlayfs_mount_dir, "tmpfs", mountflags, mount_entry_get_mount_data(mntent)) < 0) {
			ERROR_ERRNO("Could not mount tmpfs to %s", overlayfs_mount_dir);
			mem_free(overlayfs_mount_dir);
			goto error;
		}
		DEBUG("Successfully mounted tmpfs to %s", overlayfs_mount_dir);
		mem_free(overlayfs_mount_dir);

		if (dir_mkdir_p(lower_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir lower dir %s", lower_dir);
			goto error;
		}
		if (dir_mkdir_p(upper_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir upper dir %s", upper_dir);
			goto error;
		}
		if (dir_mkdir_p(work_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir upper dir %s", work_dir);
			goto error;
		}

		// mount ro lower
		if (mount(dev, lower_dir, mount_entry_get_fs(mntent), mountflags | MS_RDONLY, mount_entry_get_mount_data(mntent)) < 0) {
			ERROR_ERRNO("Could not mount %s using %s to %s", img, dev, lower_dir);
			goto error;
		}
		DEBUG("Successfully mounted %s using %s to %s", img, dev, lower_dir);

		DEBUG("Mounting overlayfs: work_dir=%s, upper_dir=%s, lower_dir=%s, lower_img=%s, target dir=%s",
				work_dir, upper_dir, lower_dir, img, dir);
		// mount overlayfs to dir
		// create mount option string
		char *overlayfs_options = mem_printf("lowerdir=%s,upperdir=%s,workdir=%s",
				lower_dir, upper_dir, work_dir);
		if (mount("overlay", dir, "overlay", 0, overlayfs_options) >= 0) {
			mem_free(overlayfs_options);
			goto final;
		}
		mem_free(overlayfs_options);

		WARN_ERRNO("Could not mount overlay retrying with older overlayfs");
		overlayfs_options = mem_printf("lowerdir=%s,upperdir=%s",
				lower_dir, upper_dir);
		if (mount("overlay", dir, "overlay", 0, overlayfs_options) < 0) {
			ERROR_ERRNO("Could not mount overlayfs");
			mem_free(overlayfs_options);
			goto error;
		}
		mem_free(overlayfs_options);
		goto final;
	}

	if (mount_entry_get_type(mntent) == MOUNT_TYPE_SHARED_DATA) {
		// create mountpoints for lower and upper dev
		char *overlayfs_mount_dir = mem_printf("/tmp/%s-overlayfs", uuid_string(container_get_uuid(vol->container)));
		lower_dir = mem_printf("%s/%s-lower", overlayfs_mount_dir, mount_entry_get_dir(mntent));
		upper_dir = mem_printf("%s/%s-upper", overlayfs_mount_dir, mount_entry_get_dir(mntent));
		mem_free(overlayfs_mount_dir);
		if (dir_mkdir_p(lower_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir lower dir %s", lower_dir);
			goto error;
		}
		if (dir_mkdir_p(upper_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir upper dir %s", upper_dir);
			goto error;
		}

		// mount ro lower
		if (mount(lower_dev, lower_dir, mount_entry_get_fs(mntent), mountflags | MS_RDONLY, NULL) < 0) {
			ERROR_ERRNO("Could not mount %s using %s to %s", lower_img, lower_dev, lower_dir);
			goto error;
		}
		DEBUG("Successfully mounted %s using %s to %s", lower_img, lower_dev, lower_dir);

		if(new_image) {
			if (c_vol_format_image(dev, "ext4") < 0) {
				ERROR("Could not format image %s using %s", img, dev);
				goto error;
			}
			DEBUG("Successfully formatted new image %s using %s", img, dev);
		}

		// mount rw upper
		if (mount(dev, upper_dir, "ext4", MS_NOATIME | MS_NODEV, mount_entry_get_mount_data(mntent)) < 0) {
			ERROR_ERRNO("Could not mount %s using %s to %s", img, dev, upper_dir);
			goto error;
		}
		DEBUG("Successfully mounted %s using %s to %s", img, dev, upper_dir);

		DEBUG("Mounting overlayfs: upper_dir=%s, upper_img=%s, lower_dir=%s, lower_img=%s, target dir=%s",
				upper_dir, img, lower_dir, lower_img, dir);
		// mount overlayfs to dir
		// create mount option string
		char *overlayfs_options = mem_printf("lowerdir=%s,upperdir=%s",
				lower_dir, upper_dir);
		if (mount("overlayfs", dir, "overlayfs", 0, overlayfs_options) < 0) {
			ERROR_ERRNO("Could not mount overlayfs");
			mem_free(overlayfs_options);
			goto error;
		}
		mem_free(overlayfs_options);
		goto final;
	}

	if (mount_entry_get_type(mntent) == MOUNT_TYPE_OVERLAY_RO) {
		// check if its a feature mount and if the container has the feature enabled
		const char* img_name = mount_entry_get_img(mntent);
		size_t feature_len = strlen("feature_");
		if (strncmp(img_name , "feature_", feature_len) == 0) {
			if (!container_is_feature_enabled(vol->container, img_name+feature_len)) {
				DEBUG("Feature %s not enabled, skipping...", img_name+feature_len);
				goto final;
			}
			DEBUG("Going to mount feature %s", img_name+feature_len);
		}
		// create mountpoints for lower and upper dev
		char *overlayfs_mount_dir = mem_printf("/tmp/%s-overlayfs", uuid_string(container_get_uuid(vol->container)));
		upper_dir = mem_printf("%s/%s", overlayfs_mount_dir, mount_entry_get_img(mntent));
		mem_free(overlayfs_mount_dir);

		if (dir_mkdir_p(upper_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir upper dir %s", upper_dir);
			goto error;
		}

		// mount ro upper
		if (mount(dev, upper_dir, mount_entry_get_fs(mntent), mountflags | MS_RDONLY, mount_entry_get_mount_data(mntent)) < 0) {
			ERROR_ERRNO("Could not mount %s using %s to %s", img, dev, upper_dir);
			goto error;
		}
		DEBUG("Successfully mounted %s using %s to %s", img, dev, upper_dir);

		DEBUG("Mounting overlayfs: upper_dir=%s, upper_img=%s, lower_dir=%s, target dir=%s",
				upper_dir, img, dir, dir);
		// mount overlayfs to dir
		// create mount option string
		char *overlayfs_options = mem_printf("lowerdir=%s,upperdir=%s",
				dir, upper_dir);
		if (mount("overlayfs", dir, "overlayfs", 0, overlayfs_options) < 0) {
			ERROR_ERRNO("Could not mount overlayfs");
			mem_free(overlayfs_options);
			goto error;
		}
		mem_free(overlayfs_options);
		goto final;
	}

	DEBUG("Mounting image %s %s using %s to %s",
	      img, mountflags & MS_RDONLY ? "ro" : "rw" , dev, dir);

	if (mount(dev, dir, mount_entry_get_fs(mntent), mountflags, mount_entry_get_mount_data(mntent)) >= 0) {
		DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);
		goto final;
	}

	// retry with default options if selinux is disabled .. (e.g. context= will cause an EINVAL)
	if (is_selinux_disabled() && mount(dev, dir, mount_entry_get_fs(mntent), mountflags, NULL) >= 0) {
		DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);
		goto final;
	}

	if (errno != EINVAL) {
		ERROR_ERRNO("Could not mount image %s using %s to %s", img, dev, dir);
		goto error;
	}

	INFO("Could not mount image %s using %s to %s because an invalid "
			"superblock was detected.", img, dev, dir);

	if (mount_entry_get_type(mntent) != MOUNT_TYPE_EMPTY)
		goto error;

	/* TODO better password handling before in order to remove this condition. */
	if (encrypted  && !new_image) {
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
	if (mount(dev, dir, mount_entry_get_fs(mntent), mountflags, mount_entry_get_mount_data(mntent)) < 0) {
		ERROR("Could not mount image %s using %s to %s", img, dev, dir);
		goto error;
	}

	DEBUG("Sucessfully mounted %s using %s to %s", img, dev, dir);

final:
	if (dev)
		loopdev_free(dev);
	if (lower_dev)
		loopdev_free(lower_dev);
	if (img)
		mem_free(img);
	if (lower_img)
		mem_free(lower_img);
	if (dir)
		mem_free(dir);
	if (lower_dir)
		mem_free(lower_dir);
	if (upper_dir)
		mem_free(upper_dir);
	if (work_dir)
		mem_free(work_dir);
	if (fd)
		close(fd);
	return 0;

error:
	if (dev)
		loopdev_free(dev);
	if (lower_dev)
		loopdev_free(lower_dev);
	if (img)
		mem_free(img);
	if (lower_img)
		mem_free(lower_img);
	if (dir)
		mem_free(dir);
	if (lower_dir)
		mem_free(lower_dir);
	if (upper_dir)
		mem_free(upper_dir);
	if (work_dir)
		mem_free(work_dir);
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

/**
 * Mount all image files.
 * This function is called in the child.
 * @param vol The vol struct for the container.
 * @param root Directory where the root file system should be mounted.
 */
static int
c_vol_mount_images(c_vol_t *vol, const char *root)
{
	size_t i, n;

	ASSERT(vol);
	ASSERT(root);

	/*
	 * We do not umount images here in case of an error because the mount
	 * name space will be deleted in this case anyway.
	 */

	n = mount_get_count(container_get_mount(vol->container));
	for (i = 0; i < n; i++) {
		const mount_entry_t *mntent;

		mntent = mount_get_entry(container_get_mount(vol->container), i);

		if (c_vol_mount_image(vol, root, mntent) < 0) {
			c_vol_cleanup_dm(vol);
			return -1;
		}
	}

	return 0;
}

static void
c_vol_fixup_logdev()
{
	char *log_buffers[4] = {"events", "main", "radio", "system"};
	for (int i=0; i < 4; ++i) {
		char *log_buffer_src = mem_printf("/dev/log_%s", log_buffers[i]);
		if (file_exists(log_buffer_src)) {
			char *log_buffer_dest = mem_printf("/dev/log/%s", log_buffers[i]);
			if (mkdir("/dev/log", 0755) < 0 && errno != EEXIST)
				WARN_ERRNO("Could not mkdir /dev/log dir for container logging");
			if (file_move(log_buffer_src, log_buffer_dest, 0))
				WARN_ERRNO("Could not move %s log buffer to %s", log_buffer_src, log_buffer_dest);
			mem_free(log_buffer_dest);
		}
		mem_free(log_buffer_src);
	}
}

/******************************************************************************/

c_vol_t *
c_vol_new(const container_t *container)
{
	ASSERT(container);

	c_vol_t *vol = mem_new0(c_vol_t, 1);
	vol->container = container;

	return vol;
}

void
c_vol_free(c_vol_t *vol)
{
	ASSERT(vol);

	mem_free(vol);
}

int
c_vol_start_child(c_vol_t *vol)
{
	char *root;

	ASSERT(vol);

	root = mem_printf("/tmp/%s", uuid_string(container_get_uuid(vol->container)));
	INFO("Mounting rootfs to %s", root);

	if (mkdir(container_get_images_dir(vol->container), 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Cound not mkdir container directory %s", container_get_images_dir(vol->container));
		goto error;
	}

	if (mkdir("/tmp", 0700) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir /tmp dir for container start");
		goto error;
	}

	if (mkdir(root, 0700) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir root dir %s for container start", root);
		goto error;
	}

	DEBUG("Mounting images");
	if (c_vol_mount_images(vol, root) < 0) {
		ERROR("Could not mount images for container start");
		goto error;
	}

	/* Bind-mount shared mount for communication */
	// TODO: properly secure this against intercontainer attacks
	char *com_mnt = mem_printf("%s/%s/", root, ICC_SHARED_MOUNT);
	char *com_mnt_data = NULL;
	if(is_selinux_enabled())
		com_mnt_data = mem_printf("defcontext=%s", ICC_SHARED_DATA_TYPE);
	DEBUG("Mounting %s", com_mnt);
	if (mkdir(com_mnt, 0755) < 0 )
		WARN_ERRNO("Could not mkdir %s", com_mnt);
	if (mount("/data/cml/communication", com_mnt, "bind", MS_BIND | MS_NOSUID, com_mnt_data) < 0)
		WARN_ERRNO("Could not mount %s", com_mnt);
	mem_free(com_mnt);

	if (guestos_is_privileged(container_get_guestos(vol->container))) {
		com_mnt = mem_printf("%s/%s/", root, TPM2D_SHARED_MOUNT);
		DEBUG("Mounting %s", com_mnt);
		if (mkdir(com_mnt, 0755) < 0 )
			WARN_ERRNO("Could not mkdir %s", com_mnt);
		if (mount("/data/cml/tpm2d/communication", com_mnt, "bind", MS_BIND | MS_NOSUID, com_mnt_data) < 0)
			WARN_ERRNO("Could not mount %s", com_mnt);
		mem_free(com_mnt);
	}
	mem_free(com_mnt_data);

	if (umount2("/data", MNT_DETACH) < 0 && errno != ENOENT) {
		ERROR_ERRNO("Could not umount /data");
		goto error;
	}

	if (umount("/firmware") < 0 && errno != ENOENT) {
		ERROR_ERRNO("Could not umount /firmware");
		goto error;
	}

	if (umount("/firmware-mdm") < 0 && errno != ENOENT) {
		ERROR_ERRNO("Could not umount /firmware-mdm");
		goto error;
	}

	if (chdir(root) < 0) {
		ERROR_ERRNO("Could not chdir to root dir %s for container start", root);
		goto error;
	}

	if (mount(".", "/", NULL, MS_MOVE, NULL) < 0) {
		ERROR_ERRNO("Could not move mount for container start");
		goto error;
	}

	char *mount_output = file_read_new("/proc/self/mounts", 2048);
	INFO("Mounted filesystems:");
	INFO("%s", mount_output);
	mem_free(mount_output);

	if (chroot(".") < 0) {
		ERROR_ERRNO("Could not chroot to . for container start");
		goto error;
	}

	if (chdir("/") < 0)
		ERROR_ERRNO("Could not chdir to / for container start");

	/* TODO: do we want this mounting configurabel somewhere? */

	DEBUG("Mounting /proc");
	if (mount("proc", "/proc", "proc", MS_RELATIME | MS_NOSUID, NULL) < 0)
		WARN_ERRNO("Could not mount /proc");

	DEBUG("Mounting /sys");
	if (mount("sys", "/sys", "sysfs", MS_RELATIME | MS_NOSUID, NULL) < 0)
		WARN_ERRNO("Could not mount /sys");

	/* Normally this would be done by the policy loading code in the android init process 
	 * (system/core/init/init.c and external/libselinux/src/android.c) */
	if (is_selinux_enabled()) {
		DEBUG("Mounting /sys/fs/selinux");
		if (mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", MS_RELATIME | MS_NOSUID, NULL) < 0)
			WARN_ERRNO("Could not mount /sys/fs/selinuxfs");
	}

	DEBUG("Mounting securityfs to /sys/kernel/security");
	if (mount("securityfs", "/sys/kernel/security", "securityfs", MS_RELATIME | MS_NOSUID, NULL) < 0)
		WARN_ERRNO("Could not mount securityfs to /sys/kernel/security");

	DEBUG("Mounting /dev");
	char* mount_data = is_selinux_enabled() ? "rootcontext=u:object_r:device:s0" : NULL;
	char* devfstype =
		guestos_get_feature_devtmpfs(container_get_guestos(vol->container)) ? "devtmpfs" : "tmpfs";

	if (mount(devfstype, "/dev", devfstype, MS_RELATIME | MS_NOSUID, mount_data) < 0)
		WARN_ERRNO("Could not mount /dev");

	c_vol_fixup_logdev();

	if (mkdir("/dev/pts", 0755) < 0)
		WARN_ERRNO("Could not mkdir /dev/pts");

	DEBUG("Mounting /dev/pts");
	if (mount("devpts", "/dev/pts", "devpts", MS_RELATIME | MS_NOSUID, NULL) < 0)
		WARN_ERRNO("Could not mount /dev/pts");

	if (mkdir("/dev/socket", 0755) < 0)
		WARN_ERRNO("Could not mkdir /dev/socket");

	mem_free(root);
	return 0;

error:
	mem_free(root);
	return -1;
}

void
c_vol_cleanup(c_vol_t *vol)
{
	ASSERT(vol);

	// TODO: also tries to delete other directories (e.g. system), but doesn't succeed.
	// There is only an eror message thrown, not an error returned
	if (c_vol_cleanup_dm(vol))
		WARN("Could not remove mounts properly");
}
