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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "loopdev.h"

#include "macro.h"
#include "mem.h"

#ifndef LOOP_CTL_GET_FREE
#define LOOP_CTL_GET_FREE 0x4C82
#endif

#ifdef ANDROID
#define LOOP_DEV_PREFIX "/dev/block/loop"
#else
#define LOOP_DEV_PREFIX "/dev/loop"
#endif

#define LOOP_CONTROL "/dev/loop-control"

#define SECTOR_SHIFT 9
#define SECTOR_SIZE (1 << SECTOR_SHIFT)

/**
 * Get a free loop device.
 * @return The path of the loop device or NULL in case of an error.
 */
static char *
loopdev_new(void)
{
	int fd, i;
	char dev[64];
	struct stat st;

	fd = open(LOOP_CONTROL, O_RDONLY);
	if (fd < 0) {
		ERROR_ERRNO("Cannot open %s", LOOP_CONTROL);
		return NULL;
	}

	i = ioctl(fd, LOOP_CTL_GET_FREE);
	close(fd);
	if (i < 0) {
		ERROR("Cannot get free loop device");
		return NULL;
	}

	if (sprintf(dev, "%s%d", LOOP_DEV_PREFIX, i) < 0) {
		ERROR("Failed to create loopdev name");
		return NULL;
	}

	if (stat(dev, &st)) {
		ERROR("Failed to check device info");
		return NULL;
	}

	if (!S_ISBLK(st.st_mode)) {
		ERROR("Device is not a block device");
		return NULL;
	}

	return mem_strdup(dev);
}

char *
loopdev_create_new(int *loop_fd, const char *img, int readonly, size_t blocksize)
{
	struct loop_info64 info;
	mem_memset(&info, 0, sizeof(info));
	int img_fd;
	char *loop_dev = NULL;

	img_fd = open(img, (readonly ? O_RDONLY : O_RDWR) | O_EXCL);
	if (img_fd < 0) {
		ERROR_ERRNO("Could not open image file %s with readonly = %d", img, readonly);
		goto error;
	}

	// Set file name
	strncpy((char *)info.lo_file_name, img, sizeof(info.lo_file_name) - 1);
	// Do not require detach after umount
	info.lo_flags |= LO_FLAGS_AUTOCLEAR;

	do {
		loop_dev = loopdev_new();
		if (!loop_dev) {
			ERROR("Could not get free loop device for %s", img);
			goto error;
		}

		*loop_fd = open(loop_dev, readonly ? O_RDONLY : O_RDWR);
		if (*loop_fd < 0) {
			ERROR_ERRNO("Could not open device %s", loop_dev);
			goto error;
		}

		if (ioctl(*loop_fd, LOOP_SET_FD, img_fd) < 0) {
			if (errno != EBUSY) {
				ERROR_ERRNO("LOOP_SET_FD ioctl failed");
				goto error;
			}
			mem_free(loop_dev);
			loop_dev = NULL;
			close(*loop_fd);
			*loop_fd = -1;
		}
	} while (*loop_fd < 0);

	if (blocksize > SECTOR_SIZE) {
		ioctl(*loop_fd, LOOP_SET_BLOCK_SIZE, (unsigned long)blocksize);
	}

	// TODO For kernel 5.8 and later, LOOP_CONFIGURE could be used instead
	// (https://man7.org/linux/man-pages/man4/loop.4.html)
	if (ioctl(*loop_fd, LOOP_SET_STATUS64, &info) < 0) {
		ERROR_ERRNO("Failed to set AUTOCLEAR for loop device %s", loop_dev);
		goto error;
	}

	memset(&info, 0x0, sizeof(info));
	if (ioctl(*loop_fd, LOOP_GET_STATUS64, &info) < 0) {
		ERROR_ERRNO("Failed to get status64 for loop device %s", loop_dev);
		goto error;
	}

	// Verify that autoclear is set
	if (!(info.lo_flags & LO_FLAGS_AUTOCLEAR)) {
		ERROR("Autoclear not successfully set");
		goto error;
	}

	close(img_fd);
	return loop_dev;

error:
	if (img_fd >= 0)
		close(img_fd);

	if (*loop_fd >= 0) {
		ioctl(*loop_fd, LOOP_CLR_FD, 0);
		close(*loop_fd);
	}
	return NULL;
}

void
loopdev_free(char *dev)
{
	mem_free0(dev);
}