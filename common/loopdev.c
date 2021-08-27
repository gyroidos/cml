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

char *
loopdev_new(void)
{
	int fd, i;

	fd = open(LOOP_CONTROL, O_RDONLY);
	if (fd < 0) {
		ERROR_ERRNO("Cannot open %s", LOOP_CONTROL);
		return NULL;
	}

	//i = ioctl(loop_fd, LOOP_CTL_ADD);
	i = ioctl(fd, LOOP_CTL_GET_FREE);
	close(fd);
	if (i < 0) {
		ERROR("Cannot get free loop device");
		return NULL;
	}

	/* TODO: Handle creation of new loop devices dynamically?
	 */

	return mem_printf("%s%d", LOOP_DEV_PREFIX, i);
}

void
loopdev_free(char *dev)
{
	mem_free0(dev);
}

int
loopdev_wait(const char *dev, unsigned timeout)
{
	unsigned i;

	for (i = 0; i < timeout; i++) {
		struct stat st;

		DEBUG("Checking loop device %s (%i/%i)", dev, i, timeout);
		if (stat(dev, &st) || !S_ISBLK(st.st_mode))
			usleep(1000);
		else
			return 0;
	}

	return -1;
}

/*
 * Taken from:
 * http://stackoverflow.com/questions/11295154/how-do-i-loop-mount-programmatically
 */

int
loopdev_setup_device(const char *img, const char *dev)
{
	struct loop_info64 info;
	mem_memset(&info, 0, sizeof(info));
	int img_fd, dev_fd = -1;

	img_fd = open(img, O_RDWR | O_EXCL);
	if (img_fd < 0) {
		ERROR_ERRNO("Could not open image file %s", img);
		goto error;
	}

	dev_fd = open(dev, O_RDWR);
	if (dev_fd < 0) {
		ERROR_ERRNO("Could not open device %s", dev);
		goto error;
	}

	if (ioctl(dev_fd, LOOP_SET_FD, img_fd) < 0) {
		ERROR_ERRNO("Failed to set fd of loop device %s", dev);
		goto error;
	}

	if (ioctl(dev_fd, LOOP_GET_STATUS64, &info) < 0) {
		ERROR_ERRNO("Failed to get status64 for loop device %s", dev);
		goto error;
	}

	/* so we do not need a detach of the loop device after umount */
	info.lo_flags |= LO_FLAGS_AUTOCLEAR;

	if (ioctl(dev_fd, LOOP_SET_STATUS64, &info) < 0) {
		ERROR_ERRNO("Failed to set AUTOCLEAR for loop device %s", dev);
		goto error;
	}

	close(img_fd);
	return dev_fd;

error:
	if (img_fd >= 0)
		close(img_fd);

	if (dev_fd >= 0) {
		ioctl(dev_fd, LOOP_CLR_FD, 0);
		close(dev_fd);
	}
	return -1;
}
