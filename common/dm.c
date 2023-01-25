
/*
 * This file is part of trust|me
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

#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/ioctl.h>
#include <linux/unistd.h>
#include <linux/dm-ioctl.h>
#include <libgen.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <errno.h>
#include <stdint.h>

#include "macro.h"
#include "mem.h"
#include "dm.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct dm_cmd_table cmd_table[] = {
	{ DM_DEV_CREATE, { 4, 0, 0 } },	  { DM_TABLE_LOAD, { 4, 0, 0 } },
	{ DM_DEV_REMOVE, { 4, 0, 0 } },	  { DM_REMOVE_ALL, { 4, 0, 0 } },
	{ DM_DEV_SUSPEND, { 4, 0, 0 } },  { DM_DEV_STATUS, { 4, 0, 0 } },
	{ DM_TABLE_DEPS, { 4, 0, 0 } },	  { DM_DEV_RENAME, { 4, 0, 0 } },
	{ DM_VERSION, { 4, 0, 0 } },	  { DM_TABLE_STATUS, { 4, 0, 0 } },
	{ DM_DEV_WAIT, { 4, 0, 0 } },	  { DM_LIST_DEVICES, { 4, 0, 0 } },
	{ DM_TABLE_CLEAR, { 4, 0, 0 } },  { DM_LIST_VERSIONS, { 4, 1, 0 } },
	{ DM_TARGET_MSG, { 4, 2, 0 } },	  { DM_DEV_SET_GEOMETRY, { 4, 6, 0 } },
	{ DM_DEV_ARM_POLL, { 4, 36, 0 } }
};

#ifndef __GNU_LIBRARY__
/*
 * non glibc std libraries such as musl provide ioctl (int, int, ...)
 * wrapper. However, dm integrity requests are 'unsigned long int' and
 * would overflow on a cast to int. Thus, we directly provide a wrapper
 * here instead of using the ioctl wrapper of the std library.
 */
int
dm_ioctl(int fd, unsigned long int request, ...)
{
	void *args;
	va_list ap;
	int result;
	va_start(ap, request);
	args = va_arg(ap, void *);
	result = syscall(__NR_ioctl, fd, request, args);
	va_end(ap);
	return result;
}
#endif

int
dm_ioctl_init(struct dm_ioctl *io, enum dm_cmd_index idx, size_t data_size, const char *name,
	      const char *uuid, unsigned flags, unsigned long long dev, unsigned int target_count,
	      unsigned int event_nr)
{
	if (idx > ARRAY_SIZE(cmd_table)) {
		ERROR("Failed to lookup ioctl command");
		return -1;
	}

	mem_memset(io, 0, data_size);
	io->data_size = data_size;
	io->data_start = sizeof(struct dm_ioctl);
	io->version[0] = cmd_table[idx].version[0];
	io->version[1] = cmd_table[idx].version[1];
	io->version[2] = cmd_table[idx].version[2];
	io->flags = flags;
	io->dev = dev;
	io->target_count = target_count;
	io->event_nr = event_nr;

	if (name)
		strncpy(io->name, name, sizeof(io->name) - 1);

	if (uuid)
		strncpy(io->uuid, uuid, sizeof(io->name) - 1);

	return 0;
}

int
dm_open_control(void)
{
	int fd = open(DM_CONTROL, O_RDWR);
	if (fd < 0) {
		ERROR_ERRNO("Failed to open %s\n", DM_CONTROL);
		return -1;
	}
	return fd;
}

void
dm_close_control(int fd)
{
	if (fd > 0)
		close(fd);
}

uint64_t
dm_get_blkdev_size64(int fd)
{
	uint64_t size;

	if ((dm_ioctl(fd, BLKGETSIZE64, &size)) == -1) {
		ERROR_ERRNO("BLKGETSIZE64 ioctl failed");
		size = 0;
	}
	return size;
}

int
dm_get_blkdev_sector_size(int fd)
{
	int sec_size;

	if ((dm_ioctl(fd, BLKSSZGET, &sec_size)) == -1) {
		ERROR_ERRNO("BLKSSZGET ioctl failed");
		sec_size = -1;
	}
	return sec_size;
}

int
dm_get_blkdev_readonly(int fd)
{
	int read_only;

	if ((dm_ioctl(fd, BLKROGET, &read_only)) == -1) {
		ERROR_ERRNO("BLKROGET ioctl failed");
		read_only = -1;
	}
	return read_only;
}

int
dm_read_version(int fd)
{
	uint8_t buf[16384] = { 0 };
	struct dm_ioctl *dmi = NULL;

	dmi = (struct dm_ioctl *)buf;
	dm_ioctl_init(dmi, INDEX_DM_VERSION, sizeof(buf), NULL, NULL, DM_EXISTS_FLAG, 0, 0, 0);
	int ioctl_ret = dm_ioctl(fd, cmd_table[INDEX_DM_VERSION].cmd, dmi);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("DM_VERSION ioctl returned %d", ioctl_ret);
		return -1;
	}

	TRACE("DM Version: %d.%d.%d", dmi->version[0], dmi->version[1], dmi->version[2]);
	return 0;
}

int
dm_list_versions(int fd)
{
	uint8_t buf[16384] = { 0 };
	struct dm_ioctl *dmi = NULL;

	dmi = (struct dm_ioctl *)buf;
	dm_ioctl_init(dmi, INDEX_DM_LIST_VERSIONS, sizeof(buf), NULL, NULL, DM_EXISTS_FLAG, 0, 0,
		      0);
	int ioctl_ret = dm_ioctl(fd, cmd_table[INDEX_DM_LIST_VERSIONS].cmd, dmi);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("DM_VERSION ioctl returned %d", ioctl_ret);
		return -1;
	}

	return 0;
}

char *
dm_get_target_type_new(int fd, const char *name)
{
	ASSERT(strlen(name) <= DM_NAME_LEN);

	uint8_t buf[16384] = { 0 };
	struct dm_ioctl *dmi = NULL;

	dmi = (struct dm_ioctl *)buf;
	dm_ioctl_init(dmi, INDEX_DM_TABLE_STATUS, sizeof(buf), name, NULL, DM_EXISTS_FLAG, 0, 0, 0);
	int ret = dm_ioctl(fd, cmd_table[INDEX_DM_TABLE_STATUS].cmd, dmi);
	if (ret) {
		// Integrity devices get a "-integrity" postfix, try again with postfix
		char *integrity_dev_name = mem_printf("%s-%s", name, "integrity");
		dm_ioctl_init(dmi, INDEX_DM_TABLE_STATUS, sizeof(buf), integrity_dev_name, NULL,
			      DM_EXISTS_FLAG, 0, 0, 0);
		int ret = dm_ioctl(fd, cmd_table[INDEX_DM_TABLE_STATUS].cmd, dmi);
		mem_free0(integrity_dev_name);
		if (ret) {
			ERROR_ERRNO("Failed to get dm-type: DM_TABLE_STATUS ioctl returned %d",
				    ret);
			return NULL;
		}
	}

	struct dm_target_spec *tgt;
	tgt = (struct dm_target_spec *)&buf[sizeof(struct dm_ioctl)];

	return mem_strdup(tgt->target_type);
}