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

#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/dm-ioctl.h>
#include <libgen.h>
#include <stdlib.h>
#include <sys/param.h>
#include <string.h>
#include <sys/mount.h>
#include <errno.h>
#include <linux/kdev_t.h>

#include "common/cryptfs.h"

#include "common/macro.h"
#include "common/mem.h"

#define DM_CRYPT_BUF_SIZE 4096

#define TABLE_LOAD_RETRIES 10

#ifdef ANDROID
#define DEV_MAPPER "/dev/device-mapper"
#define CRYPT_PATH_PREFIX "/dev/block/dm-"
#else
#define DEV_MAPPER "/dev/mapper/control"
#define CRYPT_PATH_PREFIX "/dev/mapper/"
#endif

#define CRYPTO_TYPE "aes-xts-plain64"

/* taken from vold */
#define DEVMAPPER_BUFFER_SIZE 4096

/******************************************************************************/

static void
ioctl_init(struct dm_ioctl *io, size_t dataSize, const char *name, unsigned flags)
{
	memset(io, 0, dataSize);
	io->data_size = dataSize;
	io->data_start = sizeof(struct dm_ioctl);
	io->version[0] = 4;
	io->version[1] = 0;
	io->version[2] = 0;
	io->flags = flags;

	if (name)
		strncpy(io->name, name, sizeof(io->name)-1);
}

static unsigned long
get_blkdev_size(int fd)
{
	unsigned long nr_sec;

	if ((ioctl(fd, BLKGETSIZE, &nr_sec)) == -1) {
		nr_sec = -1;
	}
	return nr_sec;
}

char *
cryptfs_get_device_path_new(const char *label)
{
	return mem_printf("%s%s", CRYPT_PATH_PREFIX, label);
}

#if 0
/* Convert a binary key of specified length into an ascii hex string equivalent,
 * without the leading 0x and with null termination
 */
static void
convert_key_to_hex_ascii(unsigned char *master_key, unsigned int keysize,
			      char *master_key_ascii)
{
	unsigned int i, a;
	unsigned char nibble;

	for (i = 0, a = 0; i < keysize; i++, a += 2) {
		/* For each byte, write out two ascii hex digits */
		nibble = (master_key[i] >> 4) & 0xf;
		master_key_ascii[a] = nibble + (nibble > 9 ? 0x37 : 0x30);

		nibble = master_key[i] & 0xf;
		master_key_ascii[a + 1] = nibble + (nibble > 9 ? 0x37 : 0x30);
	}

	/* Add the null termination */
	master_key_ascii[a] = '\0';

}
#endif

static int
load_crypto_mapping_table(const char *real_blk_name,
	     const char *master_key_ascii, const char *name,
	     int fs_size, int fd)
{
	char buffer[DM_CRYPT_BUF_SIZE];
	struct dm_ioctl *io;
	struct dm_target_spec *tgt;
	char *crypt_params;
	char *extra_params = "1 allow_discards";
	int i;

	//DEBUG("Loading crypto mapping table (%s,%s,%s,%d,%d)", real_blk_name,
	//		master_key_ascii, name, fs_size, fd);

	io = (struct dm_ioctl *)buffer;

	/* Load the mapping table for this device */
	tgt = (struct dm_target_spec *)&buffer[sizeof(struct dm_ioctl)];

	ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);
	io->target_count = 1;
	tgt->status = 0;
	tgt->sector_start = 0;
	tgt->length = fs_size;
	strcpy(tgt->target_type, "crypt");

	crypt_params = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
	snprintf(crypt_params, DM_CRYPT_BUF_SIZE-sizeof(struct dm_ioctl)-sizeof(struct dm_target_spec),
			"%s %s 0 %s 0 %s", CRYPTO_TYPE, master_key_ascii,
			real_blk_name, extra_params);
	crypt_params += strlen(crypt_params) + 1;
	crypt_params = (char *)(((unsigned long)crypt_params + 7) & ~8);	/* Align to an 8 byte boundary */
	tgt->next = crypt_params - buffer;

	for (i = 0; i < TABLE_LOAD_RETRIES; i++) {
		if (!ioctl(fd, (int) DM_TABLE_LOAD, io)) {
			break;
		}
		usleep(500000);
	}

	if (i == TABLE_LOAD_RETRIES) {
		/* We failed to load the table, return an error */
		return -1;
	} else {
		return i + 1;
	}
}

static int
create_crypto_blk_dev(const char *real_blk_name, const char *master_key,
				 const char *name)
{
	char buffer[DM_CRYPT_BUF_SIZE];
	struct dm_ioctl *io;
	int fd;
	int retval = -1;
	int load_count;
	unsigned long fs_size;
	int i;

	/* Update the fs_size field to be the size of the volume */
	if ((fd = open(real_blk_name, O_RDONLY)) < 0) {
		ERROR("Cannot open volume %s", real_blk_name);
		return -1;
	}
	fs_size = get_blkdev_size(fd);
	close(fd);
	if (fs_size == 0) {
		ERROR("Cannot get size of volume %s", real_blk_name);
		return -1;
	}

	if ((fd = open(DEV_MAPPER, O_RDWR)) < 0) {
		ERROR("Cannot open device-mapper\n");
		goto errout;
	}

	io = (struct dm_ioctl *)buffer;
	ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);

	for (i = 0; i < TABLE_LOAD_RETRIES; i++) {
		if (!ioctl(fd, (int) DM_DEV_CREATE, io)) {
			break;
		}
		usleep(500000);
	}

	if (i == TABLE_LOAD_RETRIES) {
		/* We failed to load the table, return an error */
		ERROR("Cannot create dm-crypt device");
		goto errout;
	}

	load_count = load_crypto_mapping_table(real_blk_name, master_key,
			name, fs_size, fd);
	if (load_count < 0) {
		ERROR("Cannot load dm-crypt mapping table");
		goto errout;
	} else if (load_count > 1) {
		INFO("Took %d tries to load dmcrypt table.\n", load_count);
	}

	/* Resume this device to activate it */
	ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);

	if (ioctl(fd, (int) DM_DEV_SUSPEND, io)) {
		ERROR_ERRNO("Cannot resume the dm-crypt device\n");
		goto errout;
	}

	/* We made it here with no errors.  Woot! */
	retval = 0;

      errout:
	close(fd);		/* If fd is <0 from a failed open call, it's safe to just ignore the close error */

	return retval;
}

/* TODO:
 * maybe we need to wait a bit before device is created 
 */
static char *
create_device_node(const char *name)
{
	char *buffer = mem_new(char, DEVMAPPER_BUFFER_SIZE);

	int fd = open(DEV_MAPPER, O_RDWR);
	if (fd < 0) {
		ERROR_ERRNO("Error opening devmapper");
		mem_free(buffer);
		return NULL;
	}

	struct dm_ioctl *io = (struct dm_ioctl *) buffer;

	ioctl_init(io, DEVMAPPER_BUFFER_SIZE, name, 0);
	if (ioctl(fd, (int) DM_DEV_STATUS, io)) {
		if (errno != ENXIO) {
			ERROR_ERRNO("DM_DEV_STATUS ioctl failed for lookup");
		}
		mem_free(buffer);
		close(fd);
		return NULL;
	}
	close(fd);

	/* should not be necassery for android */
	mkdir("/dev/block", 00777);

	char *device = cryptfs_get_device_path_new(name);
	/* we might need to remove this device first */
	unlink(device);
	if (mknod(device, S_IFBLK | 00777, io->dev) != 0) {
		ERROR_ERRNO("Cannot mknod device %s", device);
		mem_free(buffer);
		mem_free(device);
		return NULL;
	}
	mem_free(buffer);
	return device;

}

char *
cryptfs_setup_volume_new(const char *label, const char *real_blkdev, const char *key)
//			 char *crypto_sys_path, unsigned int max_path)
{
	if ( create_crypto_blk_dev(real_blkdev, key, label) < 0)
		return NULL;

	return create_device_node(label);
}

int
cryptfs_delete_blk_dev(const char *name)
{
	int fd;
	char buffer[DM_CRYPT_BUF_SIZE];
	struct dm_ioctl *io;
	int ret = -1;

	fd = open(DEV_MAPPER, O_RDWR);
	if (fd < 0) {
		ERROR("Cannot open device-mapper");
		goto error;
	}

	io = (struct dm_ioctl *)buffer;

	ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);
	if (ioctl(fd, (int) DM_DEV_REMOVE, io) < 0) {
		ret = errno;
		if (errno != ENXIO)
			ERROR_ERRNO("Cannot remove dm-crypt device");
		goto error;
	}

	/* remove device node if necessary */
	char *device = cryptfs_get_device_path_new(name);
	unlink(device);
	mem_free(device);

	DEBUG("Successfully deleted dm-crypt device");
	/* We made it here with no errors.  Woot! */
	ret = 0;

error:
	close(fd); /* If fd is <0 from a failed open call, it's safe to just ignore the close error */
	return ret;
}
