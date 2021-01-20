/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2021 Fraunhofer AISEC
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
#include <linux/ioctl.h>
#include <linux/unistd.h>
#include <linux/dm-ioctl.h>
#include <libgen.h>
#include <stdlib.h>
#include <sys/param.h>
#include <string.h>
#include <sys/mount.h>
#include <errno.h>
#include <linux/kdev_t.h>

#include "cryptfs.h"
#include "macro.h"
#include "mem.h"
#include "proc.h"

#ifdef ANDROID
#define DEV_MAPPER "/dev/device-mapper"
#define CRYPT_PATH_PREFIX "/dev/block/dm-"
#else
#define DEV_MAPPER "/dev/mapper/control"
#define CRYPT_PATH_PREFIX "/dev/mapper/"
#endif

#define TABLE_LOAD_RETRIES 10
#define INTEGRITY_TAG_SIZE 32
#define CRYPTO_TYPE "capi:aegis128-random"

/* taken from vold */
#define DEVMAPPER_BUFFER_SIZE 4096
#define DM_CRYPT_BUF_SIZE 4096
#define DM_INTEGRITY_BUF_SIZE 4096

/* FIXME Rejig library to record & use errno instead */
#ifndef DM_EXISTS_FLAG
#define DM_EXISTS_FLAG 0x00000004
#endif

/******************************************************************************/

#ifdef __GNU_LIBRARY__
#define dm_ioctl(...) ioctl(__VA_ARGS__)
#else
/*
 * non glibc std libraries such as musl provide ioctl (int, int, ...)
 * wrapper. However, dm integrity requests are 'unsigned long int' and
 * would overflow on a cast to int. Thus, we directly provide a wrapper
 * here instead of using the ioctl wrapper of the std library.
 */
static int
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
		strncpy(io->name, name, sizeof(io->name) - 1);
}

static unsigned long
get_blkdev_size(int fd)
{
	unsigned long nr_sec;

	if ((dm_ioctl(fd, BLKGETSIZE, &nr_sec)) == -1) {
		nr_sec = 0;
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

//For debugging, ensure that ioctl receives the correct parameters
//static void print_io_struct(struct dm_ioctl *io)
//{
//	DEBUG("[+] struct dm_ioctl: ");
//	DEBUG("[+]     io->version: %d.%d.%d", io->version[0], io->version[1], io->version[2]);
//	DEBUG("[+]     io->data_size: %d", io->data_size);
//	DEBUG("[+]     io->data_start: %d", io->data_start);
//	DEBUG("[+]     io->target_count: %d", io->target_count);
//	DEBUG("[+]     io->open_count: %d", io->open_count);
//	DEBUG("[+]     io->flags: %d", io->flags);
//	DEBUG("[+]     io->event_nr: %d", io->event_nr);
//	DEBUG("[+]     io->name: %s", io->name);
//	DEBUG("[+]     io->uuid: %s", io->uuid);
//	DEBUG("[+]     io->data: %c%c%c%c%c%c%c",io->data[0],io->data[1],io->data[2],io->data[3],io->data[4],io->data[5],io->data[6]);
//
//	return;
//}

// This function is used for debugging purposes.
// TODO: split into load_integrity_mapping_table and create_integrity_blk_dev once it is verified to
// work properly
// This function does:
//		Create an integrity block device with IOCTL(DM_DEV_CREATE)
//		Next load the mapping table of this device with IOCTL(DM_TABLE_LOAD)
//		Lastly resume the device with IOCTL(DM_DEV_SUSPEND)
//		Only then the crypto device can be mounted ontop of the integrity device
//
//	This general functionality is adapted from [1] and strace of the dmsetup setup
//	When executing this functionality on its on (in a separate .c file), on a host system it works
//	Verified by:
//		user@host:~/$ sudo dmsetup ls --tree
//            integrity_with_hash (253:6)
//             └─ (7:3)
//
//	And:
//      user@host:~/$ sudo dmsetup table
//            integrity_with_hash: 0 327680 integrity 7:3 0 32 J 5 journal_sectors:3168 interleave_sectors:32768 buffer_sectors:128 journal_watermark:50 commit_time:10000 internal_hash:sha256
//
// -> The device gets created with the correct parameters and is mounted. Yet, this function within cryptfs.c, when executed within the VM
// does return an error while ioctl(DM_TABLE_LOAD)
// Algorithm modules and kernel configs were set according to [1]
//
// [1] https://wiki.gentoo.org/wiki/Device-mapper#Integrity
// FIXME: currently ioctl with DM_TABLE_LOAD returns errno=22,
static int
cryptfs_configure_and_execute_integrity(const char *real_blk_name, const char *name,
					unsigned long fs_size)
{
	//general variables
	int fd_mapper;
	int ioctl_ret;

	//create blk dev variables
	char create_buffer[DM_INTEGRITY_BUF_SIZE];
	struct dm_ioctl *create_io;
	int create_counter;

	//load mapping variables
	char mapping_buffer[DM_INTEGRITY_BUF_SIZE];
	struct dm_target_spec *tgt;
	struct dm_ioctl *mapping_io;
	char *integrity_params;
	char *extra_params = "internal_hash:sha256";
	int mapping_counter;

	DEBUG("[+] Configuring integrity block device");

	//open device mapper
	if ((fd_mapper = open(DEV_MAPPER, O_RDWR)) < 0) {
		ERROR("[+]  Cannot open device-mapper");
	}

	//################################################################################################
	// Create blk device
	// ioctl(fd_mapper, DM_DEV_CREATE, io)
	DEBUG("[+] Creating block device");

	//initialize create_io struct
	create_io = (struct dm_ioctl *)create_buffer;
	ioctl_init(create_io, DM_INTEGRITY_BUF_SIZE, name, 0);

	for (create_counter = 0; create_counter < TABLE_LOAD_RETRIES; create_counter++) {
		ioctl_ret = dm_ioctl(fd_mapper, DM_DEV_CREATE, create_io);
		if (ioctl_ret != 0) {
			ERROR("[+]    Could not create block device: ioctl(DM_DEV_CREATE) ret: %d, errno: %d",
			      ioctl_ret, errno);
		} else {
			DEBUG("[+]    Creating block device worked!");
			break;
		}

		usleep(500000);
	}

	if (create_counter >= TABLE_LOAD_RETRIES) {
		ERROR("[+]  Failed to create block device after %d tries", create_counter);
		goto errout;
	}

	//################################################################################################
	//Load Integrity map table
	// ioctl(fd_mapper, DM_TABLE_LOAD, io)
	DEBUG("[+]  Loading Integrity mapping table");

	mapping_io = (struct dm_ioctl *)mapping_buffer;

	/* Load the mapping table for this device */
	tgt = (struct dm_target_spec *)&mapping_buffer[sizeof(struct dm_ioctl)];

	// Configure parameters for ioctl
	ioctl_init(mapping_io, DM_INTEGRITY_BUF_SIZE, name, 0);
	mapping_io->target_count = 1;
	tgt->status = 0;
	tgt->sector_start = 0;
	tgt->length = fs_size;
	strcpy(tgt->target_type, "integrity");

	//write the intergity parameters at the end after dm_target_spec
	integrity_params = mapping_buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);

	//write parameter
	// these parameters are used in [1] as well as by dmsetup when traced with strace
	snprintf(integrity_params,
		 DM_INTEGRITY_BUF_SIZE - sizeof(struct dm_ioctl) - sizeof(struct dm_target_spec),
		 "%s 0 %d J %s", real_blk_name, INTEGRITY_TAG_SIZE, extra_params);

	DEBUG("[+]   integrity_params: %s", integrity_params);

	//set pointer behind parameter
	integrity_params += strlen(integrity_params) + 1;
	// byte align the parameter
	integrity_params = (char *)(((unsigned long)integrity_params + 7) &
				    ~8); /* Align to an 8 byte boundary */
	//set tgt->next right behind dm_target_spec
	tgt->next = integrity_params - mapping_buffer;

	//print_io_struct(mapping_io);

	for (mapping_counter = 0; mapping_counter < TABLE_LOAD_RETRIES; mapping_counter++) {
		DEBUG("[+]   Executing: ioctl(fd_mapper: %d, DM_TABLE_LOAD: %d, mapping_io:%p)",
		      fd_mapper, (int)DM_TABLE_LOAD, (void *)mapping_io);

		ioctl_ret = dm_ioctl(fd_mapper, DM_TABLE_LOAD, mapping_io);

		switch (errno) {
		case 0:
			DEBUG("[+]    No Error: errno: %d, ioctl_ret: %d", errno, ioctl_ret);
			break;
		case EINVAL:
			DEBUG("[+]    IOCTL_RETURN: EINVAL ioctl_ret: %d", ioctl_ret);
			break;
		case ENOENT:
			DEBUG("[+]    IOCTL_RETURN: ENOENT ioctl_ret: %d", ioctl_ret);
			break;
		default:
			DEBUG("[+]    OTHER ERROR: errno: %d, ioctl_ret: %d", errno, ioctl_ret);
			break;
		}

		if (ioctl_ret == 0) {
			DEBUG("[+]  IOCTL successfully returned %d", ioctl_ret);
			break;
		}
		usleep(500000);
	}

	// check that loading the table worked
	if (mapping_counter >= TABLE_LOAD_RETRIES) {
		ERROR("[+] Loading Mapping Table did not work after %d tries", mapping_counter);
		goto errout;
	}

	//################################################################################################
	// Resume this device to activate it
	// ioctl(fd_mapper, DM_DEV_SUSPEND, io)
	DEBUG("[+] Resuming the blk device");
	ioctl_init(create_io, DM_INTEGRITY_BUF_SIZE, name, 0);

	ioctl_ret = dm_ioctl(fd_mapper, DM_DEV_SUSPEND, create_io);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("[+]  Cannot resume the dm-integrity device (ioctl ret: %d, errno:%d)",
			    ioctl_ret, errno);
		goto errout;
	} else {
		DEBUG("[+]  Resuming the device worked!");
	}

	//if the program ends here: everything worked
	return 0;

errout:
	ERROR("[+] Failed integrity block creation");
	return -1;
}

//static int
//load_integrity_mapping_table(const char *real_blk_name, const char *name, int fs_size, int fd)
//{
//	char buffer[DM_INTEGRITY_BUF_SIZE];
//	struct dm_ioctl *io;
//	struct dm_target_spec *tgt;
//	char *integrity_params;
//	const char *extra_params = "0";
//	int i;
//
//	DEBUG("Loading integrity mapping table (%s,%s,%d,%d)", real_blk_name, name, fs_size, fd);
//
//	io = (struct dm_ioctl *)buffer;
//
//	/* Load the mapping table for this device */
//	tgt = (struct dm_target_spec *)&buffer[sizeof(struct dm_ioctl)];
//
//	ioctl_init(io, DM_INTEGRITY_BUF_SIZE, name, 0);
//	io->target_count = 1;
//	tgt->status = 0;
//	tgt->sector_start = 0;
//	/* Should be size specified in superblock! */
//	tgt->length = fs_size;
//	strcpy(tgt->target_type, "integrity");
//
//	integrity_params = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
//	snprintf(integrity_params,
//		 DM_INTEGRITY_BUF_SIZE - sizeof(struct dm_ioctl) - sizeof(struct dm_target_spec),
//		 "%s 0 %d J %s", real_blk_name, INTEGRITY_TAG_SIZE, extra_params);
//
//
//
//	integrity_params += strlen(integrity_params) + 1;
//	integrity_params =
//		(char *)(((unsigned long)integrity_params + 7) & ~8); /* Align to an 8 byte boundary */
//	tgt->next = integrity_params - buffer;
//
//	for (i = 0; i < TABLE_LOAD_RETRIES; i++) {
//		if (!ioctl(fd, (int)DM_TABLE_LOAD, io)) {
//			break;
//		}
//		usleep(500000);
//	}
//
//	if (i == TABLE_LOAD_RETRIES) {
//		/* We failed to load the table, return an error */
//		ERROR("Failed to load dm-integrity mapping table after %d tries", i);
//		return -1;
//	} else {
//		return i + 1;
//	}
//}

static int
load_crypto_mapping_table(const char *real_blk_name, const char *master_key_ascii, const char *name,
			  int fs_size, int fd)
{
	char buffer[DM_CRYPT_BUF_SIZE];
	struct dm_ioctl *io;
	struct dm_target_spec *tgt;
	char *crypt_params;
	char *extra_params = mem_printf("1 integrity:%d:aead", INTEGRITY_TAG_SIZE);
	int i;
	int ioctl_ret;

	DEBUG("Loading crypto mapping table (%s,%s,%s,%s,%d,%d)", real_blk_name, CRYPTO_TYPE,
	      master_key_ascii, name, fs_size, fd);

	io = (struct dm_ioctl *)buffer;

	/* Load the mapping table for this device */
	tgt = (struct dm_target_spec *)&buffer[sizeof(struct dm_ioctl)];

	ioctl_init(io, DM_CRYPT_BUF_SIZE, name, DM_EXISTS_FLAG);
	io->target_count = 1;
	tgt->status = 0;
	tgt->sector_start = 0;
	tgt->length = fs_size;
	strcpy(tgt->target_type, "crypt");

	crypt_params = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
	snprintf(crypt_params,
		 DM_CRYPT_BUF_SIZE - sizeof(struct dm_ioctl) - sizeof(struct dm_target_spec),
		 "%s %s 0 %s 0 %s", CRYPTO_TYPE, master_key_ascii, real_blk_name, extra_params);
	mem_free(extra_params);

	crypt_params += strlen(crypt_params) + 1;
	crypt_params =
		(char *)(((unsigned long)crypt_params + 7) & ~8); /* Align to an 8 byte boundary */
	tgt->next = crypt_params - buffer;

	for (i = 0; i < TABLE_LOAD_RETRIES; i++) {
		ioctl_ret = dm_ioctl(fd, DM_TABLE_LOAD, io);
		if (!ioctl_ret) {
			DEBUG("[+]   LOADING ENCRYPTION MAP WORKED FLAWLESS!");
			break;
		} else {
			DEBUG("[+]  ERROR while loading table entries: ioctl_ret:%d, errno:%d",
			      ioctl_ret, errno);
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

//static int
//create_integrity_blk_dev(const char *real_blk_name, const char *name, const unsigned long fs_size)
//{
//	char buffer[DM_INTEGRITY_BUF_SIZE];
//	struct dm_ioctl *io;
//	int fd;
//	int retval = -1;
//	int load_count;
//	int i;
//
//	if ((fd = open(DEV_MAPPER, O_RDWR)) < 0) {
//		ERROR("Cannot open device-mapper");
//		goto errout;
//	}
//
//	io = (struct dm_ioctl *)buffer;
//	ioctl_init(io, DM_INTEGRITY_BUF_SIZE, name, 0);
//
//	for (i = 0; i < TABLE_LOAD_RETRIES; i++) {
//		if (!ioctl(fd, (int)DM_DEV_CREATE, io)) {
//			break;
//		}
//		usleep(500000);
//	}
//
//	if (i == TABLE_LOAD_RETRIES) {
//		/* We failed create the device, return an error */
//		ERROR("Cannot create dm-integrity device");
//		goto errout;
//	}
//
//	/* fs_size should be read from superblock after first table load with fs_size=1 */
//	load_count = load_integrity_mapping_table(real_blk_name, name, fs_size, fd);
//
//	if (load_count < 0) {
//		ERROR("Cannot load dm-integrity mapping table");
//		goto errout;
//	} else if (load_count > 1) {
//		INFO("Took %d tries to load dm-integrity table.", load_count);
//	}
//
//	/* Resume this device to activate it */
//	ioctl_init(io, DM_INTEGRITY_BUF_SIZE, name, 0);
//
//	if (ioctl(fd, (int)DM_DEV_SUSPEND, io)) {
//		ERROR_ERRNO("Cannot resume the dm-integrity device");
//		goto errout;
//	}
//
//	/* We made it here with no errors.  Woot! */
//	retval = 0;
//
//errout:
//	close(fd);
//
//	return retval;
//}

static int
create_crypto_blk_dev(const char *real_blk_name, const char *master_key, const char *name)
{
	char buffer[DM_CRYPT_BUF_SIZE];
	struct dm_ioctl *io;
	int fd;
	int retval = -1;
	int load_count;
	unsigned long fs_size;
	int i;
	int ioctl_ret;

	DEBUG("[+] Creating crypto blk device");
	/* Update the fs_size field to be the size of the volume */
	if ((fd = open(real_blk_name, O_RDONLY)) < 0) {
		ERROR("      Cannot open volume %s", real_blk_name);
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
		ioctl_ret = dm_ioctl(fd, DM_DEV_CREATE, io);

		if (!ioctl_ret) {
			DEBUG("[+]  Cryptp DM_DEV_CREATE WORKED!");
			break;
		}
		DEBUG("[+]  Cryptp DM_DEV_CREATE DOES NOT WORK!");
		usleep(500000);
	}

	if (i == TABLE_LOAD_RETRIES) {
		/* We failed to load the table, return an error */
		ERROR("Cannot create dm-crypt device");
		goto errout;
	}

	load_count = load_crypto_mapping_table(real_blk_name, master_key, name, fs_size, fd);
	if (load_count < 0) {
		ERROR("Cannot load dm-crypt mapping table");
		goto errout;
	} else if (load_count > 1) {
		INFO("Took %d tries to load dmcrypt table.\n", load_count);
	}

	/* Resume this device to activate it */
	ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);

	if (dm_ioctl(fd, DM_DEV_SUSPEND, io)) {
		ERROR_ERRNO("Cannot resume the dm-crypt device\n");
		goto errout;
	}

	/* We made it here with no errors.  Woot! */
	retval = 0;

errout:
	close(fd); /* If fd is <0 from a failed open call, it's safe to just ignore the close error */
	DEBUG("[+]      Returning %d from create_crypte_bkl_dev", retval);
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

	struct dm_ioctl *io = (struct dm_ioctl *)buffer;

	ioctl_init(io, DEVMAPPER_BUFFER_SIZE, name, 0);
	if (dm_ioctl(fd, DM_DEV_STATUS, io)) {
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

static int
delete_integrity_blk_dev(const char *name)
{
	int fd;
	char buffer[DM_INTEGRITY_BUF_SIZE];
	struct dm_ioctl *io;
	int ret = -1;

	fd = open(DEV_MAPPER, O_RDWR);
	if (fd < 0) {
		ERROR("Cannot open device-mapper");
		goto error;
	}

	io = (struct dm_ioctl *)buffer;

	ioctl_init(io, DM_INTEGRITY_BUF_SIZE, name, 0);
	if (dm_ioctl(fd, DM_DEV_REMOVE, io) < 0) {
		ret = errno;
		if (errno != ENXIO)
			ERROR_ERRNO("Cannot remove dm-integrity device");
		goto error;
	}

	/* remove device node if necessary */
	char *device = cryptfs_get_device_path_new(name);
	unlink(device);
	mem_free(device);

	DEBUG("Successfully deleted dm-integrity device");
	/* We made it here with no errors.  Woot! */
	ret = 0;

error:
	close(fd);
	return ret;
}

/*
static unsigned long
get_provided_data_sectors(const char *real_blk_name)
{
	int fd;
	unsigned long provided_data_sectors = 0;
	char magic[8]; // "integrt" on a valid superblock

	if ((fd = open(real_blk_name, O_RDONLY)) < 0) {
		ERROR("Cannot open volume %s", real_blk_name);
		return 0;
	}

	int bytes_read = read(fd, magic, sizeof(magic));
	DEBUG("Bytes read: %d", bytes_read);
	if (bytes_read != sizeof(magic)) {
		ERROR("Cannot read superblock type from volume %s", real_blk_name);
		goto errout;
	}
	if (strcmp(magic, "integrt") != 0) {
		DEBUG("No existing integrity superblock detected on %s", real_blk_name);
		provided_data_sectors = 1;
		goto errout;
	}

	// 16 Bytes offset from start of superblock for provided_data_sectors
	lseek(fd, 16, SEEK_SET);
	bytes_read = read(fd, &provided_data_sectors, sizeof(provided_data_sectors));
	DEBUG("Read bytes is: %d", bytes_read);

	if (bytes_read != sizeof(provided_data_sectors) || provided_data_sectors == 0) {
	        ERROR("Cannot read provided_data_sectors from volume %s", real_blk_name);
		goto errout;
	}

errout:
	DEBUG("Returning: provided_data_sectors= %ld",provided_data_sectors);
	DEBUG("[+++++++] get_provided_data_sectors done");
	close(fd);
	return provided_data_sectors;
}
*/
//TODO: get number of data sectors available from superblock

static unsigned long
get_provided_data_sectors(const char *real_blk_name)
{
	int fd;
	unsigned long provided_data_sectors = 0;
	DEBUG("[+]      In get_provided_data_sectors");
	if ((fd = open(real_blk_name, O_RDONLY)) < 0) {
		ERROR("Cannot open volume %s", real_blk_name);
		return 0;
	}

	DEBUG("[+]      Using 80%% of block device size as provided_data_sectors");
	provided_data_sectors = 0.8 * get_blkdev_size(fd);

	close(fd);
	return provided_data_sectors;
}

char *
cryptfs_setup_volume_new(const char *label, const char *real_blkdev, const char *key)
//			 char *crypto_sys_path, unsigned int max_path)
{
	char *integrity_dev_label = mem_printf("%s-%s", label, "integrity");
	unsigned long fs_size = get_provided_data_sectors(real_blkdev);

	if (fs_size <= 0) {
		DEBUG("[+]    get_provided_data_sectors returned %lu!!", fs_size);
		return NULL;
	}

	if (cryptfs_configure_and_execute_integrity(real_blkdev, integrity_dev_label, fs_size) <
	    0) {
		DEBUG("[+]    create_integrity_blk_dev failed!");
		return NULL;
	}

	//TODO: fix create_integrity_blk_dev once cryptfs_configure_and_execute_integrity works
	//if (create_integrity_blk_dev(real_blkdev, //integrity_dev_label, fs_size) < 0)
	//{
	//	DEBUG("[+]    create_integrity_blk_dev failed!");
	//	return NULL;
	//}
	//DEBUG("[+]    create_integrity_blk_dev suceeded");

	char *integrity_dev = create_device_node(integrity_dev_label);
	mem_free(integrity_dev_label);
	if (!integrity_dev)
		return NULL;

	/* Use only the first 32 hex digits of master key for 128 bit aead modes */
	char aead_key[33];
	snprintf(aead_key, 33, "%s", key);

	if (create_crypto_blk_dev(integrity_dev, aead_key, label) < 0)
		return NULL;

	return create_device_node(label);
}

int
cryptfs_format_volume(const char *dev)
{
	int fd;
	unsigned long fs_size;
	char *of;
	char *count;
	int ret;
	DEBUG("[+] Encrypting device in cryptfs_format_volume");
	/* Update the fs_size field to be the size of the volume */
	if ((fd = open(dev, O_RDONLY)) < 0) {
		ERROR("Cannot open volume %s", dev);
		return -1;
	}
	fs_size = get_blkdev_size(fd);
	close(fd);
	if (fs_size == 0) {
		ERROR("Cannot get size of volume %s", dev);
		return -1;
	}

	if ((fd = open(dev, O_RDWR)) < 0) {
		ERROR("Cannot open volume %s", dev);
		return -1;
	}

	/* Set direct io for dm-crypt device to ignore invalid integrity tags */
	int ioctl_return = ioctl(fd, O_DIRECT, 1);

	if (ioctl_return < 0) {
		ERROR("IOCTL coult not be opened!");
	}

	of = mem_printf("of=%s", dev);
	count = mem_printf("count=%lu", fs_size);
	const char *const argv_dd[] = { "dd", "if=/dev/null", of, count, NULL };

	DEBUG("Formatting device %s (%s %s %s %s)", dev, argv_dd[0], argv_dd[1], argv_dd[2],
	      argv_dd[3]);

	ret = proc_fork_and_execvp(argv_dd);
	DEBUG("[+] cryptfs_format_volume returnes: %d, errno: %d", ret, errno);
	ioctl(fd, O_DIRECT, 0);
	close(fd);
	mem_free(of);
	mem_free(count);

	return ret;
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
	if (dm_ioctl(fd, DM_DEV_REMOVE, io) < 0) {
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

	char *integrity_dev_name = mem_printf("%s-%s", name, "integrity");
	if (delete_integrity_blk_dev(integrity_dev_name) < 0) {
		mem_free(integrity_dev_name);
		goto error;
	}

	mem_free(integrity_dev_name);

	/* We made it here with no errors.  Woot! */
	ret = 0;

error:
	close(fd); /* If fd is <0 from a failed open call, it's safe to just ignore the close error */
	return ret;
}
