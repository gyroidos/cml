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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/dm-ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include "macro.h"
#include "mem.h"
#include "uuid.h"
#include "hex.h"
#include "fd.h"

#include "loopdev.h"
#include "cryptfs.h"
#include "dm.h"

#define UUID_LEN 37

extern struct dm_cmd_table cmd_table[];

/* https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity#verity-superblock-format */
typedef struct __attribute__((packed)) {
	uint8_t signature[8];
	uint32_t version;
	uint32_t hash_type;
	uint8_t uuid[16];
	uint8_t algorithm[32];
	uint32_t data_block_size;
	uint32_t hash_block_size;
	uint64_t data_blocks;
	uint16_t salt_size;
	uint8_t reserved1[6];
	uint8_t salt[256];
	uint8_t reserved2[168];
} verity_sb_t;

extern int errno;

static int
verity_create_uuid(const char *name, const char *uuid_str, char *buf, size_t buflen)
{
	ASSERT(uuid_str);

	// Strip '-' charaters
	char uuid_stripped[UUID_LEN] = { 0 };
	char *p = uuid_stripped;
	for (int i = 0; i < UUID_LEN; i++) {
		if (uuid_str[i] != '-') {
			*p = uuid_str[i];
			p++;
		}
	}

	// Create dm-verity UUID with format CRYPT-VERITY-<UUID>-<device-name>
	if (snprintf(buf, buflen, "CRYPT-VERITY-%s-%s", uuid_stripped, name) < 0) {
		ERROR("Failed to create dm-verity uuid");
		return -1;
	}

	return 0;
}

static void
uuid_bytes_to_string(char *str, uint8_t uuid[16])
{
	char const hex[] = "0123456789abcdef";

	char *p = str;
	for (int i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10) {
			*p++ = '-';
		}
		uint32_t tmp = uuid[i];
		*p++ = hex[tmp >> 4];
		*p++ = hex[tmp & 15];
	}
	*p = '\0';
}

static int
generate_dm_table_load_extra_params(uint8_t *buf, size_t len, verity_sb_t *sb, char *fs_dev,
				    uint64_t fs_size, char *hash_dev, const char *root_hash)
{
	if (len < sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec)) {
		ERROR("Failed to generate dm_table_load extra params: Buffer too small");
		return -1;
	}

	struct dm_target_spec *tgt;
	tgt = (struct dm_target_spec *)&buf[sizeof(struct dm_ioctl)];
	tgt->sector_start = 0;
	tgt->length = fs_size;
	tgt->status = 0;
	strncpy(tgt->target_type, "verity", sizeof(tgt->target_type));

	char *verity_params;
	verity_params = (char *)(buf + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec));

	char *salt = convert_bin_to_hex_new(sb->salt, sb->salt_size);
	uint32_t offset = 1;
	snprintf(verity_params, len - sizeof(struct dm_ioctl) - sizeof(struct dm_target_spec),
		 "%d %s %s %d %d %" PRIu64 " %d %s %s %s", sb->version, fs_dev, hash_dev,
		 sb->data_block_size, sb->hash_block_size, sb->data_blocks, offset, sb->algorithm,
		 root_hash, salt);

	mem_free(salt);

	// Set pointer behind parameter
	verity_params += strlen(verity_params) + 1;
	// Align to an 8 byte boundary
	verity_params = (char *)(((unsigned long)verity_params + 7) & ~8);
	// Set tgt->next right behind dm_target_spec
	tgt->next = (unsigned int)(verity_params - (char *)buf);

	return 0;
}

char *
verity_get_device_path_new(const char *label)
{
	return mem_printf("%s%s", DM_PATH_PREFIX, label);
}

int
verity_create_blk_dev(const char *name, const char *fs_img_name, const char *hash_dev_name,
		      const char *root_hash)
{
	int control_fd = -1;
	int ret = -1;
	uint8_t buf[16384] = { 0 };
	struct dm_ioctl *dmi = NULL;

	TRACE("Opening dm-verity device %s with image %s, hash-tree %s and root-hash %s", name,
	      fs_img_name, hash_dev_name, root_hash);

	// Get UUID and Superblock information from hash device
	verity_sb_t sb = { 0 };
	int hash_fd = open(hash_dev_name, O_RDONLY);
	if (hash_fd < 0) {
		ERROR_ERRNO("Failed to open dm-verity hash device %s", hash_dev_name);
	}

	ssize_t size = fd_read_blockwise(hash_fd, &sb, sizeof(verity_sb_t), 4096, 4096);
	if (size < (ssize_t)sizeof(verity_sb_t)) {
		ERROR("Failed to read superblock of %s", hash_dev_name);
		goto out;
	}
	close(hash_fd);

	// Create dm-verity format uuid
	char uuid[40] = { 0 };
	char dev_uuid[DM_UUID_LEN] = { 0 };
	uuid_bytes_to_string(uuid, sb.uuid);
	if (verity_create_uuid(name, uuid, dev_uuid, sizeof(dev_uuid))) {
		ERROR("Failed to create uuid for dm-verity device %s", name);
		goto out;
	}
	TRACE("dm-verity device %s uuid: %s", name, dev_uuid);

	if ((control_fd = dm_open_control()) < 0) {
		goto out;
	}

	// Make sure that dm-verity device does not already exist
	dmi = (struct dm_ioctl *)buf;
	dm_ioctl_init(dmi, INDEX_DM_TABLE_STATUS, sizeof(buf), name, NULL, DM_EXISTS_FLAG, 0, 0, 0);
	int ioctl_ret = dm_ioctl(control_fd, cmd_table[INDEX_DM_TABLE_STATUS].cmd, dmi);
	if (ioctl_ret == 0 || errno != ENXIO) {
		ERROR("Cannot create dm-verity device %s: Device already exists", name);
		goto out;
	}

	// Create loopdevice for dm-verity image
	int fs_fd = 0;
	char *fs_dev = loopdev_create_new(&fs_fd, fs_img_name, 1, 0);
	if (!fs_dev) {
		goto out;
	}
	TRACE("Created loop device %s for %s", fs_dev, fs_img_name);

	int fs_sector_size = dm_get_blkdev_sector_size(fs_fd);
	if (!(fs_sector_size > 0)) {
		goto out;
	}
	uint64_t fs_size = dm_get_blkdev_size64(fs_fd) / fs_sector_size;
	if (fs_size == 0) {
		goto out;
	}

	// Create loop device for dm-verity hash-tree
	char *hash_dev = loopdev_create_new(&hash_fd, hash_dev_name, 1, 0);
	if (!hash_dev) {
		goto out;
	}
	TRACE("Created loop device %s for %s", hash_dev, hash_dev_name);

	int hash_sector_size = dm_get_blkdev_sector_size(hash_fd);
	if (!(hash_sector_size > 0)) {
		goto out;
	}
	uint64_t hash_dev_size = dm_get_blkdev_size64(hash_fd) / hash_sector_size;
	if (hash_dev_size == 0) {
		goto out;
	}

	// Create verity device
	dm_ioctl_init(dmi, INDEX_DM_DEV_CREATE, sizeof(buf), name, dev_uuid, DM_EXISTS_FLAG, 0, 0,
		      0);
	ioctl_ret = dm_ioctl(control_fd, cmd_table[INDEX_DM_DEV_CREATE].cmd, dmi);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("DM_DEV_CREATE ioctl returned %d", ioctl_ret);
		goto out;
	}

	unsigned long long dev = dmi->dev;

	// Reload the dm table
	dmi = (struct dm_ioctl *)buf;
	unsigned int flags =
		DM_READONLY_FLAG | DM_EXISTS_FLAG | DM_PERSISTENT_DEV_FLAG | DM_SECURE_DATA_FLAG;
	dm_ioctl_init(dmi, INDEX_DM_TABLE_LOAD, sizeof(buf), NULL, NULL, flags, dev, 1, 0);
	if (generate_dm_table_load_extra_params(buf, sizeof(buf), &sb, fs_dev, fs_size, hash_dev,
						root_hash)) {
		goto out;
	}
	ioctl_ret = dm_ioctl(control_fd, cmd_table[INDEX_DM_TABLE_LOAD].cmd, dmi);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("DM_TABLE_LOAD ioctl returned %d", ioctl_ret);
		goto out;
	}

	// Run dev-suspend command
	dmi = (struct dm_ioctl *)buf;
	flags = DM_READONLY_FLAG | DM_EXISTS_FLAG | DM_SECURE_DATA_FLAG;
	dm_ioctl_init(dmi, INDEX_DM_DEV_SUSPEND, sizeof(buf), name, NULL, flags, 0, 0, 0);
	ioctl_ret = dm_ioctl(control_fd, cmd_table[INDEX_DM_DEV_SUSPEND].cmd, dmi);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("DM_DEV_SUSPEND ioctl returned %d", ioctl_ret);
		goto out;
	}

	// Check that verity device activation was successful
	dmi = (struct dm_ioctl *)buf;
	dm_ioctl_init(dmi, INDEX_DM_TABLE_STATUS, sizeof(buf), name, NULL, DM_EXISTS_FLAG, 0, 0, 0);
	ioctl_ret = dm_ioctl(control_fd, cmd_table[INDEX_DM_TABLE_STATUS].cmd, dmi);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("DM_TABLE_STATUS ioctl returned %d", ioctl_ret);
		goto out;
	}
	char *status_line = (char *)&buf[sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec)];
	if (status_line[0] == 'V') {
		DEBUG("Successfully activated verity device %s", name);
	} else if (status_line[0] == 'C') {
		WARN("Activated verity device %s, corruption detected", name);
		goto out;
	} else {
		WARN("Activated verity device %s, unknown status %c", name, status_line[0]);
		goto out;
	}

	ret = 0;

out:
	dm_close_control(control_fd);
	if (fs_fd > 0)
		close(fs_fd);
	if (hash_fd > 0)
		close(hash_fd);

	return ret;
}

int
verity_delete_blk_dev(const char *name)
{
	int control_fd = -1;
	int ret = -1;
	uint8_t buf[16384] = { 0 };
	struct dm_ioctl *dmi = NULL;

	TRACE("Closing dm-verity device %s", name);

	if ((control_fd = dm_open_control()) < 0) {
		goto out;
	}

	// Make sure that dm-verity device exists
	dmi = (struct dm_ioctl *)buf;
	dm_ioctl_init(dmi, INDEX_DM_TABLE_STATUS, sizeof(buf), name, NULL,
		      DM_EXISTS_FLAG | DM_NOFLUSH_FLAG, 0, 0, 0);
	int ioctl_ret = dm_ioctl(control_fd, cmd_table[INDEX_DM_TABLE_STATUS].cmd, dmi);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("Cannot close dm-verity device %s", name);
		goto out;
	}

	dmi = (struct dm_ioctl *)buf;
	dm_ioctl_init(dmi, INDEX_DM_DEV_REMOVE, sizeof(buf), name, NULL, DM_EXISTS_FLAG, 0, 0, 0);
	ioctl_ret = dm_ioctl(control_fd, cmd_table[INDEX_DM_DEV_REMOVE].cmd, dmi);
	if (ioctl_ret != 0) {
		ERROR_ERRNO("Failed to close dm-verty device");
		goto out;
	}

	/* remove device node if necessary */
	char *device = cryptfs_get_device_path_new(name);
	unlink(device);
	mem_free0(device);

	TRACE("Successfully closed dm-verity device %s", name);
	ret = 0;

out:
	dm_close_control(control_fd);

	return ret;
}
