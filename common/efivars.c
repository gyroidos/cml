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

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/dm-ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <sys/mount.h>

#include "macro.h"
#include "mem.h"
#include "uuid.h"
#include "hex.h"
#include "fd.h"
#include "uevent.h"
#include "file.h"
#include "proc.h"

#include "loopdev.h"
#include "cryptfs.h"
#include "dm.h"

#define EFIVARS_BASE_DIR "/sys/firmware/efi/efivars/"
#define EFIVARS_BOOT_UUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"

#define EFIVARS_BOOT0000 EFIVARS_BASE_DIR "Boot0000-" EFIVARS_BOOT_UUID
#define EFIVARS_BOOT0001 EFIVARS_BASE_DIR "Boot0001-" EFIVARS_BOOT_UUID
#define EFIVARS_BOOTX EFIVARS_BASE_DIR "Boot%04X-" EFIVARS_BOOT_UUID
#define EFIVARS_BOOT_CURRENT EFIVARS_BASE_DIR "BootCurrent-" EFIVARS_BOOT_UUID
#define EFIVARS_BOOT_ORDER EFIVARS_BASE_DIR "BootOrder-" EFIVARS_BOOT_UUID
#define EFIVARS_BOOT_NEXT EFIVARS_BASE_DIR "BootNext-" EFIVARS_BOOT_UUID

static bool
efivarfs_mounted(void)
{
	return file_is_mountpoint(EFIVARS_BASE_DIR);
}

static int
mount_efivarfs(void)
{
	if (!efivarfs_mounted()) {
		DEBUG("Mounting /sys/firmware/efi/efivars");
		int ret = mount("efivarfs", "/sys/firmware/efi/efivars/", "efivarfs", 0, NULL);
		if (ret < 0)
			WARN_ERRNO("Could not mount efivarfs");
		return ret;
	}
	return 0;
}

uint16_t
efivars_get_boot_current(void)
{
	char content[6];
	uint16_t boot_current;

	ASSERT(!mount_efivarfs());

	memset(content, 0, sizeof(content));
	file_read(EFIVARS_BOOT_CURRENT, content, sizeof(content));
	boot_current = *(uint16_t *)(content + 4);

	INFO("BootCurrent is %04hX", boot_current);

	return boot_current;
}

uint16_t *
efivars_get_boot_order(size_t *len_out)
{
	char *content;
	uint16_t *boot_order;
	size_t no_boot_entries;
	off_t boot_order_file_sz;

	ASSERT(!mount_efivarfs());

	boot_order_file_sz = file_size(EFIVARS_BOOT_ORDER);
	content = mem_alloc0(boot_order_file_sz);
	boot_order_file_sz = file_read(EFIVARS_BOOT_ORDER, content, boot_order_file_sz);
	no_boot_entries =
		(boot_order_file_sz - 4) /
		sizeof(uint16_t); // should always work. prob check safe wrappers for - and /

	boot_order = (uint16_t *)mem_memcpy((const unsigned char *)(content + 4),
					    no_boot_entries * sizeof(uint16_t));
	*len_out = no_boot_entries;

	mem_free0(content);

	return boot_order;
}

void
efivars_set_boot_order(bool invert)
{
	uint16_t content[] = { 0x0007, 0x0000, 0x0000, 0x0001 };
	uint16_t content_invert[] = { 0x0007, 0x0000, 0x0001, 0x0000 };

	file_write(EFIVARS_BOOT_ORDER, (const char *)(!invert ? &content : &content_invert),
		   4 * sizeof(uint16_t));
}

void
efivars_set_boot_next(uint16_t next)
{
	uint16_t content[3] = { 0x0007, 0x0000, 0x0000 };

	content[2] = next; // next boot entry is the third byte in the file

	file_write(EFIVARS_BOOT_NEXT, (const char *)content, sizeof(content));
}

bool
efivars_boot_entries_initialized(void)
{
	int ret;

	ret = system("efibootmgr | grep Gyroidos");

	if (WEXITSTATUS(ret))
		return false;
	return true;
}

void
efivars_init_boot_entries(void)
{
	ASSERT(!mount_efivarfs());

	IF_TRUE_RETURN(efivars_boot_entries_initialized());

	INFO("Initialize EFI boot entries to default values.");

	// parsing and assembling efi load options is a PITA, so fall back to using efibootmgr for these few calls

	// efibootmgr -b 0 -B
	const char *const argv_clear_boot_0000[] = { "efibootmgr", "-b", "0", "-B", NULL };
	// efibootmgr -b 1 -B
	const char *const argv_clear_boot_0001[] = { "efibootmgr", "-b", "1", "-B", NULL };
	// efibootmgr --create --disk /dev/sda --part 1 --label 'Gyroidos0000' --loader \\EFI\\BOOT\\gyroidos.efi.0000
	const char *const argv_set_boot_0000[] = { "efibootmgr", "--create-only",
						   "--disk",	 "/dev/sda",
						   "--part",	 "1",
						   "--label",	 "GyroidosA",
						   "--loader",	 "\\EFI\\BOOT\\GYROIDOS.EFI.A",
						   NULL };
	// efibootmgr --create --disk /dev/sda --part 1 --label 'Gyroidos0001' --loader \\EFI\\BOOT\\gyroidos.efi.0001
	const char *const argv_set_boot_0001[] = { "efibootmgr", "--create-only",
						   "--disk",	 "/dev/sda",
						   "--part",	 "1",
						   "--label",	 "GyroidosB",
						   "--loader",	 "\\EFI\\BOOT\\GYROIDOS.EFI.B",
						   NULL };

	proc_fork_and_execvp(argv_clear_boot_0000);
	proc_fork_and_execvp(argv_set_boot_0000);
	proc_fork_and_execvp(argv_clear_boot_0001);
	proc_fork_and_execvp(argv_set_boot_0001);

	// set boot order if not initialized
	efivars_set_boot_order(false);

	INFO("Initialized EFI boot entries to default values.");
}
