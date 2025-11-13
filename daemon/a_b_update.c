/*
 * This file is part of GyroidOS
 * Copyright(c) 2025 Fraunhofer AISEC
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

#include <inttypes.h>
#include <stddef.h>

#include "common/efivars.h"
#include "common/file.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/reboot.h"
#include "a_b_update.h"

/*****************************************************************************/

typedef enum {
	A_B_UPDATE_INIT_NONE = 0,
	A_B_UPDATE_INIT_STAGE_1,
	A_B_UPDATE_INIT_STAGE_2,
	A_B_UPDATE_INIT_COMPLETE,
} a_b_update_init_stage_t;

/*****************************************************************************/

static bool
platform_boot_entries_initialized();
static void
platform_init_boot_entries();

/*****************************************************************************/
/* Generic functions */

a_b_update_option_t
a_b_update_get_current(void)
{
	switch (efivars_get_boot_current()) {
	case 0:
		return A_B_UPDATE_OPTION_A;
	case 1:
		return A_B_UPDATE_OPTION_B;
	default:
		return A_B_UPDATE_UNDEFINED;
	}
}

static char *
a_b_update_option_str(a_b_update_option_t opt)
{
	ASSERT(opt == A_B_UPDATE_OPTION_A || opt == A_B_UPDATE_OPTION_B);

	switch (opt) {
	case A_B_UPDATE_OPTION_A:
		return "A";
	case A_B_UPDATE_OPTION_B:
		return "B";
	default:
		return "UNDEFINED"; // never reached due to assert
	}
}

char *
a_b_update_get_path(char *base_path)
{
	a_b_update_option_t cur = a_b_update_get_current();

	if (cur == A_B_UPDATE_UNDEFINED) {
		WARN("Resilient update undefined state. Default to plain values.");
		return mem_strdup(base_path);
	} else {
		return mem_printf("%s.%s", base_path, a_b_update_option_str(cur));
	}
}

static a_b_update_option_t
a_b_update_boot_prio_invert(a_b_update_option_t in)
{
	return in == A_B_UPDATE_OPTION_A ? A_B_UPDATE_OPTION_B : A_B_UPDATE_OPTION_A;
}

char *
a_b_update_get_flash_path(const char *partition)
{
	return mem_printf(
		"%s.%s", partition,
		a_b_update_option_str(a_b_update_boot_prio_invert(a_b_update_get_current())));
}

static a_b_update_init_stage_t
a_b_update_get_init_stage(void)
{
	a_b_update_init_stage_t ret = A_B_UPDATE_INIT_NONE;

	IF_FALSE_GOTO(file_exists("/boot/EFI/BOOT/GYROIDOS.EFI.A"), out);
	IF_FALSE_GOTO(file_exists("/boot/EFI/BOOT/GYROIDOS.EFI.B"), out);
	IF_FALSE_GOTO(file_exists("/data/cml/device.conf.A"), out);
	IF_FALSE_GOTO(file_exists("/data/cml/device.conf.B"), out);
	IF_FALSE_GOTO(platform_boot_entries_initialized(), out);
	DEBUG("All files and boot entries are initialized.");
	ret = A_B_UPDATE_INIT_STAGE_1;

	IF_FALSE_GOTO(a_b_update_get_current() != A_B_UPDATE_UNDEFINED, out);
	/* is that really sufficient? what if bootcurrent was 0/1 before? */
	/* need to check: did the A kernel start? 
                      was the A config loaded? */
	DEBUG("Successfully booted into resilient update option.");
	ret = A_B_UPDATE_INIT_STAGE_2;

	IF_TRUE_GOTO(file_exists("/boot/EFI/BOOT/BOOTX64.EFI"), out);
	IF_TRUE_GOTO(file_exists("/data/cml/device.conf"), out);
	DEBUG("Non-redundant kernel/device.conf already removed.");
	ret = A_B_UPDATE_INIT_COMPLETE;

out:
	INFO("Resilient update is in stage %d/3", ret);
	return ret;
}

void
a_b_update_init(void)
{
	a_b_update_init_stage_t stage = a_b_update_get_init_stage();

	switch (stage) {
	case A_B_UPDATE_INIT_NONE:
		file_copy("/boot/EFI/BOOT/BOOTX64.EFI", "/boot/EFI/BOOT/GYROIDOS.EFI.A", -1, 1, 0);
		file_copy("/boot/EFI/BOOT/BOOTX64.EFI", "/boot/EFI/BOOT/GYROIDOS.EFI.B", -1, 1, 0);
		file_copy("/data/cml/device.conf", "/data/cml/device.conf.A", -1, 1, 0);
		file_copy("/data/cml/device.conf", "/data/cml/device.conf.B", -1, 1, 0);
		platform_init_boot_entries();
		/* intentional fallthrough */
	case A_B_UPDATE_INIT_STAGE_1:
		reboot_reboot(REBOOT);
		return; /* must reboot after this */
	case A_B_UPDATE_INIT_STAGE_2:
		unlink("/boot/EFI/BOOT/BOOTX64.EFI");
		unlink("/data/cml/device.conf");
		/* intentional fallthrough */
	case A_B_UPDATE_INIT_COMPLETE:
		return;
	}
}

/*****************************************************************************/
/* EFI specific functions */

static bool
platform_boot_entries_initialized(void)
{
	return efivars_boot_entries_initialized();
}

static void
platform_init_boot_entries(void)
{
	efivars_init_boot_entries();
}

void
a_b_update_set_boot_order(void)
{
	IF_FALSE_RETURN(a_b_update_get_init_stage() == A_B_UPDATE_INIT_COMPLETE);

	size_t boot_order_len;
	uint16_t boot_current = efivars_get_boot_current();
	uint16_t *boot_order = efivars_get_boot_order(&boot_order_len);

	if (!boot_order_len) {
		WARN("BootOrder does not contain a signle entry.");
		mem_free0(boot_order);
		return;
	}

	if (boot_current != boot_order[0]) {
		INFO("Successful boot with BootCurrent=%04hX != BootOrder[0]=%04hX. Swap BootOrder.",
		     boot_current, boot_order[0]);
		efivars_set_boot_order(boot_current ? true : false);
	} else {
		INFO("BootCurrent=%04hX equals primary load option. Keep BootOrder.", boot_current);
	}

	mem_free0(boot_order);
}

void
a_b_update_boot_new_once(void)
{
	efivars_set_boot_next(a_b_update_boot_prio_invert(a_b_update_get_current()));
}
