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
#include "../cmld.h"
#include "a_b_update.h"

/*****************************************************************************/

#define DEFAULT_KERNEL_PATH "/boot/EFI/BOOT"
#define DEFAULT_KERNEL_BINARY "BOOTX64.EFI"

/*****************************************************************************/
/* Generic functions that should not be exported outside the a_b_update code */

extern a_b_update_option_t
a_b_update_boot_prio_invert(a_b_update_option_t in);
extern a_b_update_init_stage_t
a_b_update_get_init_stage(void);

/*****************************************************************************/
/* EFI specific functions */

const char *
platform_get_file_path(a_b_update_kernel_path_t p)
{
	switch (p) {
	case KERNEL_BINARY_PLAIN:
		return DEFAULT_KERNEL_PATH "/" DEFAULT_KERNEL_BINARY;
	case KERNEL_BINARY_A:
		return DEFAULT_KERNEL_PATH "/" DEFAULT_KERNEL_BINARY ".A";
	case KERNEL_BINARY_B:
		return DEFAULT_KERNEL_PATH "/" DEFAULT_KERNEL_BINARY ".B";
	default:
		__builtin_unreachable();
	}
}

bool
platform_boot_entries_initialized(void)
{
	return efivars_boot_entry_initialized(0, "GyroidosA",
					      "\\EFI\\BOOT\\" DEFAULT_KERNEL_BINARY ".A") &&
	       efivars_boot_entry_initialized(1, "GyroidosB",
					      "\\EFI\\BOOT\\" DEFAULT_KERNEL_BINARY ".B");
}

void
platform_init_boot_entries(void)
{
	efivars_set_boot_entry(0, "GyroidosA", "\\EFI\\BOOT\\" DEFAULT_KERNEL_BINARY ".A");
	efivars_set_boot_entry(1, "GyroidosB", "\\EFI\\BOOT\\" DEFAULT_KERNEL_BINARY ".B");
	efivars_set_boot_order((uint16_t[]){ 0000, 0001 }, 2);
}

a_b_update_option_t
a_b_update_get_current(void)
{
	uint16_t boot_current;

	if (efivars_get_boot_current(&boot_current)) {
		WARN("Cannot obtain BootCurrent from efivars.");
		return A_B_UPDATE_UNDEFINED;
	}

	switch (boot_current) {
	case 0:
		return A_B_UPDATE_OPTION_A;
	case 1:
		return A_B_UPDATE_OPTION_B;
	default:
		return A_B_UPDATE_UNDEFINED;
	}
}

void
a_b_update_set_boot_order(void)
{
	IF_FALSE_RETURN(a_b_update_get_init_stage() == A_B_UPDATE_INIT_COMPLETE);

	size_t boot_order_len;
	uint16_t boot_current;
	uint16_t *boot_order;

	if (efivars_get_boot_current(&boot_current)) {
		WARN("Cannot obtain BootCurrent from efivars.");
		return;
	}

	boot_order = efivars_get_boot_order(&boot_order_len);
	if (!boot_order) {
		WARN("Cannot obtain BootOrder from efivars.");
		return;
	}

	if (!boot_order_len) {
		WARN("BootOrder does not contain a single entry.");
		mem_free0(boot_order);
		return;
	}

	if (boot_current != boot_order[0]) {
		INFO("Successful boot with BootCurrent=%04hX != BootOrder[0]=%04hX. Swap BootOrder.",
		     boot_current, boot_order[0]);
		efivars_set_boot_order(
			boot_current ? (uint16_t[]){ 0001, 0000 } : (uint16_t[]){ 0000, 0001 }, 2);
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