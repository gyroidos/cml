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

#define DEVICE_CONF_PLAIN DEFAULT_CONF_BASE_PATH "/device.conf"
#define DEVICE_CONF_A DEFAULT_CONF_BASE_PATH "/device.conf.A"
#define DEVICE_CONF_B DEFAULT_CONF_BASE_PATH "/device.conf.B"

/*****************************************************************************/
/* Platform functions that should not be exported outside the a_b_update code*/

extern const char *
platform_get_file_path(a_b_update_kernel_path_t p);
extern bool
platform_boot_entries_initialized(void);
extern void
platform_init_boot_entries();

/*****************************************************************************/
/* Generic functions */

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

a_b_update_init_stage_t
a_b_update_get_init_stage(void)
{
	a_b_update_init_stage_t ret = A_B_UPDATE_INIT_NONE;

	IF_FALSE_GOTO(file_exists(platform_get_file_path(KERNEL_BINARY_A)), out);
	IF_FALSE_GOTO(file_exists(platform_get_file_path(KERNEL_BINARY_B)), out);
	IF_FALSE_GOTO(file_exists(DEVICE_CONF_A), out);
	IF_FALSE_GOTO(file_exists(DEVICE_CONF_B), out);
	IF_FALSE_GOTO(platform_boot_entries_initialized(), out);
	DEBUG("All files and boot entries are initialized.");
	ret = A_B_UPDATE_INIT_STAGE_1;

	IF_FALSE_GOTO(a_b_update_get_current() != A_B_UPDATE_UNDEFINED, out);
	/* is that really sufficient? what if bootcurrent was 0/1 before? */
	/* need to check: did the A kernel start? 
                      was the A config loaded? */
	DEBUG("Successfully booted into resilient update option.");
	ret = A_B_UPDATE_INIT_STAGE_2;

	IF_TRUE_GOTO(file_exists(platform_get_file_path(KERNEL_BINARY_PLAIN)), out);
	IF_TRUE_GOTO(file_exists(DEVICE_CONF_PLAIN), out);
	DEBUG("Non-redundant kernel/device.conf already removed.");
	ret = A_B_UPDATE_INIT_COMPLETE;

out:
	INFO("Resilient update setup is in stage %d/3", ret);
	return ret;
}

void
a_b_update_init(void)
{
	a_b_update_init_stage_t stage = a_b_update_get_init_stage();

	switch (stage) {
	case A_B_UPDATE_INIT_NONE:
		file_copy(platform_get_file_path(KERNEL_BINARY_PLAIN),
			  platform_get_file_path(KERNEL_BINARY_A), -1, 1, 0);
		file_copy(platform_get_file_path(KERNEL_BINARY_PLAIN),
			  platform_get_file_path(KERNEL_BINARY_B), -1, 1, 0);
		file_copy(DEVICE_CONF_PLAIN, DEVICE_CONF_A, -1, 1, 0);
		file_copy(DEVICE_CONF_PLAIN, DEVICE_CONF_B, -1, 1, 0);
		platform_init_boot_entries();
		/* intentional fallthrough */
	case A_B_UPDATE_INIT_STAGE_1:
		INFO("Rebooting into A/B update configuration.");
		reboot_reboot(REBOOT);
		return; /* must reboot after this */
	case A_B_UPDATE_INIT_STAGE_2:
		unlink(platform_get_file_path(KERNEL_BINARY_PLAIN));
		unlink(DEVICE_CONF_PLAIN);
		/* intentional fallthrough */
	case A_B_UPDATE_INIT_COMPLETE:
		return;
	}
}

char *
a_b_update_get_path_new(char *base_path)
{
	a_b_update_option_t cur = a_b_update_get_current();

	if (a_b_update_get_init_stage() < A_B_UPDATE_INIT_STAGE_2 || cur == A_B_UPDATE_UNDEFINED) {
		WARN("Resilient update is not set up. Default to plain values.");
		return mem_strdup(base_path);
	} else {
		return mem_printf("%s.%s", base_path, a_b_update_option_str(cur));
	}
}

a_b_update_option_t
a_b_update_boot_prio_invert(a_b_update_option_t in)
{
	return in == A_B_UPDATE_OPTION_A ? A_B_UPDATE_OPTION_B : A_B_UPDATE_OPTION_A;
}

char *
a_b_update_get_flash_path_new(const char *partition)
{
	if (a_b_update_get_init_stage() < A_B_UPDATE_INIT_STAGE_2) {
		WARN("Resilient update is not set up. Default to plain values.");
		return mem_strdup(partition);
	} else {
		return mem_printf("%s.%s", partition,
				  a_b_update_option_str(
					  a_b_update_boot_prio_invert(a_b_update_get_current())));
	}
}
