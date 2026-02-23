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

#include "common/mem.h"

/*****************************************************************************/

typedef enum {
	A_B_UPDATE_OPTION_A = 0,
	A_B_UPDATE_OPTION_B,
	A_B_UPDATE_UNDEFINED
} a_b_update_option_t;

typedef enum {
	A_B_UPDATE_INIT_NONE = 0,
	A_B_UPDATE_INIT_STAGE_1,
	A_B_UPDATE_INIT_STAGE_2,
	A_B_UPDATE_INIT_COMPLETE,
} a_b_update_init_stage_t;

typedef enum {
	KERNEL_BINARY_A,
	KERNEL_BINARY_B,
} a_b_update_kernel_path_t;

/*****************************************************************************/

#define A_B_UPDATE_FILE_SUFFIX_A ".A"
#define A_B_UPDATE_FILE_SUFFIX_B ".B"

/*****************************************************************************/

#ifdef A_B_UPDATE
/**
 * Obtain the currently running boot option.
 * @return A_B_UPDATE_OPTION[AB] or A_B_UPDATE_UNDEFINED if the platorm is
 * 		   running an unknown boot option.
 */
a_b_update_option_t
a_b_update_get_current(void);

/**
 * Extend the given path with the extension according to the currently
 * running boot option.
 *
 * Do not use this function on the kernel image files as they use a dfferent
 * naming scheme!
 *
 * @param Base path to exetend
 * @return Extended path or the base path if the current platform state
 * 		   is undefined.
 */
char *
a_b_update_get_path_new(char *base_path);

/**
 * Like a_b_update_get_path_new except extend with the extension for the
 * alternative boot option.
 * @param Base path to exetend
 * @return Extended path; defaults to option A if platform state is undefined.
 */
char *
a_b_update_get_flash_path_new(const char *partition);

/**
 * Migrate a non-redundant installation duplicating kernel and device.conf,
 * setting the boot switch mechanism (e.g. efivars) and removing the original
 * files.
 */
void
a_b_update_init(void);

/**
 * If the current boot option differs from the default one, set the current
 * option as default. This is used to set the default option after successful
 * update.
 */
void
a_b_update_set_boot_order(void);

/**
 * Temporarily switch to the alternative boot option for the next boot.
 */
void
a_b_update_boot_new_once(void);
#else
static inline char *
a_b_update_get_path_new(char *base_path)
{
	return mem_strdup(base_path);
}

static inline void
a_b_update_init(void)
{
}

static inline void
a_b_update_set_boot_order(void)
{
}
#endif
