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
#include <sys/mount.h>

#include <efivar/efivar.h>
#include <efivar/efiboot.h>

#include "macro.h"
#include "mem.h"
#include "file.h"
#include "proc.h"

#define EFI_LOAD_OPTION_ACTIVE 1

uint16_t *
efivars_get_boot_current_new(void)
{
	uint8_t *data = NULL;
	size_t size;
	uint32_t attrs;

	IF_FALSE_RETVAL(efi_variables_supported(), NULL);

	// data is allocated by libefivar and can be passed to caller
	efi_get_variable(EFI_GLOBAL_GUID, "BootCurrent", &data, &size, &attrs);

	return (uint16_t *)data;
}

uint16_t *
efivars_get_boot_order_new(size_t *len_out)
{
	uint8_t *data = NULL;
	size_t size;
	uint32_t attrs;

	IF_FALSE_RETVAL(efi_variables_supported(), NULL);

	// data is allocated by libefivar and can be passed to caller
	efi_get_variable(EFI_GLOBAL_GUID, "BootOrder", &data, &size, &attrs);
	IF_NULL_GOTO(data, out);

	*len_out = size / sizeof(uint16_t);
out:
	return (uint16_t *)data;
}

int
efivars_set_boot_order(const uint16_t *order, size_t len)
{
	IF_FALSE_RETVAL(efi_variables_supported(), -1);

	return efi_set_variable(EFI_GLOBAL_GUID, "BootOrder", (uint8_t *)order,
				len * sizeof(uint16_t),
				EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
					EFI_VARIABLE_RUNTIME_ACCESS,
				0644);
}

int
efivars_set_boot_next(uint16_t next)
{
	IF_FALSE_RETVAL(efi_variables_supported(), -1);

	return efi_set_variable(EFI_GLOBAL_GUID, "BootNext", (uint8_t *)&next, sizeof(next),
				EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
					EFI_VARIABLE_RUNTIME_ACCESS,
				0644);
}

static efidp
device_path_new(const char *path, size_t *len_out)
{
	efidp dp = NULL;
	ssize_t dp_len;

	dp_len = efi_generate_file_device_path_from_esp(NULL, 0, "/dev/disk/by-label/boot", 1, path,
							EFIBOOT_ABBREV_HD);
	if (dp_len < 0) {
		WARN("Could not generate device path from ESP");
		goto out;
	}

	dp = mem_alloc0(dp_len);

	dp_len = efi_generate_file_device_path_from_esp(
		(uint8_t *)dp, dp_len, "/dev/disk/by-label/boot", 1, path, EFIBOOT_ABBREV_HD);
	if (dp_len < 0) {
		WARN("Could not generate device path from ESP");
		mem_free0(dp);
		goto out;
	}

	*len_out = dp_len;
out:
	return dp;
}

static char *
format_device_path_new(efidp dp, size_t dp_len)
{
	ssize_t required;
	char *buf = NULL;

	required = efidp_format_device_path(NULL, 0, dp, dp_len);
	if (required < 0) {
		WARN("Could not format device path");
		return NULL;
	}

	buf = mem_alloc0(required);

	required = efidp_format_device_path((unsigned char *)buf, required, dp, dp_len);
	if (required < 0) {
		WARN("Could not format device path");
		mem_free0(buf);
		return NULL;
	}

	return buf;
}

bool
efivars_boot_entry_initialized(uint16_t idx, const char *label, const char *path)
{
	bool ret = false;
	uint8_t *data = NULL;
	size_t size;
	uint32_t attrs;
	char *var_name;
	char *desc = NULL;
	size_t dp_len;
	efidp dp_ref = NULL, dp_is = NULL;
	char *path_ref = NULL, *path_is = NULL;

	IF_FALSE_RETVAL(efi_variables_supported(), false);

	// 0. obtain the BootXXXX variable content
	var_name = mem_printf("Boot%04hX", idx);
	IF_NULL_GOTO(var_name, out);

	efi_get_variable(EFI_GLOBAL_GUID, var_name, &data, &size, &attrs);
	IF_NULL_GOTO(data, out);

	// 1. check that the description is correctly set
	// note: desc is internally tracked by libefivar and must not be freed
	desc = (char *)efi_loadopt_desc((efi_load_option *)data, size);
	IF_FALSE_GOTO(strcmp(label, desc) == 0, out);

	// 2. check that the file path is correctly set
	// 2.1. reference value
	dp_ref = device_path_new(path, &dp_len);
	IF_NULL_GOTO(dp_ref, out);
	path_ref = format_device_path_new(dp_ref, dp_len);
	IF_NULL_GOTO(path_ref, out);

	// 2.2. actual value
	dp_is = efi_loadopt_path((efi_load_option *)data, size);
	path_is = format_device_path_new(dp_is, efi_loadopt_pathlen((efi_load_option *)data, size));
	IF_NULL_GOTO(path_ref, out);

	IF_FALSE_GOTO(strncmp(path_ref, path_is, strlen(path_ref)) == 0, out);

	ret = true;
out:
	if (var_name)
		mem_free0(var_name);
	if (dp_ref)
		mem_free0(dp_ref);
	if (path_ref)
		mem_free0(path_ref);
	if (path_is)
		mem_free0(path_is);
	if (data)
		mem_free0(data);
	return ret;
}

int
efivars_set_boot_entry(uint16_t idx, const char *label, const char *path)
{
	int ret = -1;
	size_t dp_len, loadopt_len;
	efidp dp = NULL;
	uint8_t *loadopt_buf = NULL;
	char *var_name = NULL;

	IF_FALSE_RETVAL(efi_variables_supported(), -1);

	// 1. create the load path from the partition and file path
	dp = device_path_new(path, &dp_len);
	IF_NULL_GOTO(dp, out);

	// 2. create the EFI load option struct
	loadopt_len = efi_loadopt_create(NULL, 0, EFI_LOAD_OPTION_ACTIVE, dp, dp_len,
					 (unsigned char *)label, NULL, 0);
	loadopt_buf = mem_alloc0(loadopt_len);
	loadopt_len = efi_loadopt_create(loadopt_buf, loadopt_len, EFI_LOAD_OPTION_ACTIVE, dp,
					 dp_len, (unsigned char *)label, NULL, 0);

	// 3. generate the variable name
	var_name = mem_printf("Boot%04hX", idx);
	IF_NULL_GOTO(var_name, out);

	// write to the variable
	ret = efi_set_variable(EFI_GLOBAL_GUID, var_name, loadopt_buf, loadopt_len,
			       EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
				       EFI_VARIABLE_RUNTIME_ACCESS,
			       0644);
out:
	if (var_name)
		mem_free0(var_name);
	if (loadopt_buf)
		mem_free0(loadopt_buf);
	if (dp)
		mem_free0(dp);
	return ret;
}
