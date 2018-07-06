/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2018 Fraunhofer AISEC
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

#include "nvmcrypt.h"
#include "tpm2d.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/cryptfs.h"

#define FDE_KEY_LEN 64

static uint8_t *
nvmcrypt_load_key_new(const char * fde_key_pw)
{
	int ret = 0;
	size_t key_len = FDE_KEY_LEN;
	uint8_t *fde_key = mem_new(uint8_t, FDE_KEY_LEN);

	ret = tpm2_nv_read(TPM2D_FDE_NV_HANDLE, fde_key_pw, fde_key, &key_len);

	if (TPM_RC_SUCCESS == ret) {
		INFO("Loaded FDE Key from NVRAM");
		return fde_key;
	}

	mem_free(fde_key);

	if ((ret & TPM_RCS_HANDLE) != TPM_RCS_HANDLE)
		FATAL("nv_read returned with unexpected error %08x", ret);

	INFO("The Handle %x does not yet exist, creating a new FDE Key", TPM2D_FDE_NV_HANDLE);

	// generate 64 byte random data as input for 512bit AES-XTS key
	fde_key = tpm2_getrandom_new(key_len);

	size_t verify_key_len = FDE_KEY_LEN;
	uint8_t *verify_key = mem_new(uint8_t, FDE_KEY_LEN);

	if (fde_key == NULL) {
		ERROR("Failed to generate fde key!");
		goto err;
	}

	if (TPM_RC_SUCCESS != (ret = tpm2_nv_definespace(TPM2D_KEY_HIERARCHY, TPM2D_FDE_NV_HANDLE,
						key_len, NULL, fde_key_pw))) {
		ERROR("Failed to generate nv area for fde key with error code: %08x", ret);
		goto err;
	}

	if (TPM_RC_SUCCESS != (ret = tpm2_nv_write(TPM2D_FDE_NV_HANDLE, fde_key_pw, fde_key, key_len))) {
		ERROR("Failed to write fde key to nv area with error code: %08x", ret);
		goto err;
	}

	if (TPM_RC_SUCCESS != (ret = tpm2_nv_read(TPM2D_FDE_NV_HANDLE, fde_key_pw, verify_key, &verify_key_len))) {
		ERROR("Failed to read fde key from nv area with error code: %08x", ret);
		goto err;
	}

	if (key_len != verify_key_len) {
		ERROR("FDE-Key verification process failed! key size missmatch!");
		goto err;
	}
	if (memcmp(fde_key, verify_key, key_len) != 0) {
		ERROR("FDE-Key verification process failed! byte copare missmatch!");
		goto err;
	}

	mem_free(verify_key);
	return fde_key;
err:
	if (verify_key)
		mem_free(verify_key);
	if (fde_key)
		mem_free(fde_key);

	return NULL;
}

void
nvmcrypt_dm_setup(const char* device_path, const char *fde_pw)
{
	ASSERT(device_path);

	IF_FALSE_RETURN_ERROR(file_exists(device_path));
	char *dev_name = basename(device_path);

	uint8_t * key = nvmcrypt_load_key_new(fde_pw);
	IF_NULL_RETURN_ERROR(key);

	// cryptfs_setup_volume_new expects an ascii string as key
	char * ascii_key = convert_bin_to_hex_new(key, FDE_KEY_LEN);

	INFO("Setting up crypto device mapping for %s to %s", device_path, dev_name);

	char* mapped_path = cryptfs_setup_volume_new(dev_name, device_path, ascii_key);

	if (mapped_path == NULL)
		ERROR("Failed to setup device mapping for %s", device_path);

	mem_free(mapped_path);
	mem_free(ascii_key);
	mem_free(key);
}
