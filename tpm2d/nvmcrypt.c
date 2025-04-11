/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

// for gnu version of basename
#define _GNU_SOURCE
#include <string.h>

#include "nvmcrypt.h"
#include "tpm2d.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/cryptfs.h"

static nvmcrypt_fde_state_t fde_state = FDE_RESET;
static bool secure_boot = false;
static uint8_t *nvmcrypt_nvindex_policy = NULL;

static TPM_RC
nvmcrypt_start_policy_session(TPM_SE session_type, TPMI_SH_AUTH_SESSION *session_handle,
			      TPMI_DH_OBJECT bind_handle, const char *bind_pwd)
{
	TPM_RC ret;
	tpm2d_pcr_t **pcrs = NULL;
	size_t pcrs_len = 0;

	if (session_type == TPM_SE_TRIAL) {
		pcrs_len = 1;
		pcrs = mem_alloc0(MUL_WITH_OVERFLOW_CHECK((size_t)sizeof(tpm2d_pcr_t *), pcrs_len));

		// read one PCR, namely PCR 7 (efi secure boot variables)
		pcrs[0] = tpm2_pcrread_new(0x7, TPM2D_HASH_ALGORITHM);
		if (pcrs[0] == NULL) {
			ret = TSS_RC_NULL_PARAMETER;
			goto cleanup;
		}
	}

	ret = tpm2_startauthsession(session_type, session_handle, bind_handle, bind_pwd);
	IF_FALSE_RETVAL(TPM_RC_SUCCESS == ret, ret);

	// mask PCR 7
	ret = tpm2_policypcr(*session_handle, 0x80, pcrs, pcrs_len);
cleanup:
	for (size_t i = 0; i < pcrs_len; ++i)
		if (pcrs[i])
			tpm2_pcrread_free(pcrs[i]);
	if (pcrs)
		mem_free0(pcrs);

	return ret;
}

static TPM_RC
nvmcrypt_create_policy(void)
{
	TPM_RC ret;
	TPMI_SH_AUTH_SESSION se_trial;

	if (NULL == nvmcrypt_nvindex_policy)
		nvmcrypt_nvindex_policy = mem_new(uint8_t, TPM2D_DIGEST_SIZE);

	ret = nvmcrypt_start_policy_session(TPM_SE_TRIAL, &se_trial, TPM_RH_NULL, NULL);
	IF_FALSE_RETVAL(TPM_RC_SUCCESS == ret, ret);

	ret = tpm2_policygetdigest(se_trial, nvmcrypt_nvindex_policy, TPM2D_DIGEST_SIZE);
	IF_FALSE_RETVAL(TPM_RC_SUCCESS == ret, ret);

	// cleanup any previous policy states, e.g. form trial session
	ret = tpm2_policyrestart(se_trial);
	IF_FALSE_RETVAL(TPM_RC_SUCCESS == ret, ret);

	return tpm2_flushcontext(se_trial);
}

static uint8_t *
nvmcrypt_load_key_new(const char *fde_key_pw)
{
	TPMI_SH_AUTH_SESSION se_handle;
	int ret = 0;
	size_t key_len = CRYPTFS_FDE_KEY_LEN;
	uint8_t *fde_key;

	// check if nv index exists by requesting size of index which does a nv_read_public
	if (tpm2_nv_get_data_size(TPM2D_FDE_NV_HANDLE) != 0) {
		if (secure_boot) {
			//ret = nvmcrypt_start_policy_session(TPM_SE_POLICY, &se_handle, TPM2D_FDE_NV_HANDLE, fde_key_pw);
			ret = nvmcrypt_start_policy_session(TPM_SE_POLICY, &se_handle, TPM_RH_NULL,
							    NULL);
		} else {
			// let nv_read do its own auth session
			se_handle = TPM_RH_NULL;
			ret = TPM_RC_SUCCESS;
		}
		if (TPM_RC_SUCCESS == ret) {
			fde_key = mem_new(uint8_t, CRYPTFS_FDE_KEY_LEN);
			ret = tpm2_nv_read(se_handle, TPM2D_FDE_NV_HANDLE, fde_key_pw, fde_key,
					   &key_len);

			if (TPM_RC_SUCCESS == ret) {
				fde_state = FDE_OK;
				INFO("Loaded FDE Key from NVRAM");
				//ret = tpm2_flushcontext(se_handle);
				if (TPM_RC_SUCCESS != ret)
					WARN("Failed flush policy session after nvread with error code: %08x",
					     ret);
				return fde_key;
			}

			if ((ret & TPM_RC_AUTH_FAIL) == TPM_RC_AUTH_FAIL) {
				fde_state = FDE_AUTH_FAILED;
			} else if ((ret & TPM_RC_POLICY_FAIL) == TPM_RC_POLICY_FAIL) {
				fde_state = FDE_AUTH_FAILED;
			} else if ((ret & TPM_RC_NV_LOCKED) == TPM_RC_NV_LOCKED) {
				fde_state = FDE_KEY_ACCESS_LOCKED;
			} else {
				WARN("nv_read returned with unexpected error %08x", ret);
				fde_state = FDE_UNEXPECTED_ERROR;
			}
			mem_free0(fde_key);
			return NULL;
		}
	}

	INFO("The Handle %x does not yet exist, creating a new FDE Key", TPM2D_FDE_NV_HANDLE);

	// generate 64 byte random data as input for 512bit AES-XTS key
	fde_key = tpm2_getrandom_new(key_len);

	size_t verify_key_len = CRYPTFS_FDE_KEY_LEN;
	uint8_t *verify_key = mem_new(uint8_t, CRYPTFS_FDE_KEY_LEN);

	if (fde_key == NULL) {
		ERROR("Failed to generate fde key!");
		goto err;
	}

	if (TPM_RC_SUCCESS !=
	    (ret = tpm2_nv_definespace(TPM2D_KEY_HIERARCHY, TPM2D_FDE_NV_HANDLE, key_len, NULL,
				       fde_key_pw, nvmcrypt_nvindex_policy))) {
		ERROR("Failed to generate nv area for fde key with error code: %08x", ret);
		goto err;
	}

	if (TPM_RC_SUCCESS !=
	    (ret = tpm2_nv_write(TPM2D_FDE_NV_HANDLE, fde_key_pw, fde_key, key_len))) {
		ERROR("Failed to write fde key to nv area with error code: %08x", ret);
		goto err;
	}

	if (secure_boot) {
		if (TPM_RC_SUCCESS != (ret = nvmcrypt_start_policy_session(
					       TPM_SE_POLICY, &se_handle, TPM_RH_NULL, NULL))) {
			ERROR("Failed to start policy session for nvread! with error code: %08x",
			      ret);
			goto err;
		}
	} else {
		// let nv_read do its own auth session
		se_handle = TPM_RH_NULL;
	}

	if (TPM_RC_SUCCESS != (ret = tpm2_nv_read(se_handle, TPM2D_FDE_NV_HANDLE, fde_key_pw,
						  verify_key, &verify_key_len))) {
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

	mem_free0(verify_key);

	fde_state = FDE_OK;
	return fde_key;
err:
	fde_state = FDE_KEYGEN_FAILED;
	if (verify_key)
		mem_free0(verify_key);
	if (fde_key)
		mem_free0(fde_key);

	return NULL;
}

nvmcrypt_fde_state_t
nvmcrypt_dm_setup(const char *device_path, const char *fde_pw)
{
	IF_TRUE_RETVAL(device_path == NULL || !file_exists(device_path), FDE_NO_DEVICE);
	char *dev_name = basename(device_path);

	uint8_t *key = nvmcrypt_load_key_new(fde_pw);
	IF_NULL_RETVAL(key, fde_state);

	// cryptfs_setup_volume_new expects an ascii string as key
	char *ascii_key = convert_bin_to_hex_new(key, CRYPTFS_FDE_KEY_LEN);

	INFO("Setting up crypto device mapping for %s to %s", device_path, dev_name);

	char *mapped_path = cryptfs_setup_volume_new(dev_name, device_path, ascii_key, NULL,
						     CRYPTFS_MODE_ENCRYPT_ONLY);

	if (mapped_path == NULL) {
		ERROR("Failed to setup device mapping for %s", device_path);
		fde_state = FDE_NO_DEVICE;
	}

	mem_free0(mapped_path);
	mem_memset0(ascii_key, strlen(ascii_key));
	mem_memset0(key, CRYPTFS_FDE_KEY_LEN);
	mem_free0(ascii_key);
	mem_free0(key);
	return fde_state;
}

nvmcrypt_fde_state_t
nvmcrypt_dm_lock(const char *fde_pw)
{
	if (TPM_RC_SUCCESS == tpm2_nv_readlock(TPM2D_FDE_NV_HANDLE, fde_pw))
		fde_state = FDE_KEY_ACCESS_LOCKED;
	return fde_state;
}

nvmcrypt_fde_state_t
nvmcrypt_dm_reset(const char *hierarchy_pw)
{
	if (TPM_RC_SUCCESS ==
	    tpm2_nv_undefinespace(TPM2D_KEY_HIERARCHY, TPM2D_FDE_NV_HANDLE, hierarchy_pw))
		fde_state = FDE_RESET;
	return fde_state;
}

void
nvmcrypt_init(bool use_secure_boot_policy)
{
	secure_boot = use_secure_boot_policy;

	if (use_secure_boot_policy) {
		if (TPM_RC_SUCCESS != nvmcrypt_create_policy())
			FATAL("Cannot setup nvmcrypt policy!");
	}
}
