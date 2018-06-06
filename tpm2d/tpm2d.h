/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
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

#ifndef TPM2D_H
#define TPM2D_H

#include <tss2/tss.h>

#define TPM2D_KEY_HIERARCHY TPM_RH_OWNER
#define TPM2D_PLATFORM_STORAGE_KEY_PERSIST_HANDLE 0x81800000
#define TPM2D_OWNER_STORAGE_KEY_PERSIST_HANDLE 0x81000000
#define TPM2D_PRIMARY_STORAGE_KEY_PW "primary"
#define TPM2D_ATTESTATION_KEY_PW "sig"

#define TPM2D_BASE_DIR "/data/cml/tpm2d"
#define TPM2D_TOKEN_DIR "tokens"
#define TPM2D_SESSION_DIR "session"
#define TPM2D_ATTESTATION_PRIV_FILE	TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_priv.bin"
#define TPM2D_ATTESTATION_PUB_FILE	TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_pub.bin"
#define TPM2D_PS_PUB_FILE		TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/ps_pub.bin"

#define TPM2D_ASYM_ALGORITHM	TPM_ALG_RSA
#define TPM2D_CURVE_ID		TPM_ECC_NONE
#define TPM2D_HASH_ALGORITHM 	TPM_ALG_SHA256

typedef enum tpm2d_key_type {
	TPM2D_KEY_TYPE_STORAGE = 1,
	TPM2D_KEY_TYPE_SIGNING_U,
	TPM2D_KEY_TYPE_SIGNING_R
} tpm2d_key_type_t;

typedef struct tpm2d_pcr_strings {
	char *halg_str;
	char *pcr_str;
} tpm2d_pcr_strings_t;

typedef struct tpm2d_quote_strings {
	char *halg_str;
	char *quoted_str;
	char *signature_str;
} tpm2d_quote_strings_t;

TPM_RC
tpm2_powerup(void);

TPM_RC
tpm2_startup(TPM_SU startup_type);

TPM_RC
tpm2_selftest(void);

TPM_RC
tpm2_createprimary_asym(TPMI_RH_HIERARCHY hierachy, tpm2d_key_type_t key_type,
		const char *hierachy_pwd, const char *key_pwd,
		const char *file_name_pub_key, uint32_t *out_handle);

TPM_RC
tpm2_create_asym(TPMI_DH_OBJECT parent_handle, tpm2d_key_type_t key_type,
		uint32_t object_vals, const char *parent_pwd, const char *key_pwd,
		const char *file_name_priv_key, const char *file_name_pub_key);

TPM_RC
tpm2_load(TPMI_DH_OBJECT parent_handle, const char *parent_pwd,
		const char *file_name_priv_key, const char *file_name_pub_key,
		uint32_t *out_handle);

TPM_RC
tpm2_pcrextend(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg, const char *data);

tpm2d_pcr_strings_t *
tpm2_pcrread_new(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg);

void
tpm2_pcrread_free(tpm2d_pcr_strings_t *pcr_strings);

tpm2d_quote_strings_t *
tpm2_quote_new(TPMI_DH_PCR pcr_indices, TPMI_DH_OBJECT sig_key_handle,
			const char *sig_key_pwd, const char *qualifying_data);

void
tpm2_quote_free(tpm2d_quote_strings_t *quote_strings);

char *
tpm2_read_file_to_hex_string_new(const char *file_name);

#endif // TPM2D_H

TPM_RC
tpm2_evictcontrol(TPMI_RH_HIERARCHY auth, char* auth_pwd, TPMI_DH_OBJECT obj_handle,
						 TPMI_DH_PERSISTENT persist_handle);
