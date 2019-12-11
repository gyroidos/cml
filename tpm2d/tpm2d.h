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

#include <ibmtss/tss.h>

#include <stdbool.h>

//#define TPM2D_ASYM_ALGORITHM		TPM_ALG_ECC
#define TPM2D_ASYM_ALGORITHM TPM_ALG_RSA
#define TPM2D_CURVE_ID TPM_ECC_NIST_P256
#define TPM2D_HASH_ALGORITHM TPM_ALG_SHA256
//#define TPM2D_HASH_ALGORITHM		TPM_ALG_SHA1
#define TPM2D_DIGEST_SIZE 32
//#define TPM2D_DIGEST_SIZE		20
#define TPM2D_SYM_SESSION_ALGORITHM TPM_ALG_AES

#define TPM2D_KEY_HIERARCHY TPM_RH_OWNER

#define TPM2D_FDE_NV_HANDLE 0x01000000

#ifndef TPM2D_NVMCRYPT_ONLY

#define TPM2D_PLATFORM_KEY_PERSIST_HANDLE 0x81800000
#define TPM2D_STORAGE_KEY_PERSIST_HANDLE 0x81000000
#define TPM2D_ENDORSEMENT_KEY_PERSIST_HANDLE 0x81010000

typedef struct tpm2d_quote {
	TPM_ALG_ID halg_id;
	size_t quoted_size;
	uint8_t *quoted_value;
	size_t signature_size;
	uint8_t *signature_value;
} tpm2d_quote_t;

#endif // ifndef TPM2D_NVMCRYPT_ONLY

typedef enum tpm2d_key_type {
	TPM2D_KEY_TYPE_STORAGE_U = 1,
	TPM2D_KEY_TYPE_STORAGE_R,
	TPM2D_KEY_TYPE_SIGNING_U,
	TPM2D_KEY_TYPE_SIGNING_R,
	TPM2D_KEY_TYPE_SIGNING_EK
} tpm2d_key_type_t;

typedef struct tpm2d_pcr {
	size_t pcr_size;
	TPM_ALG_ID halg_id;
	uint8_t *pcr_value;
} tpm2d_pcr_t;

/*****************************************************************************/
void
tpm2d_exit(void);

TPMI_DH_OBJECT
tpm2d_get_salt_key_handle(void);

void
tss2_init(void);

void
tss2_destroy(void);

/**
 * Helper function to convert a binary buffer to an hex string
 *
 * This function allocates a new buffer containing the
 * resulting hex representation containing a terminating '\0'
 * of the binary buffer.
 *
 * @param bin binary buffer
 * @param length of the binary buffer
 */
char *
convert_bin_to_hex_new(const uint8_t *bin, int length);

/**
 * Helper function to convert a hex string into binary
 *
 * This function allocates a new buffer containing the
 * resulting binary representation of the string.
 *
 * @param hex_str buffer containing the hex string representation
 * @param out_length in this pointer the size of result is returned
 */
uint8_t *
convert_hex_to_bin_new(const char *hex_str, int *out_length);

/**
 * Function to powerup the simulator
 *
 * This function only may used for simulator. On a real TPM this
 * is done in hardware and would fail.
 */
TPM_RC
tpm2_powerup(void);

/**
 * Funtion to startup the TPM.
 *
 * This function is only needed for simulator. In case of a real
 * TPM the BIOS/UEFI has already started the TPM.
 *
 * @param startup_type type value for startup
 */
TPM_RC
tpm2_startup(TPM_SU startup_type);

/**
 * Funtion to check if TPM is usable.
 */
TPM_RC
tpm2_selftest(void);

/**
 * Function which clears the complete state of the TPM
 *
 * This function can be used to do a factory reset of the TPM,
 * it uses the LOCKOUT hierarchy.
 *
 * @param lockout_pwd passord for the lockout handle
 */
TPM_RC
tpm2_clear(const char *lockout_pwd);

/**
 * Funtion to reset the DA failed counter
 *
 * @param lockout_pwd passord for the lockout handle
 */
TPM_RC
tpm2_dictionaryattacklockreset(const char *lockout_pwd);

/**
 * Function to generate the primary key of an hierarchy
 */
TPM_RC
tpm2_createprimary_asym(TPMI_RH_HIERARCHY hierachy, tpm2d_key_type_t key_type,
			const char *hierachy_pwd, const char *key_pwd,
			const char *file_name_pub_key, uint32_t *out_handle);

/**
 * Function to flush loaded objects out of the transient memory of the TPM
 */
TPM_RC
tpm2_flushcontext(TPMI_DH_CONTEXT handle);

#ifndef TPM2D_NVMCRYPT_ONLY
/**
 * Creates an asymmetric key as part of the hierarchy designated by the parent handle
 * If not null, this function ensure to persist the TPM-protected key blobs in
 * file_name_priv/public_key for the private/public key, and as a blob loadable by
 * the openssl tpm engine designated by file_name_tss_key
 */
TPM_RC
tpm2_create_asym(TPMI_DH_OBJECT parent_handle, tpm2d_key_type_t key_type, uint32_t object_vals,
		 const char *parent_pwd, const char *key_pwd, const char *file_name_priv_key,
		 const char *file_name_pub_key, const char *file_name_tss_key);

TPM_RC
tpm2_load(TPMI_DH_OBJECT parent_handle, const char *parent_pwd, const char *file_name_priv_key,
	  const char *file_name_pub_key, uint32_t *out_handle);

TPMI_DH_OBJECT
tpm2d_get_as_key_handle(void);

void
tpm2d_flush_as_key_handle(void);

TPM_RC
tpm2_pcrextend(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg, const uint8_t *data, size_t data_len);

tpm2d_quote_t *
tpm2_quote_new(TPMI_DH_PCR pcr_indices, TPMI_DH_OBJECT sig_key_handle, const char *sig_key_pwd,
	       uint8_t *qualifying_data, size_t qualifying_data_len);

void
tpm2_quote_free(tpm2d_quote_t *quote);

TPM_RC
tpm2_evictcontrol(TPMI_RH_HIERARCHY auth, char *auth_pwd, TPMI_DH_OBJECT obj_handle,
		  TPMI_DH_PERSISTENT persist_handle);

TPM_RC
tpm2_rsaencrypt(TPMI_DH_OBJECT key_handle, uint8_t *in_buffer, size_t in_length,
		uint8_t *out_buffer, size_t *out_length);

TPM_RC
tpm2_rsadecrypt(TPMI_DH_OBJECT key_handle, const char *key_pwd, uint8_t *in_buffer,
		size_t in_length, uint8_t *out_buffer, size_t *out_length);
#endif // ndef TPM2D_NVMCRYPT_ONLY

TPM_RC
tpm2_hierarchychangeauth(TPMI_RH_HIERARCHY hierarchy, const char *old_pwd, const char *new_pwd);

tpm2d_pcr_t *
tpm2_pcrread_new(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg);

void
tpm2_pcrread_free(tpm2d_pcr_t *pcr);

uint8_t *
tpm2_getrandom_new(size_t rand_length);

size_t
tpm2_nv_get_data_size(TPMI_RH_NV_INDEX nv_index_handle);

TPM_RC
tpm2_nv_definespace(TPMI_RH_HIERARCHY hierarchy, TPMI_RH_NV_INDEX nv_index_handle, size_t nv_size,
		    const char *hierarchy_pwd, const char *nv_pwd, uint8_t *policy_digest);
TPM_RC
tpm2_nv_undefinespace(TPMI_RH_HIERARCHY hierarchy, TPMI_RH_NV_INDEX nv_index_handle,
		      const char *hierarchy_pwd);

TPM_RC
tpm2_nv_write(TPMI_RH_NV_INDEX nv_index_handle, const char *nv_pwd, uint8_t *data,
	      size_t data_length);

TPM_RC
tpm2_nv_read(TPMI_SH_POLICY se_handle, TPMI_RH_NV_INDEX nv_index_handle, const char *nv_pwd,
	     uint8_t *out_buffer, size_t *out_length);

TPM_RC
tpm2_nv_readlock(TPMI_RH_NV_INDEX nv_index_handle, const char *nv_pwd);

TPM_RC
tpm2_startauthsession(TPM_SE session_type, TPMI_SH_AUTH_SESSION *out_session_handle,
		      TPMI_DH_OBJECT bind_handle, const char *bind_pwd);
TPM_RC
tpm2_policyauthvalue(TPMI_SH_POLICY se_handle);

TPM_RC
tpm2_policypcr(TPMI_SH_POLICY se_handle, uint32_t pcr_mask, tpm2d_pcr_t *pcrs[], size_t pcrs_size);

TPM_RC
tpm2_policygetdigest(TPMI_SH_POLICY se_handle, uint8_t *out_digest, size_t out_digest_len);

TPM_RC
tpm2_policyrestart(TPMI_SH_POLICY se_handle);

#endif // TPM2D_H
