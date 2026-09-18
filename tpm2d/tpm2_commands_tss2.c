/*
 * This file is part of GyroidOS
 * Copyright(c) 2026 Fraunhofer AISEC
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

#include "tpm2d_tss2.h"

#include "common/mem.h"
#include "common/macro.h"
#include "common/file.h"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>

#include "tpm2d_write_openssl_tss2.h"

#include <openssl/evp.h>

static ESYS_CONTEXT *esys_context = NULL;

// TODO: free msg?
#define TSS_TPM_CMD_ERROR(rc, cc_string)                                                           \
	{                                                                                          \
		const char *msg = Tss2_RC_Decode(rc);                                              \
		ERROR("%s failed, rc %08x: %s\n", cc_string, rc, msg);                             \
	}

/************************************************************************************/

void
tss2_init(void)
{
	int ret;

	if (esys_context) {
		INFO("Context already exists.");
		return;
	}

	if (TPM2_RC_SUCCESS != (ret = Esys_Initialize(&esys_context, NULL, NULL)))
		FATAL("Cannot create esys context error code: %08x", ret);

	// TODO: trace level?
	// TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
}

void
tss2_destroy(void)
{
	IF_NULL_RETURN_ERROR(esys_context);

	Esys_Free(esys_context);

	esys_context = NULL;
}

#ifndef TPM2D_NVMCRYPT_ONLY
static uint8_t *
tpm2d_marshal_structure_tpmt_signature_new(const TPMT_SIGNATURE *structure, size_t *size)
{
	size_t buffer_size = sizeof(TPMT_SIGNATURE);
	uint8_t *buffer = mem_alloc0(buffer_size);
	size_t offset = 0;

	if (TPM2_RC_SUCCESS !=
	    Tss2_MU_TPMT_SIGNATURE_Marshal(structure, buffer, buffer_size, &offset)) {
		WARN("no data written to stream!");
		*size = 0;
		mem_free0(buffer);
		return NULL;
	}
	*size = offset;
	INFO("marshal written size %zu, *size %zu", offset, *size);
	return buffer;
}
#endif

static TPM2_RC
tss_tpm2b_create(TPM2B_DATA *target, uint8_t *buffer, uint16_t size, uint16_t target_size)
{
	if (size > target_size) {
		return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
	}

	target->size = size;
	if (size != 0) {
		memmove(target->buffer, buffer, size);
	}

	return TPM2_RC_SUCCESS;
}

static TPM2_RC
tss_tpm2b_auth_strcpy(TPM2B_AUTH *target, const char *source, uint16_t target_size)
{
	size_t length;
	uint16_t length16;

	if (source == NULL) {
		target->size = 0;
		return TPM2_RC_SUCCESS;
	}

	length = strlen(source);
	if (length > 0xffff) { // overflow
		return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
	}

	length16 = (uint16_t)length;
	if (length16 > target_size) {
		return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
	}

	target->size = length16;
	memcpy(target->buffer, source, length);

	return TPM2_RC_SUCCESS;
}

static TPM2_RC
esys_set_auth_pw(const char *password, ESYS_TR handle)
{
	TPM2_RC rc;
	TPM2B_AUTH auth_value = { 0 };
	rc = tss_tpm2b_auth_strcpy(&auth_value, password, sizeof(auth_value.buffer));
	IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);

	rc = Esys_TR_SetAuth(esys_context, handle, &auth_value);

	return rc;
}

// prints the buffer in the same format as ibmtss's TSS_PrintAll function
static void
tss_print_all(const char *string, const unsigned char *buff, uint32_t length)
{
	if (buff == NULL) {
		printf(" %s null\n", string);
		return;
	}

	printf(" %s length %u\n ", string, length);
	for (uint32_t i = 0; i < length; i++) {
		if (i != 0 && (i % 16) == 0) {
			printf("\n ");
		}
		printf("%.2x ", buff[i]);
	}
	printf("\n");
}

static TPM2_RC
tss_file_write_structure_tpm2b_public(const TPM2B_PUBLIC *src, const char *file_name)
{
	TPM2_RC rc;
	uint8_t buffer[sizeof(TPM2B_PUBLIC)];
	size_t offset = 0;

	rc = Tss2_MU_TPM2B_PUBLIC_Marshal(src, buffer, sizeof(buffer), &offset);
	IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);

	if (file_write(file_name, (char *)buffer, offset) != (ssize_t)offset) {
		return TSS2_BASE_RC_IO_ERROR;
	}

	return rc;
}

static TPM2_RC
tss_file_read_structure_flag_tpm2b_public(TPM2B_PUBLIC *dest, bool flag, const char *file_name)
{
	TPM2_RC rc;
	int bytes_read;
	uint8_t buffer[sizeof(TPM2B_PUBLIC)];
	size_t offset = 0;

	bytes_read = file_read(file_name, (char *)buffer, sizeof(buffer));
	if (bytes_read < 0) {
		return TSS2_BASE_RC_IO_ERROR;
	}

	rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(buffer, (size_t)bytes_read, &offset, dest);
	IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);

	// if flag is false, we treat remaining bytes as error
	if (flag == false && offset != (size_t)bytes_read) {
		return TSS2_BASE_RC_MALFORMED_RESPONSE;
	}

	return TPM2_RC_SUCCESS;
}

static TPM2_RC
tss_file_write_structure_tpm2b_private(const TPM2B_PRIVATE *src, const char *file_name)
{
	TPM2_RC rc;
	uint8_t buffer[sizeof(TPM2B_PRIVATE)];
	size_t offset = 0;

	rc = Tss2_MU_TPM2B_PRIVATE_Marshal(src, buffer, sizeof(buffer), &offset);
	IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);

	if (file_write(file_name, (char *)buffer, offset) != (ssize_t)offset) {
		return TSS2_BASE_RC_IO_ERROR;
	}

	return rc;
}

static TPM2_RC
tss_file_read_structure_tpm2b_private(TPM2B_PRIVATE *dest, const char *file_name)
{
	TPM2_RC rc;
	int bytes_read;
	uint8_t buffer[sizeof(TPM2B_PRIVATE)];
	size_t offset = 0;

	bytes_read = file_read(file_name, (char *)buffer, sizeof(buffer));
	if (bytes_read < 0) {
		return TSS2_BASE_RC_IO_ERROR;
	}

	rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(buffer, (size_t)bytes_read, &offset, dest);

	return rc;
}

/************************************************************************************/

TPM2_RC
tpm2_powerup(void)
{
	// TODO: tss2 does not expose this functionality but it is only used for simulations anyways
	return TSS2_BASE_RC_NOT_IMPLEMENTED;
}

TPM2_RC
tpm2_startup(TPM2_SU startup_type)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	rc = Esys_Startup(esys_context, startup_type);

	if (TPM2_RC_INITIALIZE == rc) {
		WARN("Already initialized, returing Success.");
		return TPM2_RC_SUCCESS;
	}
	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_StartUp");

	return rc;
}

TPM2_RC
tpm2_selftest(void)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	rc = Esys_SelfTest(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_YES);

	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_SelfTest");

	return rc;
}

TPM2_RC
tpm2_clear(const char *lockout_pwd)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	rc = esys_set_auth_pw(lockout_pwd, ESYS_TR_RH_LOCKOUT);
	IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);

	rc = Esys_Clear(esys_context, ESYS_TR_RH_LOCKOUT, ESYS_TR_PASSWORD, ESYS_TR_NONE,
			ESYS_TR_NONE);

	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_Clear");

	return rc;
}

TPM2_RC
tpm2_dictionaryattacklockreset(const char *lockout_pwd)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	rc = esys_set_auth_pw(lockout_pwd, ESYS_TR_RH_LOCKOUT);
	IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);

	rc = Esys_DictionaryAttackLockReset(esys_context, ESYS_TR_RH_LOCKOUT, ESYS_TR_PASSWORD,
					    ESYS_TR_NONE, ESYS_TR_NONE);

	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_DictionaryAttackLockReset");

	return rc;
}

TPM2_RC
tpm2_startauthsession(TPM2_SE session_type, TPMI_SH_AUTH_SESSION *out_session_handle,
		      TPMI_DH_OBJECT bind_handle, const char *bind_pwd)
{
	TPM2_RC rc;
	ESYS_TR tpmKey;
	ESYS_TR bind;
	TPM2_SE sessionType;
	TPMT_SYM_DEF symmetric;
	TPMI_ALG_HASH authHash;
	ESYS_TR sessionHandle;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	sessionType = session_type;

	/* bind password */
	bind = bind_handle;
	if (bind != ESYS_TR_RH_NULL) {
		rc = esys_set_auth_pw(bind_pwd, bind);
		IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);
	}

	/* salt key default NULL*/
	tpmKey = tpm2d_get_salt_key_handle();

	/* parameter encryption */
	symmetric.algorithm = TPM2D_SYM_SESSION_ALGORITHM;
	if (symmetric.algorithm == TPM2_ALG_XOR) {
		/* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */
		/* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */
		symmetric.keyBits.exclusiveOr = TPM2D_HASH_ALGORITHM;
		/* Table 126 - Definition of TPMU_SYM_MODE Union */
		symmetric.mode.sym = TPM2_ALG_NULL;
	} else { /* TPM_ALG_AES */
		/* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */
		/* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */
		symmetric.keyBits.aes = 128;
		/* Table 126 - Definition of TPMU_SYM_MODE Union */
		/* Table 63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type */
		symmetric.mode.aes = TPM2_ALG_CFB;
	}

	/* authHash */
	authHash = TPM2D_HASH_ALGORITHM;

	rc = Esys_StartAuthSession(esys_context, tpmKey, bind, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, /* nonceCaller (not required) */ NULL, sessionType,
				   &symmetric, authHash, &sessionHandle);

	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_StartAuthSession");
		return rc;
	}

	// return handle to just created object
	*out_session_handle = sessionHandle;

	return rc;
}

TPM2_RC
tpm2_policyauthvalue(TPMI_SH_POLICY se_handle)
{
	TPM2_RC rc;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	rc = Esys_PolicyAuthValue(esys_context, se_handle, ESYS_TR_NONE, ESYS_TR_NONE,
				  ESYS_TR_NONE);

	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_PolicyAuthValue");

	return rc;
}

TPM2_RC
tpm2_policypcr(TPMI_SH_AUTH_SESSION se_handle, uint32_t pcr_mask, tpm2d_pcr_t *pcrs[],
	       size_t pcrs_size)
{
	TPM2_RC rc = TPM2_RC_HASH;
	ESYS_TR policySession;
	TPM2B_DIGEST pcrDigest;
	TPML_PCR_SELECTION in_pcrs;

	EVP_MD_CTX *mdctx = NULL;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	TPM2_ALG_ID hash_alg = TPM2D_HASH_ALGORITHM;

	pcrDigest.size = 0;

	policySession = se_handle;
	/* Table 102 - Definition of TPML_PCR_SELECTION Structure */
	in_pcrs.count = 1; // use default hash only
	/* Table 85 - Definition of TPMS_PCR_SELECTION Structure - pcrSelections */
	in_pcrs.pcrSelections[0].hash = hash_alg;
	in_pcrs.pcrSelections[0].sizeofSelect = 3;
	in_pcrs.pcrSelections[0].pcrSelect[0] = (pcr_mask >> 0) & 0xff;
	in_pcrs.pcrSelections[0].pcrSelect[1] = (pcr_mask >> 8) & 0xff;
	in_pcrs.pcrSelections[0].pcrSelect[2] = (pcr_mask >> 16) & 0xff;

	if (pcrs_size > 0) {
		const EVP_MD *md;
		unsigned int md_size;

		switch (hash_alg) {
		case TPM2_ALG_SHA1:
			md = EVP_sha1();
			break;
		case TPM2_ALG_SHA256:
			md = EVP_sha256();
			break;
		case TPM2_ALG_SHA384:
			md = EVP_sha384();
			break;
		default:
			return TPM2_RC_HASH;
		}

		mdctx = EVP_MD_CTX_new();
		IF_FALSE_GOTO(EVP_DigestInit(mdctx, md), out);
		for (size_t i = 0; i < pcrs_size; ++i) {
			IF_FALSE_GOTO(EVP_DigestUpdate(mdctx, pcrs[i]->pcr_value,
						       pcrs[i]->pcr_size),
				      out);
			INFO("pcrs[%zu]: size: %zu", i, pcrs[i]->pcr_size);
		}
		IF_FALSE_GOTO(EVP_DigestFinal(mdctx, pcrDigest.buffer, &md_size), out);
		pcrDigest.size = md_size;

		tss_print_all("PCR digest: ", pcrDigest.buffer, pcrDigest.size);
	}

	rc = Esys_PolicyPCR(esys_context, policySession, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			    &pcrDigest, &in_pcrs);

	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_PolicyPCR");

out:
	if (mdctx)
		EVP_MD_CTX_free(mdctx);

	return rc;
}

TPM2_RC
tpm2_policygetdigest(TPMI_SH_POLICY se_handle, uint8_t *out_digest, size_t out_digest_len)
{
	TPM2_RC rc;
	ESYS_TR policySession;
	TPM2B_DIGEST *policyDigest = NULL;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	policySession = se_handle;

	rc = Esys_PolicyGetDigest(esys_context, policySession, ESYS_TR_NONE, ESYS_TR_NONE,
				  ESYS_TR_NONE, &policyDigest);

	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_PolicyGetDigest");
		goto err;
	}

	tss_print_all("policy digest: ", policyDigest->buffer, policyDigest->size);

	//rc = TSS_File_WriteBinaryFile(out.policyDigest.t.buffer, out.policyDigest.t.size, out_file);

	if (out_digest_len < policyDigest->size) {
		ERROR("Digest size %d exceeds outputbuffer of size %zu\n", policyDigest->size,
		      out_digest_len);
		rc = TSS2_BASE_RC_INSUFFICIENT_BUFFER;
		goto err;
	}

	memcpy(out_digest, policyDigest->buffer, policyDigest->size);
	out_digest_len = policyDigest->size;

err:
	Esys_Free(policyDigest);
	return rc;
}

TPM2_RC
tpm2_policyrestart(TPMI_SH_POLICY se_handle)
{
	TPM2_RC rc;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	rc = Esys_PolicyRestart(esys_context, se_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);

	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_PolicyRestart");

	return rc;
}

TPM2_RC
tpm2_flushcontext(TPMI_DH_CONTEXT handle)
{
	TPM2_RC rc;

	rc = Esys_FlushContext(esys_context, handle);

	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_FlushContext");

	return rc;
}

static TPM2_RC
tpm2_fill_rsa_details(TPMT_PUBLIC *out_public_area, tpm2d_key_type_t key_type)
{
	ASSERT(out_public_area);

	out_public_area->parameters.rsaDetail.keyBits = 2048;
	out_public_area->parameters.rsaDetail.exponent = 0;

	switch (key_type) {
	case TPM2D_KEY_TYPE_STORAGE_U:
		out_public_area->parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
		out_public_area->parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
		break;
	case TPM2D_KEY_TYPE_STORAGE_R:
		out_public_area->parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
		out_public_area->parameters.rsaDetail.symmetric.keyBits.aes = 128;
		out_public_area->parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
		out_public_area->parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
		break;
	case TPM2D_KEY_TYPE_SIGNING_U:
		out_public_area->parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
		out_public_area->parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
		break;
	case TPM2D_KEY_TYPE_SIGNING_R:
	case TPM2D_KEY_TYPE_SIGNING_EK:
		out_public_area->parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
		out_public_area->parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
		out_public_area->parameters.rsaDetail.scheme.details.rsassa.hashAlg =
			TPM2D_HASH_ALGORITHM;
		break;
	default:
		ERROR("Keytype not supported for rsa keys!");
		return TPM2_RC_VALUE;
		break;
	}

	return TPM2_RC_SUCCESS;
}

static TPM2_RC
tpm2_fill_ecc_details(TPMT_PUBLIC *out_public_area, tpm2d_key_type_t key_type)
{
	ASSERT(out_public_area);

	switch (key_type) {
	case TPM2D_KEY_TYPE_SIGNING_U:
		// non-storage keys require TPM_ALG_NULL set for the symmetric algorithm
		out_public_area->parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
		out_public_area->parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
		out_public_area->parameters.eccDetail.curveID = TPM2D_CURVE_ID;
		out_public_area->parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
		break;
	case TPM2D_KEY_TYPE_SIGNING_R:
	case TPM2D_KEY_TYPE_SIGNING_EK:
		// non-storage keys require TPM_ALG_NULL set for the symmetric algorithm
		out_public_area->parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;

		out_public_area->parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
		out_public_area->parameters.eccDetail.scheme.details.ecdsa.hashAlg =
			TPM2D_HASH_ALGORITHM;
		out_public_area->parameters.eccDetail.kdf.details.mgf1.hashAlg =
			TPM2D_HASH_ALGORITHM;
		out_public_area->parameters.eccDetail.curveID = TPM2D_CURVE_ID;
		out_public_area->parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
		break;
	case TPM2D_KEY_TYPE_STORAGE_U:
	case TPM2D_KEY_TYPE_STORAGE_R:
		out_public_area->parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
		out_public_area->parameters.eccDetail.symmetric.keyBits.aes = 128;
		out_public_area->parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
		out_public_area->parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
		out_public_area->parameters.eccDetail.scheme.details.anySig.hashAlg = 0;
		out_public_area->parameters.eccDetail.curveID = TPM2D_CURVE_ID;
		out_public_area->parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
		out_public_area->parameters.eccDetail.kdf.details.mgf1.hashAlg = 0;
		break;
	default:
		ERROR("Keytype not supported for ecc keys!");
		return TPM2_RC_VALUE;
		break;
	}

	return TPM2_RC_SUCCESS;
}

// default IWG policy for EK primary key
static uint8_t ek_iwg_policy[] = { 0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
				   0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
				   0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA };

static TPM2_RC
tpm2_public_area_helper(TPMT_PUBLIC *out_public_area, TPMA_OBJECT object_attrs,
			tpm2d_key_type_t key_type)
{
	ASSERT(out_public_area);

	TPM2_RC rc = TPM2_RC_SUCCESS;

	out_public_area->type = TPM2D_ASYM_ALGORITHM;
	out_public_area->nameAlg = TPM2D_HASH_ALGORITHM;
	out_public_area->objectAttributes = object_attrs;

	out_public_area->objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	out_public_area->objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
	out_public_area->objectAttributes &= ~TPMA_OBJECT_ADMINWITHPOLICY;

	// set default empty policy
	out_public_area->authPolicy.size = 0;

	switch (key_type) {
	case TPM2D_KEY_TYPE_STORAGE_U:
		// TODO needed both signing (for tpm2d) and decryption (for openssl),
		// found no suitable keytype, so I toggled the flag (question is whether to create a new keytype)
		out_public_area->objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
		out_public_area->objectAttributes |= TPMA_OBJECT_DECRYPT;
		out_public_area->objectAttributes &= ~TPMA_OBJECT_RESTRICTED;
		break;
	case TPM2D_KEY_TYPE_STORAGE_R:
		out_public_area->objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;
		out_public_area->objectAttributes |= TPMA_OBJECT_DECRYPT;
		out_public_area->objectAttributes |= TPMA_OBJECT_RESTRICTED;
		break;
	case TPM2D_KEY_TYPE_SIGNING_U:
		out_public_area->objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
		out_public_area->objectAttributes &= ~TPMA_OBJECT_DECRYPT;
		out_public_area->objectAttributes &= ~TPMA_OBJECT_RESTRICTED;
		break;
	case TPM2D_KEY_TYPE_SIGNING_EK:
		out_public_area->objectAttributes |= TPMA_OBJECT_ADMINWITHPOLICY;
		out_public_area->authPolicy.size = sizeof(ek_iwg_policy);
		memcpy(&out_public_area->authPolicy.buffer, ek_iwg_policy, sizeof(ek_iwg_policy));
	// fallthrough
	case TPM2D_KEY_TYPE_SIGNING_R:
		out_public_area->objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
		out_public_area->objectAttributes &= ~TPMA_OBJECT_DECRYPT;
		out_public_area->objectAttributes |= TPMA_OBJECT_RESTRICTED;
		break;
	default:
		ERROR("Only support creation of signing and storage keys!");
		return TPM2_RC_VALUE;
		break;
	}

	if (TPM2D_ASYM_ALGORITHM == TPM2_ALG_RSA) {
		out_public_area->unique.rsa.size = 0;
		rc = tpm2_fill_rsa_details(out_public_area, key_type);
	} else {
		// TPM2D_ASYM_ALGORITHM == TPM_ALG_ECC
		out_public_area->unique.ecc.x.size = 0;
		out_public_area->unique.ecc.y.size = 0;
		rc = tpm2_fill_ecc_details(out_public_area, key_type);
	}

	return rc;
}

TPM2_RC
tpm2_createprimary_asym(TPMI_RH_HIERARCHY hierachy, tpm2d_key_type_t key_type,
			const char *hierachy_pwd, const char *key_pwd,
			const char *file_name_pub_key, uint32_t *out_handle)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	ESYS_TR primaryHandle;
	TPM2B_SENSITIVE_CREATE inSensitive;
	TPM2B_PUBLIC inPublic;
	TPM2B_DATA outsideInfo;
	TPML_PCR_SELECTION creationPCR;
	TPMA_OBJECT object_attrs;
	ESYS_TR objectHandle;
	TPM2B_PUBLIC *outPublic = NULL;
	TPM2B_CREATION_DATA *creationData = NULL;
	TPM2B_DIGEST *creationHash = NULL;
	TPMT_TK_CREATION *creationTicket = NULL;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	// set some default key attr overwritten by tpm2_public_area helper
	// depending on key_type
	object_attrs = 0;
	object_attrs |= TPMA_OBJECT_NODA;
	object_attrs |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	object_attrs |= TPMA_OBJECT_USERWITHAUTH;
	object_attrs &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	object_attrs |= TPMA_OBJECT_RESTRICTED;
	object_attrs |= TPMA_OBJECT_DECRYPT;
	object_attrs &= ~TPMA_OBJECT_SIGN_ENCRYPT;
	object_attrs |= TPMA_OBJECT_FIXEDTPM;
	object_attrs |= TPMA_OBJECT_FIXEDPARENT;

	primaryHandle = hierachy;

	// Table 134 - Definition of TPM2B_SENSITIVE_CREATE inSensitive
	if (key_pwd == NULL) {
		inSensitive.sensitive.userAuth.size = 0;
	} else if (TPM2_RC_SUCCESS != (rc = tss_tpm2b_auth_strcpy(&inSensitive.sensitive.userAuth,
								  key_pwd, sizeof(TPMU_HA))))
		return rc;

	inSensitive.sensitive.data.size = 0;

	// fill in TPM2B_PUBLIC (and overwrite object_attrs)
	if (TPM2_RC_SUCCESS !=
	    (rc = tpm2_public_area_helper(&inPublic.publicArea, object_attrs, key_type)))
		return rc;

	// TPM2B_DATA outsideInfo
	outsideInfo.size = 0;
	// Table 102 - TPML_PCR_SELECTION creationPCR
	creationPCR.count = 0;

	rc = esys_set_auth_pw(hierachy_pwd, primaryHandle);
	IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);
	rc = Esys_CreatePrimary(esys_context, primaryHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
				ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
				&objectHandle, &outPublic, &creationData, &creationHash,
				&creationTicket);

	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_CreatePrimary");
		goto err;
	}

	// save the public key
	if (file_name_pub_key) {
		rc = tss_file_write_structure_tpm2b_public(outPublic, file_name_pub_key);
	}

	// return handle to just created object
	*out_handle = objectHandle;

err:
	Esys_Free(outPublic);
	Esys_Free(creationData);
	Esys_Free(creationHash);
	Esys_Free(creationTicket);
	return rc;
}

#ifndef TPM2D_NVMCRYPT_ONLY
TPM2_RC
tpm2_create_asym(TPMI_DH_OBJECT parent_handle, tpm2d_key_type_t key_type, uint32_t object_vals,
		 const char *parent_pwd, const char *key_pwd, const char *file_name_priv_key,
		 const char *file_name_pub_key, const char *file_name_tss_key)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	ESYS_TR parentHandle;
	TPM2B_SENSITIVE_CREATE inSensitive;
	TPM2B_PUBLIC inPublic;
	TPM2B_DATA outsideInfo;
	TPML_PCR_SELECTION creationPCR;
	TPM2B_PRIVATE *outPrivate = NULL;
	TPM2B_PUBLIC *outPublic = NULL;
	TPM2B_CREATION_DATA *creationData = NULL;
	TPM2B_DIGEST *creationHash = NULL;
	TPMT_TK_CREATION *creationTicket = NULL;
	TPMA_OBJECT object_attrs;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	parentHandle = parent_handle;
	object_attrs = object_vals;

	// Table 134 - Definition of TPM2B_SENSITIVE_CREATE inSensitive
	if (key_pwd == NULL) {
		inSensitive.sensitive.userAuth.size = 0;
	} else if (TPM2_RC_SUCCESS != (rc = tss_tpm2b_auth_strcpy(&inSensitive.sensitive.userAuth,
								  key_pwd, sizeof(TPMU_HA))))
		return rc;

	inSensitive.sensitive.data.size = 0;

	// fill in TPM2B_PUBLIC
	if (TPM2_RC_SUCCESS !=
	    (rc = tpm2_public_area_helper(&inPublic.publicArea, object_attrs, key_type)))
		return rc;

	// TPM2B_DATA outsideInfo
	outsideInfo.size = 0;
	// Table 102 - TPML_PCR_SELECTION creationPCR
	creationPCR.count = 0;

	rc = esys_set_auth_pw(parent_pwd, parentHandle);
	IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);
	rc = Esys_Create(esys_context, parentHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			 &inSensitive, &inPublic, &outsideInfo, &creationPCR, &outPrivate,
			 &outPublic, &creationData, &creationHash, &creationTicket);

	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_Create");
		goto err;
	}

	// save the private key
	if (file_name_priv_key) {
		if (TPM2_RC_SUCCESS !=
		    (rc = tss_file_write_structure_tpm2b_private(outPrivate, file_name_priv_key))) {
			goto err;
		}
	}

	// save the public key
	if (file_name_pub_key) {
		rc = tss_file_write_structure_tpm2b_public(outPublic, file_name_pub_key);
	}

	if (file_name_tss_key) {
		BYTE pubkey[sizeof(TPM2B_PUBLIC)], privkey[sizeof(TPM2B_PRIVATE)];
		TPM2B_PUBLIC *pub = outPublic;
		TPM2B_PRIVATE *priv = outPrivate;
		uint16_t pubkey_len, privkey_len;
		size_t offset;

		offset = 0;
		rc = Tss2_MU_TPM2B_PUBLIC_Marshal(pub, pubkey, sizeof(pubkey), &offset);
		IF_TRUE_GOTO(rc != TPM2_RC_SUCCESS, err);
		pubkey_len = offset;

		offset = 0;
		rc = Tss2_MU_TPM2B_PRIVATE_Marshal(priv, privkey, sizeof(privkey), &offset);
		IF_TRUE_GOTO(rc != TPM2_RC_SUCCESS, err);
		privkey_len = offset;
		tpm2d_openssl_write_tpmfile(file_name_tss_key, pubkey, pubkey_len, privkey,
					    privkey_len, key_pwd == NULL, parent_handle, NULL);
	}

err:
	Esys_Free(outPrivate);
	Esys_Free(outPublic);
	Esys_Free(creationData);
	Esys_Free(creationHash);
	Esys_Free(creationTicket);
	return rc;
}

TPM2_RC
tpm2_load(TPMI_DH_OBJECT parent_handle, const char *parent_pwd, const char *file_name_priv_key,
	  const char *file_name_pub_key, uint32_t *out_handle)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	ESYS_TR parentHandle;
	TPM2B_PRIVATE inPrivate;
	TPM2B_PUBLIC inPublic;
	ESYS_TR objectHandle;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	parentHandle = parent_handle;

	if (TPM2_RC_SUCCESS !=
	    (rc = tss_file_read_structure_tpm2b_private(&inPrivate, file_name_priv_key)))
		return rc;

	if (TPM2_RC_SUCCESS !=
	    (rc = tss_file_read_structure_flag_tpm2b_public(&inPublic, false, file_name_pub_key)))
		return rc;

	rc = esys_set_auth_pw(parent_pwd, parentHandle);
	IF_TRUE_RETVAL(rc != TPM2_RC_SUCCESS, rc);
	rc = Esys_Load(esys_context, parentHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
		       &inPrivate, &inPublic, &objectHandle);

	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_Load");
		return rc;
	}

	// return handle to just created object
	*out_handle = objectHandle;

	return rc;
}

TPM2_RC
tpm2_pcrextend(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg, const uint8_t *data, size_t data_len)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	ESYS_TR pcrHandle;
	TPML_DIGEST_VALUES digests;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	if (data_len > sizeof(TPMU_HA)) {
		ERROR("Data length %zu exceeds hash size %zu!", data_len, sizeof(TPMU_HA));
		return EXIT_FAILURE;
	}

	pcrHandle = pcr_index;

	// extend one bank
	digests.count = 1;

	// pad and set data
	digests.digests[0].hashAlg = hash_alg;
	mem_memset((uint8_t *)&digests.digests[0].digest, 0, sizeof(TPMU_HA));
	memcpy((uint8_t *)&digests.digests[0].digest, data, data_len);

	rc = Esys_PCR_Extend(esys_context, pcrHandle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			     &digests);

	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_PCR_Extend");

	return rc;
}

tpm2d_quote_t *
tpm2_quote_new(uint8_t *pcr_bitmap, size_t size_pcr_bitmap, TPMI_DH_OBJECT sig_key_handle,
	       const char *sig_key_pwd, uint8_t *qualifying_data, size_t qualifying_data_len)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	ESYS_TR signHandle;
	TPM2B_DATA qualifyingData;
	TPMT_SIG_SCHEME inScheme;
	TPML_PCR_SELECTION PCRselect;
	TPM2B_ATTEST *quoted = NULL;
	TPMT_SIGNATURE *signature = NULL;
	TPMS_ATTEST tpms_attest;
	tpm2d_quote_t *quote = NULL;

	IF_NULL_RETVAL_ERROR(esys_context, NULL);

	if (size_pcr_bitmap > TPM2_PCR_SELECT_MAX) {
		ERROR("Exceeded maximum available PCR registers!");
		return NULL;
	}

	PCRselect.pcrSelections[0].sizeofSelect = size_pcr_bitmap;
	for (size_t i = 0; i < size_pcr_bitmap; i++) {
		PCRselect.pcrSelections[0].pcrSelect[i] = pcr_bitmap[i];
	}

	signHandle = sig_key_handle;
	if (TPM2D_ASYM_ALGORITHM == TPM2_ALG_RSA) {
		inScheme.scheme = TPM2_ALG_RSASSA;
		inScheme.details.rsassa.hashAlg = TPM2D_HASH_ALGORITHM;
	} else {
		// TPM2D_ASYM_ALGORITHM == TPM_ALG_ECC
		inScheme.scheme = TPM2_ALG_ECDSA;
		inScheme.details.ecdsa.hashAlg = TPM2D_HASH_ALGORITHM;
	}

	PCRselect.count = 1;
	PCRselect.pcrSelections[0].hash = TPM2D_HASH_ALGORITHM;

	if (qualifying_data != NULL) {
		if (TPM2_RC_SUCCESS !=
		    (rc = tss_tpm2b_create(&qualifyingData, qualifying_data, qualifying_data_len,
					   sizeof(TPMT_HA))))
			goto err;
	} else {
		qualifyingData.size = 0;
	}

	do {
		rc = esys_set_auth_pw(sig_key_pwd, signHandle);
		if (rc == TPM2_RC_SUCCESS) {
			rc = Esys_Quote(esys_context, signHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
					ESYS_TR_NONE, &qualifyingData, &inScheme, &PCRselect,
					&quoted, &signature);
		}
	} while (TPM2_RC_RETRY == rc);

	if (rc != TPM2_RC_SUCCESS) {
		quote = NULL;
		goto err;
	}

	// check if input qualifying data matches output extra data
	size_t offset = 0;
	if (TPM2_RC_SUCCESS !=
	    (rc = Tss2_MU_TPMS_ATTEST_Unmarshal(quoted->attestationData, quoted->size, &offset,
						&tpms_attest)))
		goto err;
	if (qualifyingData.size != tpms_attest.extraData.size ||
	    memcmp(qualifyingData.buffer, tpms_attest.extraData.buffer, qualifyingData.size) != 0)
		goto err;

	// finally fill the output structure needed for protobuf
	quote = mem_alloc0(sizeof(tpm2d_quote_t));
	quote->halg_id = PCRselect.pcrSelections[0].hash;
	quote->quoted_size = quoted->size;
	quote->quoted_value = mem_new0(uint8_t, quoted->size);
	memcpy(quote->quoted_value, quoted->attestationData, quoted->size);

	size_t signature_size;
	quote->signature_value =
		tpm2d_marshal_structure_tpmt_signature_new(signature, &signature_size);
	quote->signature_size = signature_size;

	if (inScheme.scheme == TPM2_ALG_RSASSA) {
		tss_print_all("RSA signature", signature->signature.rsassa.sig.buffer,
			      signature->signature.rsassa.sig.size);
	}
	goto out;

err:
	TSS_TPM_CMD_ERROR(rc, "CC_Quote");
out:
	Esys_Free(quoted);
	Esys_Free(signature);
	return quote;
}

void
tpm2_quote_free(tpm2d_quote_t *quote)
{
	if (quote->quoted_value)
		mem_free0(quote->quoted_value);
	if (quote->signature_value)
		mem_free0(quote->signature_value);
	mem_free0(quote);
}

TPM2_RC
tpm2_evictcontrol(TPMI_RH_HIERARCHY auth, char *auth_pwd, TPMI_DH_OBJECT obj_handle,
		  TPMI_DH_PERSISTENT persist_handle)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	ESYS_TR in_auth;
	ESYS_TR objectHandle;
	TPMI_DH_PERSISTENT persistentHandle;
	ESYS_TR new_obj_handle;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	// TOOD: convert to ESYS_TR?
	in_auth = auth;
	objectHandle = obj_handle;
	persistentHandle = persist_handle;

	do {
		rc = esys_set_auth_pw(auth_pwd, in_auth);
		if (rc == TPM2_RC_SUCCESS) {
			rc = Esys_EvictControl(esys_context, in_auth, objectHandle,
					       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
					       persistentHandle, &new_obj_handle);
		}
	} while (TPM2_RC_RETRY == rc);

	if (TPM2_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_EvictControl");

	return rc;
}

TPM2_RC
tpm2_rsaencrypt(TPMI_DH_OBJECT key_handle, uint8_t *in_buffer, size_t in_length,
		uint8_t *out_buffer, size_t *out_length)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	ESYS_TR keyHandle;
	TPM2B_PUBLIC_KEY_RSA message;
	TPMT_RSA_DECRYPT inScheme;
	TPM2B_DATA label;
	TPM2B_PUBLIC_KEY_RSA *outData = NULL;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	if (in_length > TPM2_MAX_RSA_KEY_BYTES) {
		ERROR("Input buffer exceeds RSA Blocksize %zu\n", in_length);
		return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
	}

	keyHandle = key_handle;
	/* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */
	message.size = (uint16_t)in_length;
	memcpy(message.buffer, in_buffer, in_length);
	/* Table 157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */
	inScheme.scheme = TPM2_ALG_OAEP;
	inScheme.details.oaep.hashAlg = TPM2D_HASH_ALGORITHM;
	/* Table 73 - Definition of TPM2B_DATA Structure */
	label.size = 0;

	do {
		rc = Esys_RSA_Encrypt(esys_context, keyHandle, ESYS_TR_NONE, ESYS_TR_NONE,
				      ESYS_TR_NONE, &message, &inScheme, &label, &outData);
	} while (TPM2_RC_RETRY == rc);

	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_RSA_encrypt");
		return rc;
	}

	tss_print_all("RSA encrypted data", outData->buffer, outData->size);

	// return handle to just created object
	if (outData->size > *out_length) {
		ERROR("Output buffer (size=%zu) is to small for encrypted data of size %u\n",
		      *out_length, outData->size);
		return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
	}
	memcpy(out_buffer, outData->buffer, outData->size);

	Esys_Free(outData);
	return rc;
}

TPM2_RC
tpm2_rsadecrypt(TPMI_DH_OBJECT key_handle, const char *key_pwd, uint8_t *in_buffer,
		size_t in_length, uint8_t *out_buffer, size_t *out_length)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	ESYS_TR keyHandle;
	TPM2B_PUBLIC_KEY_RSA cipherText;
	TPMT_RSA_DECRYPT inScheme;
	TPM2B_DATA label;
	TPM2B_PUBLIC_KEY_RSA *message = NULL;
	uint16_t msg_size;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	if (in_length > TPM2_MAX_RSA_KEY_BYTES) {
		ERROR("Input buffer exceeds RSA block size %zu\n", in_length);
		return TSS2_BASE_RC_INSUFFICIENT_BUFFER;
	}

	keyHandle = key_handle;
	/* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */
	cipherText.size = (uint16_t)in_length;
	memcpy(cipherText.buffer, in_buffer, in_length);
	/* Table 157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */
	inScheme.scheme = TPM2_ALG_OAEP;
	inScheme.details.oaep.hashAlg = TPM2D_HASH_ALGORITHM;
	/* Table 73 - Definition of TPM2B_DATA Structure */
	label.size = 0;

	do {
		rc = esys_set_auth_pw(key_pwd, keyHandle);
		if (rc == TPM2_RC_SUCCESS) {
			rc = Esys_RSA_Decrypt(esys_context, keyHandle, ESYS_TR_PASSWORD,
					      ESYS_TR_NONE, ESYS_TR_NONE, &cipherText, &inScheme,
					      &label, &message);
		}
	} while (TPM2_RC_RETRY == rc);

	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_RSA_decrypt");
		goto err;
	}

	tss_print_all("RSA Decrypted message", message->buffer, message->size);

	msg_size = message->size;

	// return handle to just created object
	if (msg_size > *out_length) {
		ERROR("Output buffer (size=%zu) is to small for decrypted message of size %u\n",
		      *out_length, msg_size);
		rc = TSS2_BASE_RC_INSUFFICIENT_BUFFER;
		goto err;
	}
	memcpy(out_buffer, message->buffer, message->size);
	*out_length = message->size;

err:
	Esys_Free(message);
	return rc;
}
#endif // ndef TPM2D_NVMCRYPT_ONLY

TPM2_RC
tpm2_hierarchychangeauth(TPMI_RH_HIERARCHY hierarchy, const char *old_pwd, const char *new_pwd)
{
	TPM2_RC rc, rc_flush = TPM2_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	ESYS_TR authHandle;
	TPM2B_AUTH newAuth;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	authHandle = hierarchy;

	if (new_pwd == NULL) {
		newAuth.size = 0;
	} else if (TPM2_RC_SUCCESS !=
		   (rc = tss_tpm2b_auth_strcpy(&newAuth, new_pwd, sizeof(TPMU_HA))))
		return rc;

	// since we use this to store symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM2_SE_HMAC, &se_handle, hierarchy, old_pwd);
	if (TPM2_RC_SUCCESS != rc)
		goto err;

	do {
		rc = Esys_TRSess_SetAttributes(esys_context, se_handle,
					       TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION,
					       TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION);
		if (rc == TPM2_RC_SUCCESS) {
			rc = Esys_HierarchyChangeAuth(esys_context, authHandle, se_handle,
						      ESYS_TR_NONE, ESYS_TR_NONE, &newAuth);
		}
	} while (TPM2_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);
err:
	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_HierarchyChangeAuth");
	} else {
		rc = rc_flush;
	}
	return rc;
}

uint8_t *
tpm2_getrandom_new(size_t rand_length)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	UINT16 bytesRequested;
	TPM2B_DIGEST *out = NULL;

	IF_NULL_RETVAL_ERROR(esys_context, NULL);

	// since we use this to generate symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM2_SE_HMAC, &se_handle, ESYS_TR_RH_NULL, NULL);
	if (TPM2_RC_SUCCESS != rc)
		return NULL;

	uint8_t *rand = mem_new0(uint8_t, rand_length);
	size_t recv_bytes = 0;
	do {
		bytesRequested = rand_length - recv_bytes;
		rc = Esys_TRSess_SetAttributes(esys_context, se_handle,
					       TPMA_SESSION_ENCRYPT | TPMA_SESSION_CONTINUESESSION,
					       TPMA_SESSION_ENCRYPT | TPMA_SESSION_CONTINUESESSION);
		if (rc != TPM2_RC_SUCCESS) {
			break;
		}
		rc = Esys_GetRandom(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				    bytesRequested, &out);
		if (rc != TPM2_RC_SUCCESS)
			break;
		memcpy(&rand[recv_bytes], out->buffer, out->size);
		recv_bytes += out->size;
		Esys_Free(out);
	} while (recv_bytes < rand_length);

	Esys_Free(out);

	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_GetRandom");
		mem_free0(rand);
		return NULL;
	}

	if (TPM2_RC_SUCCESS != tpm2_flushcontext(se_handle))
		WARN("Flush failed, maybe session handle was allready flushed.");

	return rand;
}

tpm2d_pcr_t *
tpm2_pcrread_new(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg)
{
	TPM2_RC rc = TPM2_RC_SUCCESS;
	TPML_PCR_SELECTION pcrSelectionIn;
	UINT32 pcrUpdateCounter;
	TPML_PCR_SELECTION *pcrSelectionOut = NULL;
	TPML_DIGEST *pcrValues = NULL;

	tpm2d_pcr_t *pcr = NULL;

	IF_NULL_RETVAL_ERROR(esys_context, NULL);

	/* Table 102 - Definition of TPML_PCR_SELECTION Structure */
	pcrSelectionIn.count = 1;
	/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */
	pcrSelectionIn.pcrSelections[0].hash = hash_alg;
	pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
	pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
	pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
	pcrSelectionIn.pcrSelections[0].pcrSelect[pcr_index / 8] = 1 << (pcr_index % 8);

	do {
		rc = Esys_PCR_Read(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				   &pcrSelectionIn, &pcrUpdateCounter, &pcrSelectionOut,
				   &pcrValues);
	} while (TPM2_RC_RETRY == rc);

	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_PCR_Read");
		pcr = NULL;
		goto err;
	}

	if (pcrValues->count == 0) {
		WARN("CC_PCR_Read returned no values. Seems PCRs are not initialized, reboot System!");
		pcr = NULL;
		goto err;
	}

	INFO("pcrValues->digests[0].size %d", pcrValues->digests[0].size);

	// finally fill the output structure needed for protobuf
	pcr = mem_alloc0(sizeof(tpm2d_pcr_t));
	pcr->halg_id = pcrSelectionIn.pcrSelections[0].hash;
	pcr->pcr_value = mem_alloc0(
		MUL_WITH_OVERFLOW_CHECK((size_t)sizeof(uint8_t), pcrValues->digests[0].size));
	memcpy(pcr->pcr_value, pcrValues->digests[0].buffer, pcrValues->digests[0].size);
	pcr->pcr_size = pcrValues->digests[0].size;

err:
	Esys_Free(pcrSelectionOut);
	Esys_Free(pcrValues);
	return pcr;
}

void
tpm2_pcrread_free(tpm2d_pcr_t *pcr)
{
	if (pcr->pcr_value)
		mem_free0(pcr->pcr_value);
	mem_free0(pcr);
}

size_t
tpm2_nv_get_data_size(TPMI_RH_NV_INDEX nv_index_handle)
{
	TPM2B_NV_PUBLIC *nv_public = NULL;
	TPM2B_NAME *nv_name = NULL;
	size_t data_size = 0;

	IF_NULL_RETVAL_WARN(esys_context, 0);

	if ((nv_index_handle >> 24) != TPM2_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return -1;
	}

	if (TPM2_RC_SUCCESS != Esys_NV_ReadPublic(esys_context, nv_index_handle, ESYS_TR_NONE,
						  ESYS_TR_NONE, ESYS_TR_NONE, &nv_public,
						  &nv_name)) {
		Esys_Free(nv_public);
		Esys_Free(nv_name);
		return 0;
	}

	uint32_t nv_type = (nv_public->nvPublic.attributes & TPMA_NV_TPM2_NT_MASK) >> 4;
	if (nv_type == TPM2_NT_ORDINARY) {
		data_size = nv_public->nvPublic.dataSize;
	} else {
		WARN("Only ORDINARY data have variable size!");
	}
	INFO("Data size of NV index %x is %zd", nv_index_handle, data_size);

	Esys_Free(nv_public);
	Esys_Free(nv_name);

	return data_size;
}

static size_t
tpm2_nv_get_max_buffer_size(ESYS_CONTEXT *esys_context)
{
	TPM2_CAP capability;
	UINT32 property;
	UINT32 propertyCount;
	TPMI_YES_NO more_data;
	TPMS_CAPABILITY_DATA *capability_data;

	capability = TPM2_CAP_TPM_PROPERTIES;
	property = TPM2_PT_NV_BUFFER_MAX;
	propertyCount = 1;

	// set a small default fallback value;
	size_t buffer_size = 512;

	IF_NULL_RETVAL_WARN(esys_context, buffer_size);

	if (TPM2_RC_SUCCESS != Esys_GetCapability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
						  ESYS_TR_NONE, capability, property, propertyCount,
						  &more_data, &capability_data)) {
		Esys_Free(capability_data);
		ERROR("GetCapability failed, returning default value %zd", buffer_size);
		return buffer_size;
	}

	if (capability_data->data.tpmProperties.count > 0 &&
	    capability_data->data.tpmProperties.tpmProperty[0].property == TPM2_PT_NV_BUFFER_MAX)
		buffer_size = capability_data->data.tpmProperties.tpmProperty[0].value;
	else
		ERROR("GetCapability failed, returning default value %zd", buffer_size);

	INFO("NV buffer maximum size is set to %zd", buffer_size);

	Esys_Free(capability_data);

	return buffer_size;
}

TPM2_RC
tpm2_nv_definespace(TPMI_RH_HIERARCHY hierarchy, TPMI_RH_NV_INDEX nv_index_handle, size_t nv_size,
		    const char *hierarchy_pwd, const char *nv_pwd, uint8_t *policy_digest)
{
	TPM2_RC rc, rc_flush = TPM2_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	ESYS_TR authHandle;
	TPM2B_AUTH auth;
	TPM2B_NV_PUBLIC publicInfo;
	ESYS_TR nvHandle;
	TPMA_NV nv_attr;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	if ((nv_index_handle >> 24) != TPM2_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TPM2_RC_HANDLE;
	}

	if (nv_pwd == NULL)
		auth.size = 0;
	else if (TPM2_RC_SUCCESS != (rc = tss_tpm2b_auth_strcpy(&auth, nv_pwd, sizeof(TPMU_HA))))
		return rc;

	authHandle = hierarchy;

	nv_attr = 0;
	if (hierarchy == ESYS_TR_RH_PLATFORM) {
		nv_attr |= TPMA_NV_PLATFORMCREATE;
		nv_attr |= TPMA_NV_PPWRITE;
		nv_attr |= TPMA_NV_PPREAD;
	} else { // TPM_RH_OWNER
		nv_attr |= TPMA_NV_OWNERWRITE;
		nv_attr |= TPMA_NV_OWNERREAD;
	}
	// TPMA_NVA_ORDINARY does not exist in tss2 but is defined to 0 in ibmtss
	// nv_attr |= TPMA_NVA_ORDINARY;
	// this is also commented out in ibmtss version
	//nv_attr |= TPMA_NV_AUTHREAD;
	nv_attr |= TPMA_NV_AUTHWRITE;

	// needed to allow readlock
	nv_attr |= TPMA_NV_READ_STCLEAR;

	publicInfo.nvPublic.nvIndex = nv_index_handle;
	publicInfo.nvPublic.nameAlg = TPM2D_HASH_ALGORITHM;
	publicInfo.nvPublic.dataSize = nv_size;

	// set policy
	if (policy_digest) {
		publicInfo.nvPublic.authPolicy.size = TPM2D_DIGEST_SIZE;
		memcpy(&publicInfo.nvPublic.authPolicy.buffer, policy_digest, TPM2D_DIGEST_SIZE);
		//rc = TSS_File_Read2B(&in.publicInfo.nvPublic.authPolicy.b, sizeof(TPMU_HA),
		// 		policy_digest_file);
		//if (TPM2_RC_SUCCESS != rc) {
		//	ERROR("Failed to read policy digest!");
		//	goto err;
		//}
		if (publicInfo.nvPublic.authPolicy.size != TPM2D_DIGEST_SIZE) {
			ERROR("digest size mismatch!");
			rc = TPM2_RC_POLICY;
			goto err;
		}

		nv_attr |= TPMA_NV_POLICYREAD;
		//nv_attr.val |= TPMA_NVA_POLICYWRITE;
	} else { // set default empty policy
		publicInfo.nvPublic.authPolicy.size = 0;
		nv_attr |= TPMA_NV_AUTHREAD;
		//nv_attr.val |= TPMA_NVA_AUTHWRITE;
	}

	publicInfo.nvPublic.attributes = nv_attr;

	// since we use this to store symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM2_SE_HMAC, &se_handle, hierarchy, hierarchy_pwd);
	if (TPM2_RC_SUCCESS != rc)
		goto err;

	do {
#if 0
		rc = TSS_Execute(tss_context, NULL, (COMMAND_PARAMETERS *)&in, NULL,
				 TPM_CC_NV_DefineSpace,
				 //TPM_RS_PW, hierarchy_pwd, 0,
				 se_handle, 0, TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION,
				 TPM_RH_NULL, NULL, 0);
#endif
		rc = Esys_TRSess_SetAttributes(esys_context, se_handle,
					       TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION,
					       TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION);
		if (rc == TPM2_RC_SUCCESS) {
			rc = Esys_NV_DefineSpace(esys_context, authHandle, se_handle, ESYS_TR_NONE,
						 ESYS_TR_NONE, &auth, &publicInfo, &nvHandle);
		}
	} while (TPM2_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);
err:
	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_DefineSpace");
	} else {
		rc = rc_flush;
	}

	return rc;
}

TPM2_RC
tpm2_nv_undefinespace(TPMI_RH_HIERARCHY hierarchy, TPMI_RH_NV_INDEX nv_index_handle,
		      const char *hierarchy_pwd)
{
	TPM2_RC rc, rc_flush = TPM2_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	ESYS_TR authHandle;
	ESYS_TR nvIndex;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	if ((nv_index_handle >> 24) != TPM2_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TPM2_RC_HANDLE;
	}

	authHandle = hierarchy;
	nvIndex = nv_index_handle;

	// since we use this to store symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM2_SE_HMAC, &se_handle, hierarchy, hierarchy_pwd);
	if (TPM2_RC_SUCCESS != rc)
		goto err;

	do {
		rc = Esys_TRSess_SetAttributes(esys_context, se_handle,
					       TPMA_SESSION_CONTINUESESSION,
					       TPMA_SESSION_CONTINUESESSION);
		if (rc == TPM2_RC_SUCCESS) {
			rc = Esys_NV_UndefineSpace(esys_context, authHandle, nvIndex, se_handle,
						   ESYS_TR_NONE, ESYS_TR_NONE);
		}
	} while (TPM2_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);
err:
	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_UndefineSpace");
	} else {
		rc = rc_flush;
	}

	return rc;
}

TPM2_RC
tpm2_nv_write(TPMI_RH_NV_INDEX nv_index_handle, const char *nv_pwd, uint8_t *data,
	      size_t data_length)
{
	TPM2_RC rc, rc_flush = TPM2_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	ESYS_TR authHandle;
	ESYS_TR nvIndex;
	TPM2B_MAX_NV_BUFFER in_data;
	UINT16 offset;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);
	if ((nv_index_handle >> 24) != TPM2_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TPM2_RC_HANDLE;
	}

	authHandle = nv_index_handle;
	nvIndex = nv_index_handle;
	offset = 0;

	size_t buffer_max = tpm2_nv_get_max_buffer_size(esys_context);
	if (data_length > buffer_max) {
		INFO("Only one chunk is supported by this implementation!");
		rc = TSS2_BASE_RC_INSUFFICIENT_BUFFER;
		goto err;
	}
	memcpy(in_data.buffer, data, data_length);
	in_data.size = data_length;

	// since we use this to read symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM2_SE_HMAC, &se_handle, nv_index_handle, nv_pwd);
	if (TPM2_RC_SUCCESS != rc)
		goto err;

	do {
		rc = Esys_TRSess_SetAttributes(esys_context, se_handle,
					       TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION,
					       TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION);
		if (rc == TPM2_RC_SUCCESS) {
			rc = Esys_NV_Write(esys_context, authHandle, nvIndex, se_handle,
					   ESYS_TR_NONE, ESYS_TR_NONE, &in_data, offset);
		}
	} while (TPM2_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);
err:
	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_Write");
	} else {
		rc = rc_flush;
	}
	return rc;
}

TPM2_RC
tpm2_nv_read(TPMI_SH_POLICY se_handle, TPMI_RH_NV_INDEX nv_index_handle, const char *nv_pwd,
	     uint8_t *out_buffer, size_t *out_length)
{
	TPM2_RC rc, rc_flush = TPM2_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION auth_se_handle;

	ESYS_TR authHandle;
	ESYS_TR nvIndex;
	UINT16 size;
	UINT16 offset;
	TPM2B_MAX_NV_BUFFER *data = NULL;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	if ((nv_index_handle >> 24) != TPM2_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TPM2_RC_HANDLE;
	}

	authHandle = nv_index_handle;
	nvIndex = nv_index_handle;

	size_t data_size = tpm2_nv_get_data_size(nv_index_handle);
	size_t buffer_max = tpm2_nv_get_max_buffer_size(esys_context);

	if (data_size > *out_length) {
		ERROR("Output buffer (size=%zd) is to small for nv data of size %zd\n", *out_length,
		      data_size);
		rc = TSS2_BASE_RC_INSUFFICIENT_BUFFER;
		goto err;
	}

	// since we use this to read symetric keys, start an encrypted transport
	if (se_handle == ESYS_TR_RH_NULL) {
		rc = tpm2_startauthsession(TPM2_SE_HMAC, &auth_se_handle, nv_index_handle, nv_pwd);
		if (TPM2_RC_SUCCESS != rc)
			goto err;
	} else {
		INFO("Using provided se_handle");
		auth_se_handle = se_handle;
	}

	offset = *out_length = 0;
	do {
		size = (data_size > buffer_max) ? buffer_max : data_size;
		INFO("Reading chunk of size=%d", size);

		do {
			rc = Esys_TRSess_SetAttributes(
				esys_context, se_handle,
				TPMA_SESSION_ENCRYPT | TPMA_SESSION_CONTINUESESSION,
				TPMA_SESSION_ENCRYPT | TPMA_SESSION_CONTINUESESSION);
			if (rc == TPM2_RC_SUCCESS) {
				rc = Esys_NV_Read(esys_context, authHandle, nvIndex, se_handle,
						  ESYS_TR_NONE, ESYS_TR_NONE, size, offset, &data);
			}
		} while (TPM2_RC_RETRY == rc);

		if (TPM2_RC_SUCCESS != rc)
			goto flush;

		memcpy(out_buffer + offset, data->buffer, data->size);
		data_size -= data->size;
		offset += data->size;
		// set ouput length of caller
		*out_length += data->size;

	} while (data_size > 0);

	tss_print_all("nv_read data: ", out_buffer, *out_length);

flush:
	rc_flush = tpm2_flushcontext(auth_se_handle);

err:
	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_Read");
	} else {
		rc = rc_flush;
	}

	Esys_Free(data);

	return rc;
}

TPM2_RC
tpm2_nv_readlock(TPMI_RH_NV_INDEX nv_index_handle, const char *nv_pwd)
{
	TPM2_RC rc, rc_flush = TPM2_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	ESYS_TR authHandle;
	ESYS_TR nvIndex;

	IF_NULL_RETVAL_ERROR(esys_context, TSS2_BASE_RC_BAD_REFERENCE);

	if ((nv_index_handle >> 24) != TPM2_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TPM2_RC_HANDLE;
	}

	authHandle = nv_index_handle;
	nvIndex = nv_index_handle;

	// since we use this to read symetric keys, start an encrypted transport
	rc = tpm2_startauthsession(TPM2_SE_HMAC, &se_handle, nv_index_handle, nv_pwd);
	if (TPM2_RC_SUCCESS != rc)
		goto err;

	do {
		rc = Esys_TRSess_SetAttributes(esys_context, se_handle,
					       TPMA_SESSION_CONTINUESESSION,
					       TPMA_SESSION_CONTINUESESSION);
		if (rc == TPM2_RC_SUCCESS) {
			rc = Esys_NV_ReadLock(esys_context, authHandle, nvIndex, se_handle,
					      ESYS_TR_NONE, ESYS_TR_NONE);
		}
	} while (TPM2_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);

err:
	if (TPM2_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_ReadLock");
	} else {
		rc = rc_flush;
	}
	return rc;
}
