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

#include "tpm2d.h"

#include "common/mem.h"
#include "common/macro.h"
#include "common/file.h"

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsstransmit.h>
#include <ibmtss/Unmarshal_fp.h>

#include <ibmtss/tssprint.h>

#include "tpm2d_write_openssl.h"

#include <openssl/sha.h>

static TSS_CONTEXT *tss_context = NULL;

#define TSS_TPM_CMD_ERROR(rc, cc_string) \
{ \
	const char *msg; \
	const char *submsg; \
	const char *num; \
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc); \
	ERROR("%s failed, rc %08x: %s%s%s\n", cc_string, rc, msg, submsg, num); \
}

/************************************************************************************/

void
tss2_init(void)
{
	int ret;

	if (tss_context) {
		WARN("Context already exists");
		return;
	}

	if (TPM_RC_SUCCESS != (ret = TSS_Create(&tss_context)))
		FATAL("Cannot create tss context error code: %08x", ret);

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
}

void
tss2_destroy(void)
{
	int ret;
	IF_NULL_RETURN_ERROR(tss_context);

	if (TPM_RC_SUCCESS != (ret = TSS_Delete(tss_context)))
		FATAL("Cannot destroy tss context error code: %08x", ret);

	tss_context = NULL;
}

char *
convert_bin_to_hex_new(const uint8_t *bin, int length)
{
	char *hex = mem_alloc0(sizeof(char)*length*2 + 1);

	for (int i=0; i < length; ++i) {
		// remember snprintf additionally writs a '0' byte
		snprintf(hex+i*2, 3, "%.2x", bin[i]);
	}

	return hex;
}

uint8_t *
convert_hex_to_bin_new(const char *hex_str, int *out_length)
{
	int len = strlen(hex_str);
	int i = 0, j = 0;
	*out_length = (len+1)/2;

	uint8_t *bin = mem_alloc0(*out_length);

	if (len % 2 == 1)
	{
		// odd length -> we need to pad
		IF_FALSE_GOTO(sscanf(&(hex_str[0]), "%1hhx", &(bin[0])) == 1, err);
		i = j = 1;
	}

	for (; i < len; i+=2, j++)
	{
		IF_FALSE_GOTO(sscanf(&(hex_str[i]), "%2hhx", &(bin[j])) == 1, err);
	}

	return bin;
err:
	ERROR("Converstion of hex string to bin failed!");
	mem_free(bin);
	return NULL;
}

#ifndef TPM2D_NVMCRYPT_ONLY
static uint8_t *
tpm2d_marshal_structure_new(void *structure, MarshalFunction_t marshal_function, size_t *size)
{
	uint8_t *bin_stream = NULL;
	uint16_t written_size;

	if (TPM_RC_SUCCESS != TSS_Structure_Marshal(&bin_stream, &written_size,
						structure, marshal_function)) {
		WARN("no data written to stream!");
		*size = 0;
		return NULL;
	}
	*size = written_size;
	INFO("marshal written size %d, *size %zu", written_size, *size);
	return bin_stream;
}
#endif

/************************************************************************************/

TPM_RC
tpm2_powerup(void)
{
	TPM_RC rc = TPM_RC_SUCCESS;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	if (TPM_RC_SUCCESS != (rc = TSS_TransmitPlatform(tss_context, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform")))
		goto err;

	if (TPM_RC_SUCCESS != (rc = TSS_TransmitPlatform(tss_context, TPM_SIGNAL_POWER_ON, "TPM2_PowerOnPlatform")))
		goto err;

	rc = TSS_TransmitPlatform(tss_context, TPM_SIGNAL_NV_ON, "TPM2_NvOnPlatform");
err:
	if (TPM_RC_SUCCESS != rc) 
		TSS_TPM_CMD_ERROR(rc, "CC_PowerUp");

	return rc;
}

TPM_RC
tpm2_startup(TPM_SU startup_type)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	Startup_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.startupType = startup_type;

	rc = TSS_Execute(tss_context, NULL, (COMMAND_PARAMETERS *)&in, NULL,
			 TPM_CC_Startup, TPM_RH_NULL, NULL, 0);

	if (TPM_RC_INITIALIZE == rc) {
		WARN("Already initialized, returing Success.");
		return TPM_RC_SUCCESS;
	}
	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_StartUp");

	return rc;
}

TPM_RC
tpm2_selftest(void)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	SelfTest_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.fullTest = YES;

	rc = TSS_Execute(tss_context, NULL, (COMMAND_PARAMETERS *)&in, NULL,
	                 TPM_CC_SelfTest, TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_SelfTest");

	return rc;
}

TPM_RC
tpm2_clear(const char *lockout_pwd)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	Clear_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);
	
	in.authHandle = TPM_RH_LOCKOUT;

	rc = TSS_Execute(tss_context, NULL, (COMMAND_PARAMETERS *)&in, NULL,
			TPM_CC_Clear, TPM_RS_PW, lockout_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_Clear");

	return rc;
}

TPM_RC
tpm2_dictionaryattacklockreset(const char *lockout_pwd)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	DictionaryAttackLockReset_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.lockHandle = TPM_RH_LOCKOUT;

	rc = TSS_Execute(tss_context, NULL, (COMMAND_PARAMETERS *)&in, NULL,
			TPM_CC_DictionaryAttackLockReset, TPM_RS_PW, lockout_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_DictionaryAttackLockReset");

	return rc;
}

TPM_RC
tpm2_startauthsession(TPM_SE session_type, TPMI_SH_AUTH_SESSION *out_session_handle,
		TPMI_DH_OBJECT bind_handle, const char *bind_pwd)
{
	TPM_RC rc;
	StartAuthSession_In in;
	StartAuthSession_Out out;
	StartAuthSession_Extra extra;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.sessionType = session_type;

	/* bind password */
	in.bind = bind_handle;
	if (in.bind != TPM_RH_NULL)
		extra.bindPassword = bind_pwd;

	/* salt key default NULL*/
	in.tpmKey = tpm2d_get_salt_key_handle();
	/* encryptedSalt (not required) */
	in.encryptedSalt.b.size = 0;
	/* nonceCaller (not required) */
	in.nonceCaller.t.size = 0;

	/* parameter encryption */
	in.symmetric.algorithm = TPM2D_SYM_SESSION_ALGORITHM;
	if (in.symmetric.algorithm == TPM_ALG_XOR) {
	    /* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */
	    /* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */
	    in.symmetric.keyBits.xorr = TPM2D_HASH_ALGORITHM;
	    /* Table 126 - Definition of TPMU_SYM_MODE Union */
	    in.symmetric.mode.sym = TPM_ALG_NULL;
	}
	else { /* TPM_ALG_AES */
	    /* Table 61 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM Type */
	    /* Table 125 - Definition of TPMU_SYM_KEY_BITS Union */
	    in.symmetric.keyBits.aes = 128;
	    /* Table 126 - Definition of TPMU_SYM_MODE Union */
	    /* Table 63 - Definition of (TPM_ALG_ID) TPMI_ALG_SYM_MODE Type */
	    in.symmetric.mode.aes = TPM_ALG_CFB;
	}

	/* authHash */
	in.authHash = TPM2D_HASH_ALGORITHM;

	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in,(EXTRA_PARAMETERS *)&extra, TPM_CC_StartAuthSession,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_StartAuthSession");
		return rc;
	}

	// return handle to just created object
	*out_session_handle = out.sessionHandle;

	return rc;
}

TPM_RC
tpm2_policyauthvalue(TPMI_SH_POLICY se_handle)
{
	TPM_RC rc;
	PolicyAuthValue_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.policySession = se_handle;

	rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_PolicyAuthValue,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_PolicyAuthValue");

        return rc;
}

TPM_RC
tpm2_policypcr(TPMI_SH_AUTH_SESSION se_handle, uint32_t pcr_mask,
				tpm2d_pcr_t *pcrs[], size_t pcrs_size)
{
	TPM_RC rc;
	PolicyPCR_In in;

	SHA_CTX sha1;
	SHA256_CTX sha256;
	SHA512_CTX sha384;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	TPM_ALG_ID hash_alg = TPM2D_HASH_ALGORITHM;

	in.pcrDigest.b.size = 0;

	in.policySession = se_handle;
	/* Table 102 - Definition of TPML_PCR_SELECTION Structure */
	in.pcrs.count = 1; // use default hash only
	/* Table 85 - Definition of TPMS_PCR_SELECTION Structure - pcrSelections */
	in.pcrs.pcrSelections[0].hash = hash_alg;
	in.pcrs.pcrSelections[0].sizeofSelect = 3;
	in.pcrs.pcrSelections[0].pcrSelect[0] = (pcr_mask >>  0) & 0xff;
	in.pcrs.pcrSelections[0].pcrSelect[1] = (pcr_mask >>  8) & 0xff;
	in.pcrs.pcrSelections[0].pcrSelect[2] = (pcr_mask >> 16) & 0xff;

	if (pcrs_size > 0) {
		switch (hash_alg) {
		case TPM_ALG_SHA1:
			in.pcrDigest.b.size = 20;
			SHA1_Init(&sha1);
			for (size_t i=0; i < pcrs_size; ++i) {
				SHA1_Update(&sha1, pcrs[i]->pcr_value, pcrs[i]->pcr_size);
				INFO("pcrs[%zu]: size: %zu", i, pcrs[i]->pcr_size);
			}
			SHA1_Final(in.pcrDigest.b.buffer, &sha1);
			TSS_PrintAll("PCR digest: ", in.pcrDigest.b.buffer, in.pcrDigest.b.size);
			break;
		case TPM_ALG_SHA256:
			in.pcrDigest.b.size = 32;
			SHA256_Init(&sha256);
			for (size_t i=0; i < pcrs_size; ++i) {
				SHA256_Update(&sha256, pcrs[i]->pcr_value, pcrs[i]->pcr_size);
				INFO("pcrs[%zu]: size: %zu", i, pcrs[i]->pcr_size);
			}
			SHA256_Final(in.pcrDigest.b.buffer, &sha256);
			TSS_PrintAll("PCR digest: ", in.pcrDigest.b.buffer, in.pcrDigest.b.size);
			break;
		case TPM_ALG_SHA384:
			in.pcrDigest.b.size = 48;
			SHA384_Init(&sha384);
			for (size_t i=0; i < pcrs_size; ++i)
				SHA384_Update(&sha384, pcrs[i]->pcr_value, pcrs[i]->pcr_size);
			SHA384_Final(in.pcrDigest.b.buffer, &sha384);
			break;
		default:
			return TSS_RC_BAD_HASH_ALGORITHM;
		}
	}

	rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_PolicyPCR,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_PolicyPCR");

        return rc;
}

TPM_RC
tpm2_policygetdigest(TPMI_SH_POLICY se_handle, uint8_t *out_digest,
				size_t out_digest_len)
{
	TPM_RC rc;
	PolicyGetDigest_In in;
	PolicyGetDigest_Out out;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.policySession = se_handle;

	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_PolicyGetDigest,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_PolicyGetDigest");
		return rc;
	}

	TSS_PrintAll("policy digest: ", out.policyDigest.t.buffer, out.policyDigest.t.size);

	//rc = TSS_File_WriteBinaryFile(out.policyDigest.t.buffer, out.policyDigest.t.size, out_file);

	if (out_digest_len < out.policyDigest.t.size) {
		ERROR("Digest size %d exceeds outputbuffer of size %zu\n", out.policyDigest.t.size,
				out_digest_len);
		return TSS_RC_INSUFFICIENT_BUFFER;
	}

	memcpy(out_digest, out.policyDigest.t.buffer, out.policyDigest.t.size);
	out_digest_len = out.policyDigest.t.size;
	return rc;
}

TPM_RC
tpm2_policyrestart(TPMI_SH_POLICY se_handle)
{
	TPM_RC rc;
	PolicyRestart_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.sessionHandle = se_handle;

	rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_PolicyRestart,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_PolicyRestart");

        return rc;
}

TPM_RC
tpm2_flushcontext(TPMI_DH_CONTEXT handle)
{
	TPM_RC rc;
	FlushContext_In in;

	in.flushHandle = handle;

	rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_FlushContext,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_FlushContext");

	return rc;
}

static TPM_RC
tpm2_fill_rsa_details(TPMT_PUBLIC *out_public_area, tpm2d_key_type_t key_type)
{
	ASSERT(out_public_area);

	out_public_area->parameters.rsaDetail.keyBits = 2048;
	out_public_area->parameters.rsaDetail.exponent = 0;

	switch (key_type) {
		case TPM2D_KEY_TYPE_STORAGE_U:
			out_public_area->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
			out_public_area->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
			break;
		case TPM2D_KEY_TYPE_STORAGE_R:
			out_public_area->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
			out_public_area->parameters.rsaDetail.symmetric.keyBits.aes = 128;
			out_public_area->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
			out_public_area->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
			break;
		case TPM2D_KEY_TYPE_SIGNING_U:
			out_public_area->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
			out_public_area->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
			break;
		case TPM2D_KEY_TYPE_SIGNING_R:
		case TPM2D_KEY_TYPE_SIGNING_EK:
			out_public_area->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
			out_public_area->parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
			out_public_area->parameters.rsaDetail.scheme.details.rsassa.hashAlg =
									TPM2D_HASH_ALGORITHM;
			break;
		default:
			ERROR("Keytype not supported for rsa keys!");
			return TPM_RC_VALUE;
			break;
	}

	return TPM_RC_SUCCESS;
}

static TPM_RC
tpm2_fill_ecc_details(TPMT_PUBLIC *out_public_area, tpm2d_key_type_t key_type)
{
	ASSERT(out_public_area);

	switch (key_type) {
		case TPM2D_KEY_TYPE_SIGNING_U:
			// non-storage keys require TPM_ALG_NULL set for the symmetric algorithm
			out_public_area->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
			out_public_area->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
			out_public_area->parameters.eccDetail.curveID = TPM2D_CURVE_ID;
			out_public_area->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
			break;
		case TPM2D_KEY_TYPE_SIGNING_R:
		case TPM2D_KEY_TYPE_SIGNING_EK:
			// non-storage keys require TPM_ALG_NULL set for the symmetric algorithm
			out_public_area->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;

			out_public_area->parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
			out_public_area->parameters.eccDetail.scheme.details.ecdsa.hashAlg =
									TPM2D_HASH_ALGORITHM;
			out_public_area->parameters.eccDetail.kdf.details.mgf1.hashAlg =
									TPM2D_HASH_ALGORITHM;
			out_public_area->parameters.eccDetail.curveID = TPM2D_CURVE_ID;
			out_public_area->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
			break;
		case TPM2D_KEY_TYPE_STORAGE_U:
		case TPM2D_KEY_TYPE_STORAGE_R:
			out_public_area->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
			out_public_area->parameters.eccDetail.symmetric.keyBits.aes = 128;
			out_public_area->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
			out_public_area->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
			out_public_area->parameters.eccDetail.scheme.details.anySig.hashAlg = 0;
			out_public_area->parameters.eccDetail.curveID = TPM2D_CURVE_ID;
			out_public_area->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
			out_public_area->parameters.eccDetail.kdf.details.mgf1.hashAlg = 0;
			break;
		default:
			ERROR("Keytype not supported for ecc keys!");
			return TPM_RC_VALUE;
			break;
	}

	return TPM_RC_SUCCESS;
}

// default IWG policy for EK primary key
static uint8_t ek_iwg_policy[] = {
       0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
       0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
       0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
};

static TPM_RC
tpm2_public_area_helper(TPMT_PUBLIC *out_public_area, TPMA_OBJECT object_attrs, tpm2d_key_type_t key_type)
{
	ASSERT(out_public_area);

	TPM_RC rc = TPM_RC_SUCCESS;

	out_public_area->type = TPM2D_ASYM_ALGORITHM;
	out_public_area->nameAlg = TPM2D_HASH_ALGORITHM;
	out_public_area->objectAttributes = object_attrs;

	out_public_area->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	out_public_area->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	out_public_area->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;

	// set default empty policy
	out_public_area->authPolicy.t.size = 0;

	switch (key_type) {
		case TPM2D_KEY_TYPE_STORAGE_U:
			// TODO needed both signing (for tpm2d) and decryption (for openssl),
			// found no suitable keytype, so I toggled the flag (question is whether to create a new keytype)
			out_public_area->objectAttributes.val |= TPMA_OBJECT_SIGN;
			out_public_area->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
			out_public_area->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
			break;
		case TPM2D_KEY_TYPE_STORAGE_R:
			out_public_area->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
			out_public_area->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
			out_public_area->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
			break;
		case TPM2D_KEY_TYPE_SIGNING_U:
			out_public_area->objectAttributes.val |= TPMA_OBJECT_SIGN;
			out_public_area->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
			out_public_area->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
			break;
		case TPM2D_KEY_TYPE_SIGNING_EK:
			out_public_area->objectAttributes.val |= TPMA_OBJECT_ADMINWITHPOLICY;
			out_public_area->authPolicy.t.size = sizeof(ek_iwg_policy);
			memcpy(&out_public_area->authPolicy.t.buffer, ek_iwg_policy,
				       sizeof(ek_iwg_policy)); // fallthrough
		case TPM2D_KEY_TYPE_SIGNING_R:
			out_public_area->objectAttributes.val |= TPMA_OBJECT_SIGN;
			out_public_area->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
			out_public_area->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
			break;
		default:
			ERROR("Only support creation of signing and storage keys!");
			return TPM_RC_VALUE;
			break;
	}

	if (TPM2D_ASYM_ALGORITHM == TPM_ALG_RSA) {
		out_public_area->unique.rsa.t.size = 0;
		rc = tpm2_fill_rsa_details(out_public_area, key_type);
	} else {
		// TPM2D_ASYM_ALGORITHM == TPM_ALG_ECC
		out_public_area->unique.ecc.x.t.size = 0;
		out_public_area->unique.ecc.y.t.size = 0;
		rc = tpm2_fill_ecc_details(out_public_area, key_type);
	}

	return rc;
}

TPM_RC
tpm2_createprimary_asym(TPMI_RH_HIERARCHY hierachy, tpm2d_key_type_t key_type,
		const char *hierachy_pwd, const char *key_pwd,
		const char *file_name_pub_key, uint32_t *out_handle)
{
	TPM_RC rc = TPM_RC_SUCCESS;

	CreatePrimary_In in;
	CreatePrimary_Out out;
	TPMA_OBJECT object_attrs;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	// set some default key attr overwritten by tpm2_public_area helper
	// depending on key_type
	object_attrs.val = 0;
	object_attrs.val |= TPMA_OBJECT_NODA;
	object_attrs.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	object_attrs.val |= TPMA_OBJECT_USERWITHAUTH;
	object_attrs.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
	object_attrs.val |= TPMA_OBJECT_RESTRICTED;
	object_attrs.val |= TPMA_OBJECT_DECRYPT;
	object_attrs.val &= ~TPMA_OBJECT_SIGN;
	object_attrs.val |= TPMA_OBJECT_FIXEDTPM;
	object_attrs.val |= TPMA_OBJECT_FIXEDPARENT;

	in.primaryHandle = hierachy;

	// Table 134 - Definition of TPM2B_SENSITIVE_CREATE inSensitive
	if (key_pwd == NULL)
		in.inSensitive.sensitive.userAuth.t.size = 0;
	else if (TPM_RC_SUCCESS != (rc = TSS_TPM2B_StringCopy(
				&in.inSensitive.sensitive.userAuth.b,
				key_pwd, sizeof(TPMU_HA))))
			return rc;
	in.inSensitive.sensitive.data.t.size = 0;

	// fill in TPM2B_PUBLIC (and overwrite object_attrs)
	if (TPM_RC_SUCCESS != (rc = tpm2_public_area_helper(
			&in.inPublic.publicArea, object_attrs, key_type)))
		return rc;

	// TPM2B_DATA outsideInfo
	in.outsideInfo.t.size = 0;
	// Table 102 - TPML_PCR_SELECTION creationPCR
	in.creationPCR.count = 0;


	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_CreatePrimary,
			TPM_RS_PW, hierachy_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_CreatePrimary");
		return rc;
	}

	// save the public key
	if (file_name_pub_key) {
		rc = TSS_File_WriteStructure(&out.outPublic,
				(MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal,
				file_name_pub_key);
	}

	// return handle to just created object
	*out_handle = out.objectHandle;

	return rc;
}

#ifndef TPM2D_NVMCRYPT_ONLY
TPM_RC
tpm2_create_asym(TPMI_DH_OBJECT parent_handle, tpm2d_key_type_t key_type,
		uint32_t object_vals, const char *parent_pwd, const char *key_pwd,
		const char *file_name_priv_key, const char *file_name_pub_key, const char *file_name_tss_key)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	Create_In in;
	Create_Out out;
	TPMA_OBJECT object_attrs;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.parentHandle = parent_handle;
	object_attrs.val = object_vals;

	// Table 134 - Definition of TPM2B_SENSITIVE_CREATE inSensitive
	if (key_pwd == NULL)
		in.inSensitive.sensitive.userAuth.t.size = 0;
	else if (TPM_RC_SUCCESS != (rc = TSS_TPM2B_StringCopy(
				&in.inSensitive.sensitive.userAuth.b,
				key_pwd, sizeof(TPMU_HA))))
			return rc;
	in.inSensitive.sensitive.data.t.size = 0;

	// fill in TPM2B_PUBLIC
	if (TPM_RC_SUCCESS != (rc = tpm2_public_area_helper(
			&in.inPublic.publicArea, object_attrs, key_type)))
		return rc;

	// TPM2B_DATA outsideInfo
	in.outsideInfo.t.size = 0;
	// Table 102 - TPML_PCR_SELECTION creationPCR
	in.creationPCR.count = 0;

	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Create,
			TPM_RS_PW, parent_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_Create");
		return rc;
	}

	// save the private key
	if (file_name_priv_key) {
		if (TPM_RC_SUCCESS != (rc = TSS_File_WriteStructure(&out.outPrivate,
				(MarshalFunction_t)TSS_TPM2B_PRIVATE_Marshal,
				file_name_priv_key))) {
			return rc;
		}
	}

	// save the public key
	if (file_name_pub_key) {
		rc = TSS_File_WriteStructure(&out.outPublic,
				(MarshalFunction_t)TSS_TPM2B_PUBLIC_Marshal,
				file_name_pub_key);
	}

	if (file_name_tss_key) {
		BYTE pubkey[sizeof(TPM2B_PUBLIC)], privkey[sizeof(TPM2B_PRIVATE)], *buffer;
		TPM2B_PUBLIC *pub = &out.outPublic;
		TPM2B_PRIVATE *priv = &out.outPrivate;
		uint16_t pubkey_len, privkey_len;
		int32_t size;

		buffer = pubkey;
		pubkey_len = 0;
		size = sizeof(pubkey);
		TSS_TPM2B_PUBLIC_Marshal(pub, &pubkey_len, &buffer, &size);
		buffer = privkey;
		privkey_len = 0;
		size = sizeof(privkey);
		TSS_TPM2B_PRIVATE_Marshal(priv, &privkey_len, &buffer, &size);
		openssl_write_tpmfile(file_name_tss_key, pubkey, pubkey_len, privkey, privkey_len,
				key_pwd == NULL, parent_handle, NULL, 0, NULL);
	}

	return rc;
}

TPM_RC
tpm2_load(TPMI_DH_OBJECT parent_handle, const char *parent_pwd,
		const char *file_name_priv_key, const char *file_name_pub_key,
		uint32_t *out_handle)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	Load_In in;
	Load_Out out;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.parentHandle = parent_handle;

	if (TPM_RC_SUCCESS != (rc = TSS_File_ReadStructure(&in.inPrivate,
			(UnmarshalFunction_t)TSS_TPM2B_PRIVATE_Unmarshalu,
			file_name_priv_key)))
		return rc;

	if (TPM_RC_SUCCESS != (rc = TSS_File_ReadStructureFlag(&in.inPublic,
			(UnmarshalFunctionFlag_t)TSS_TPM2B_PUBLIC_Unmarshalu,
			false, file_name_pub_key)))
		return rc;

	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Load,
			TPM_RS_PW, parent_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_Load");
		return rc;
	}

	// return handle to just created object
	*out_handle = out.objectHandle;

	return rc;
}

TPM_RC
tpm2_pcrextend(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg, const uint8_t *data, size_t data_len)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	PCR_Extend_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	if (data_len > sizeof(TPMU_HA)) {
		ERROR("Data length %zu exceeds hash size %zu!", data_len, sizeof(TPMU_HA));
		return EXIT_FAILURE;
	}

	in.pcrHandle = pcr_index;

	// extend one bank
	in.digests.count = 1;

	// pad and set data
	in.digests.digests[0].hashAlg = hash_alg;
	memset((uint8_t *)&in.digests.digests[0].digest, 0, sizeof(TPMU_HA));
	memcpy((uint8_t *)&in.digests.digests[0].digest, data, data_len);

	rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_PCR_Extend,
			TPM_RS_PW, NULL, 0,
			TPM_RH_NULL, NULL, 0);

	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_PCR_Extend");

	return rc;
}

tpm2d_quote_t *
tpm2_quote_new(TPMI_DH_PCR pcr_indices, TPMI_DH_OBJECT sig_key_handle,
			const char *sig_key_pwd, uint8_t *qualifying_data,
			size_t qualifying_data_len)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	Quote_In in;
	Quote_Out out;
	TPMS_ATTEST tpms_attest;
	tpm2d_quote_t *quote = NULL;

	IF_NULL_RETVAL_ERROR(tss_context, NULL);

	if (pcr_indices > 23) {
		ERROR("Exceeded maximum available PCR registers!");
		return NULL;
	}

	in.PCRselect.pcrSelections[0].sizeofSelect = 3;
	in.PCRselect.pcrSelections[0].pcrSelect[0] = 0;
	in.PCRselect.pcrSelections[0].pcrSelect[1] = 0;
	in.PCRselect.pcrSelections[0].pcrSelect[2] = 0;
	for (size_t i=0; i < pcr_indices; ++i) {
		in.PCRselect.pcrSelections[0].pcrSelect[pcr_indices / 8] |= 1 << (pcr_indices % 8);
	}

	in.signHandle = sig_key_handle;
	if (TPM2D_ASYM_ALGORITHM == TPM_ALG_RSA) {
		in.inScheme.scheme = TPM_ALG_RSASSA;
		in.inScheme.details.rsassa.hashAlg = TPM2D_HASH_ALGORITHM;
	} else {
		// TPM2D_ASYM_ALGORITHM == TPM_ALG_ECC
		in.inScheme.scheme = TPM_ALG_ECDSA;
		in.inScheme.details.ecdsa.hashAlg = TPM2D_HASH_ALGORITHM;
	}

	in.PCRselect.count = 1;
	in.PCRselect.pcrSelections[0].hash = TPM2D_HASH_ALGORITHM;

	if (qualifying_data != NULL) {
		if (TPM_RC_SUCCESS != (rc = TSS_TPM2B_Create(&in.qualifyingData.b,
				qualifying_data, qualifying_data_len, sizeof(TPMT_HA))))
			goto err;
	} else
		in.qualifyingData.t.size = 0;

	do {
		rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Quote,
			TPM_RS_PW, sig_key_pwd, 0,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	if (rc != TPM_RC_SUCCESS)
		goto err;

	// check if input qualifying data matches output extra data
	BYTE *buf_byte = out.quoted.t.attestationData;
	uint32_t buf_size = out.quoted.t.size;
	if (TPM_RC_SUCCESS != (rc = TSS_TPMS_ATTEST_Unmarshalu(&tpms_attest, &buf_byte, &buf_size)))
		goto err;
	if (!TSS_TPM2B_Compare(&in.qualifyingData.b, &tpms_attest.extraData.b))
		goto err;

	// finally fill the output structure needed for protobuf
	quote = mem_alloc0(sizeof(tpm2d_quote_t));
	quote->halg_id = in.PCRselect.pcrSelections[0].hash;
	quote->quoted_size = out.quoted.t.size;
	quote->quoted_value = mem_new0(uint8_t, out.quoted.t.size);
	memcpy(quote->quoted_value, out.quoted.t.attestationData, out.quoted.t.size);
	size_t signature_size;
	quote->signature_value = tpm2d_marshal_structure_new(&out.signature,
				(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshal, &signature_size);
	quote->signature_size = signature_size;

	if (in.inScheme.scheme == TPM_ALG_RSASSA) {
		TSS_PrintAll("RSA signature", out.signature.signature.rsassa.sig.t.buffer,
					out.signature.signature.rsassa.sig.t.size);
	}
	return quote;
err:
	TSS_TPM_CMD_ERROR(rc, "CC_Quote");
	return NULL;
}

void
tpm2_quote_free(tpm2d_quote_t* quote)
{
	if (quote->quoted_value)
		mem_free(quote->quoted_value);
	if (quote->signature_value)
		mem_free(quote->signature_value);
	mem_free(quote);
}

TPM_RC
tpm2_evictcontrol(TPMI_RH_HIERARCHY auth, char* auth_pwd, TPMI_DH_OBJECT obj_handle,
						 TPMI_DH_PERSISTENT persist_handle)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	EvictControl_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.auth = auth;
	in.objectHandle = obj_handle;
	in.persistentHandle = persist_handle;

	do {
		rc = TSS_Execute(tss_context, NULL, (COMMAND_PARAMETERS *)&in, NULL,
			TPM_CC_EvictControl,
			TPM_RS_PW, auth_pwd, 0,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	if (TPM_RC_SUCCESS != rc)
		TSS_TPM_CMD_ERROR(rc, "CC_EvictControl");

	return rc;
}

TPM_RC
tpm2_rsaencrypt(TPMI_DH_OBJECT key_handle, uint8_t *in_buffer, size_t in_length,
			 uint8_t *out_buffer, size_t *out_length)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	RSA_Encrypt_In in;
	RSA_Encrypt_Out out;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	if (in_length > MAX_RSA_KEY_BYTES) {
	    ERROR("Input buffer exceeds RSA Blocksize %zu\n", in_length);
	    return TSS_RC_INSUFFICIENT_BUFFER;
	}

	in.keyHandle = key_handle;
	/* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */
	in.message.t.size = (uint16_t)in_length;
	memcpy(in.message.t.buffer, in_buffer, in_length);
	/* Table 157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */
	in.inScheme.scheme = TPM_ALG_OAEP;
	in.inScheme.details.oaep.hashAlg = TPM2D_HASH_ALGORITHM;
	/* Table 73 - Definition of TPM2B_DATA Structure */
	in.label.t.size = 0;

	do {
		rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_RSA_Encrypt,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_RSA_encrypt");
		return rc;
	}

	TSS_PrintAll("RSA encrypted data", out.outData.t.buffer, out.outData.t.size);

	// return handle to just created object
	if (out.outData.t.size > *out_length) {
		ERROR("Output buffer (size=%zu) is to small for encrypted data of size %u\n",
						*out_length, out.outData.t.size);
	    return TSS_RC_INSUFFICIENT_BUFFER;
	}
	memcpy(out_buffer, out.outData.t.buffer, out.outData.t.size);

	return rc;
}

TPM_RC
tpm2_rsadecrypt(TPMI_DH_OBJECT key_handle, const char *key_pwd, uint8_t *in_buffer,
			size_t in_length, uint8_t *out_buffer, size_t *out_length)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	RSA_Decrypt_In in;
	RSA_Decrypt_Out out;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	if (in_length > MAX_RSA_KEY_BYTES) {
	    ERROR("Input buffer exceeds RSA block size %zu\n", in_length);
	    return TSS_RC_INSUFFICIENT_BUFFER;
	}

	in.keyHandle = key_handle;
	/* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */
	in.cipherText.t.size = (uint16_t)in_length;
	memcpy(in.cipherText.t.buffer, in_buffer, in_length);
	/* Table 157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */
	in.inScheme.scheme = TPM_ALG_OAEP;
	in.inScheme.details.oaep.hashAlg = TPM2D_HASH_ALGORITHM;
	/* Table 73 - Definition of TPM2B_DATA Structure */
	in.label.t.size = 0;

	do {
		rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_RSA_Decrypt,
			TPM_RS_PW, key_pwd, 0,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_RSA_decrypt");
		return rc;
	}

	TSS_PrintAll("RSA Decrypted message", out.message.t.buffer, out.message.t.size);

	// return handle to just created object
	if (out.message.t.size > *out_length) {
		ERROR("Output buffer (size=%zu) is to small for decrypted message of size %u\n",
						*out_length, out.message.t.size);
	    return TSS_RC_INSUFFICIENT_BUFFER;
	}
	memcpy(out_buffer, out.message.t.buffer, out.message.t.size);
	*out_length = out.message.t.size;

	return rc;
}
#endif // ndef TPM2D_NVMCRYPT_ONLY

TPM_RC
tpm2_hierarchychangeauth(TPMI_RH_HIERARCHY hierarchy, const char *old_pwd,
			const char *new_pwd)
{
	TPM_RC rc, rc_flush = TPM_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	HierarchyChangeAuth_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	in.authHandle = hierarchy;

	if (new_pwd == NULL)
		in.newAuth.b.size = 0;
	else if (TPM_RC_SUCCESS != (rc = TSS_TPM2B_StringCopy(&in.newAuth.b,
					new_pwd, sizeof(TPMU_HA))))
		return rc;

	// since we use this to store symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM_SE_HMAC, &se_handle, hierarchy, old_pwd);
	if (TPM_RC_SUCCESS != rc) goto err;

	do {
		rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_HierarchyChangeAuth,
			se_handle, 0, TPMA_SESSION_DECRYPT|TPMA_SESSION_CONTINUESESSION,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);
err:
	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_HierarchyChangeAuth");
	} else {
		rc = rc_flush;
	}
	return rc;
}

uint8_t *
tpm2_getrandom_new(size_t rand_length)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	GetRandom_In in;
	GetRandom_Out out;

	IF_NULL_RETVAL_ERROR(tss_context, NULL);

	// since we use this to generate symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM_SE_HMAC, &se_handle, TPM_RH_NULL, NULL);
	if (TPM_RC_SUCCESS != rc) return NULL;

	uint8_t *rand = mem_new0(uint8_t, rand_length);
	size_t recv_bytes = 0;
	do {
		in.bytesRequested = rand_length - recv_bytes;
		rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
				(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_GetRandom,
				se_handle, NULL, TPMA_SESSION_ENCRYPT|TPMA_SESSION_CONTINUESESSION,
				TPM_RH_NULL, NULL, 0);
		if (rc != TPM_RC_SUCCESS)
			break;
		memcpy(&rand[recv_bytes], out.randomBytes.t.buffer, out.randomBytes.t.size);
		recv_bytes += out.randomBytes.t.size;
	} while (recv_bytes < rand_length);

	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_GetRandom");
		mem_free(rand);
		return NULL;
	}

	char *rand_hex = convert_bin_to_hex_new(rand, rand_length);
	INFO("Generated Rand: %s", rand_hex);

	mem_free(rand_hex);

	if (TPM_RC_SUCCESS != tpm2_flushcontext(se_handle))
		WARN("Flush failed, maybe session handle was allready flushed.");

	return rand;
}

tpm2d_pcr_t *
tpm2_pcrread_new(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	PCR_Read_In in;
	PCR_Read_Out out;
	tpm2d_pcr_t *pcr = NULL;

	IF_NULL_RETVAL_ERROR(tss_context, NULL);

	/* Table 102 - Definition of TPML_PCR_SELECTION Structure */
	in.pcrSelectionIn.count = 1;
	/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */
	in.pcrSelectionIn.pcrSelections[0].hash = hash_alg;
	in.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[pcr_index / 8] = 1 << (pcr_index % 8);

	do {
		rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_PCR_Read,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_PCR_Read");
		return NULL;
	}

	if (out.pcrValues.count == 0) {
		WARN("CC_PCR_Read returned no values. Seems PCRs are not initialized, reboot System!");
		return NULL;
	}

	INFO("out.pcrValues.digests[0].t.size %d", out.pcrValues.digests[0].t.size);

	// finally fill the output structure needed for protobuf
	pcr = mem_alloc0(sizeof(tpm2d_pcr_t));
	pcr->halg_id = in.pcrSelectionIn.pcrSelections[0].hash;
	pcr->pcr_value = mem_alloc0(sizeof(uint8_t) * out.pcrValues.digests[0].t.size);
	memcpy(pcr->pcr_value, out.pcrValues.digests[0].t.buffer, 
						out.pcrValues.digests[0].t.size);
	pcr->pcr_size = out.pcrValues.digests[0].t.size;
	return pcr;
}

void
tpm2_pcrread_free(tpm2d_pcr_t *pcr)
{
	if (pcr->pcr_value)
		mem_free(pcr->pcr_value);
	mem_free(pcr);
}


size_t
tpm2_nv_get_data_size(TPMI_RH_NV_INDEX nv_index_handle)
{
	NV_ReadPublic_In in;
	NV_ReadPublic_Out out;
	size_t data_size = 0;

	IF_NULL_RETVAL_WARN(tss_context, 0);

	if ((nv_index_handle >> 24) != TPM_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return -1;
	}

	in.nvIndex = nv_index_handle;

	if (TPM_RC_SUCCESS != TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
				(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_NV_ReadPublic,
				TPM_RH_NULL, NULL, 0))
			return 0;

	uint32_t nv_type = (out.nvPublic.nvPublic.attributes.val & TPMA_NVA_TPM_NT_MASK) >> 4;
	if (nv_type == TPM_NT_ORDINARY) {
		data_size = out.nvPublic.nvPublic.dataSize;
	} else {
		WARN("Only ORDINARY data have variable size!");
	}
	INFO("Data size of NV index %x is %zd", nv_index_handle, data_size);

	return data_size;
}

static size_t
tpm2_nv_get_max_buffer_size(TSS_CONTEXT *tss_context)
{
	GetCapability_In in;
	GetCapability_Out out;

	in.capability = TPM_CAP_TPM_PROPERTIES;
	in.property = TPM_PT_NV_BUFFER_MAX;
	in.propertyCount = 1;

	// set a small default fallback value;
	size_t buffer_size = 512;

	IF_NULL_RETVAL_WARN(tss_context, buffer_size);

	if (TPM_RC_SUCCESS != TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
				(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_GetCapability,
				TPM_RH_NULL, NULL, 0)) {
		ERROR("GetCapability failed, returning default value %zd", buffer_size);
		return buffer_size;
	}

	if (out.capabilityData.data.tpmProperties.count > 0 &&
			 out.capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_NV_BUFFER_MAX)
		buffer_size = out.capabilityData.data.tpmProperties.tpmProperty[0].value;
	else
		ERROR("GetCapability failed, returning default value %zd", buffer_size);

	INFO("NV buffer maximum size is set to %zd", buffer_size);
	return buffer_size;
}

TPM_RC
tpm2_nv_definespace(TPMI_RH_HIERARCHY hierarchy, TPMI_RH_NV_INDEX nv_index_handle,
		size_t nv_size, const char *hierarchy_pwd, const char *nv_pwd,
		uint8_t *policy_digest)
{
	TPM_RC rc, rc_flush = TPM_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	NV_DefineSpace_In in;
	TPMA_NV nv_attr;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	if ((nv_index_handle >> 24) != TPM_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TSS_RC_BAD_HANDLE_NUMBER;
	}

	if (nv_pwd == NULL)
		in.auth.b.size = 0;
	else if (TPM_RC_SUCCESS != (rc = TSS_TPM2B_StringCopy(&in.auth.b,
					nv_pwd, sizeof(TPMU_HA))))
		return rc;

	in.authHandle = hierarchy;

	nv_attr.val = 0;
	if (hierarchy == TPM_RH_PLATFORM) {
		nv_attr.val |= TPMA_NVA_PLATFORMCREATE;
		nv_attr.val |= TPMA_NVA_PPWRITE;
		nv_attr.val |= TPMA_NVA_PPREAD;
	} else { // TPM_RH_OWNER
		nv_attr.val |= TPMA_NVA_OWNERWRITE;
		nv_attr.val |= TPMA_NVA_OWNERREAD;
	}
	nv_attr.val |= TPMA_NVA_ORDINARY;
	//nv_attr.val |= TPMA_NVA_AUTHREAD;
	nv_attr.val |= TPMA_NVA_AUTHWRITE;

	// needed to allow readlock
	nv_attr.val |= TPMA_NVA_READ_STCLEAR;

	in.publicInfo.nvPublic.nvIndex = nv_index_handle;
	in.publicInfo.nvPublic.nameAlg = TPM2D_HASH_ALGORITHM;
	in.publicInfo.nvPublic.dataSize = nv_size;

	// set policy
	if (policy_digest) {
		in.publicInfo.nvPublic.authPolicy.b.size = TPM2D_DIGEST_SIZE;
		memcpy(&in.publicInfo.nvPublic.authPolicy.b.buffer, policy_digest, TPM2D_DIGEST_SIZE);
		//rc = TSS_File_Read2B(&in.publicInfo.nvPublic.authPolicy.b, sizeof(TPMU_HA),
		// 		policy_digest_file);
		//if (TPM_RC_SUCCESS != rc) {
		//	ERROR("Failed to read policy digest!");
		//	goto err;
		//}
		if (in.publicInfo.nvPublic.authPolicy.b.size != TPM2D_DIGEST_SIZE) {
			ERROR("digest size mismatch!");
			rc = TPM_RC_POLICY;
			goto err;
		}

		nv_attr.val |= TPMA_NVA_POLICYREAD;
		//nv_attr.val |= TPMA_NVA_POLICYWRITE;
	} else { // set default empty policy
		in.publicInfo.nvPublic.authPolicy.t.size = 0;
		nv_attr.val |= TPMA_NVA_AUTHREAD;
		//nv_attr.val |= TPMA_NVA_AUTHWRITE;
	}

	in.publicInfo.nvPublic.attributes = nv_attr;

	// since we use this to store symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM_SE_HMAC, &se_handle, hierarchy, hierarchy_pwd);
	if (TPM_RC_SUCCESS != rc) goto err;

	do {
		rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_NV_DefineSpace,
			//TPM_RS_PW, hierarchy_pwd, 0,
			se_handle, 0, TPMA_SESSION_DECRYPT|TPMA_SESSION_CONTINUESESSION,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);
err:
	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_DefineSpace");
	} else {
		rc = rc_flush;
	}

	return rc;
}

TPM_RC
tpm2_nv_undefinespace(TPMI_RH_HIERARCHY hierarchy, TPMI_RH_NV_INDEX nv_index_handle,
					const char *hierarchy_pwd)
{
	TPM_RC rc, rc_flush = TPM_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	NV_UndefineSpace_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	if ((nv_index_handle >> 24) != TPM_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TSS_RC_BAD_HANDLE_NUMBER;
	}

	in.authHandle = hierarchy;
	in.nvIndex = nv_index_handle;

	// since we use this to store symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM_SE_HMAC, &se_handle, hierarchy, hierarchy_pwd);
	if (TPM_RC_SUCCESS != rc) goto err;

	do {
		rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_NV_UndefineSpace,
			//TPM_RS_PW, hierarchy_pwd, 0,
			se_handle, 0, TPMA_SESSION_CONTINUESESSION,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);
err:
	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_UndefineSpace");
	} else {
		rc = rc_flush;
	}

	return rc;
}

TPM_RC
tpm2_nv_write(TPMI_RH_NV_INDEX nv_index_handle, const char *nv_pwd,
					uint8_t *data, size_t data_length)
{
	TPM_RC rc, rc_flush = TPM_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	NV_Write_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);
	if ((nv_index_handle >> 24) != TPM_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TSS_RC_BAD_HANDLE_NUMBER;
	}

	in.authHandle = nv_index_handle;
	in.nvIndex = nv_index_handle;
	in.offset = 0;

	size_t buffer_max = tpm2_nv_get_max_buffer_size(tss_context);
	if (data_length > buffer_max) {
		INFO("Only one chunk is supported by this implementation!");
		rc = TSS_RC_INSUFFICIENT_BUFFER;
		goto err;
	}
	memcpy(in.data.b.buffer, data, data_length);
	in.data.b.size = data_length;

	// since we use this to read symetric keys, start an encrypted transport */
	rc = tpm2_startauthsession(TPM_SE_HMAC, &se_handle, nv_index_handle, nv_pwd);
	if (TPM_RC_SUCCESS != rc) goto err;

	do {
		rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_NV_Write,
			se_handle, NULL, TPMA_SESSION_DECRYPT|TPMA_SESSION_CONTINUESESSION,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);
err:
	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_Write");
	} else {
		rc = rc_flush;
	}
	return rc;
}

TPM_RC
tpm2_nv_read(TPMI_SH_POLICY se_handle, TPMI_RH_NV_INDEX nv_index_handle, const char *nv_pwd,
				uint8_t *out_buffer, size_t *out_length)
{
	TPM_RC rc, rc_flush = TPM_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION auth_se_handle;

	NV_Read_In in;
	NV_Read_Out out;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	if ((nv_index_handle >> 24) != TPM_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TSS_RC_BAD_HANDLE_NUMBER;
	}

	in.authHandle = nv_index_handle;
	in.nvIndex = nv_index_handle;

	size_t data_size = tpm2_nv_get_data_size(nv_index_handle);
	size_t buffer_max = tpm2_nv_get_max_buffer_size(tss_context);

	if (data_size > *out_length) {
		ERROR("Output buffer (size=%zd) is to small for nv data of size %zd\n",
						*out_length, data_size);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
		goto err;
	}

	// since we use this to read symetric keys, start an encrypted transport
	if (se_handle == TPM_RH_NULL) {
		rc = tpm2_startauthsession(TPM_SE_HMAC, &auth_se_handle, nv_index_handle, nv_pwd);
		if (TPM_RC_SUCCESS != rc)
			goto err;
	} else {
		INFO("Using provided se_handle");
		auth_se_handle = se_handle;
	}

	in.offset = *out_length = 0;
	do {
		in.size = (data_size > buffer_max) ? buffer_max : data_size;
		INFO("Reading chunk of size=%d", in.size);

		do {
			rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
				(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_NV_Read,
				auth_se_handle, NULL, TPMA_SESSION_ENCRYPT|TPMA_SESSION_CONTINUESESSION,
				TPM_RH_NULL, NULL, 0);
		} while (TPM_RC_RETRY == rc);

		if (TPM_RC_SUCCESS != rc)
			goto flush;

		memcpy(out_buffer+in.offset, out.data.b.buffer, out.data.b.size);
		data_size -= out.data.b.size;
		in.offset += out.data.b.size;
		// set ouput length of caller
		*out_length += out.data.b.size;

	} while (data_size > 0);

	TSS_PrintAll("nv_read data: ", out_buffer, *out_length);

flush:
	rc_flush = tpm2_flushcontext(auth_se_handle);

err:
	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_Read");
	} else {
		rc = rc_flush;
	}
	return rc;
}

TPM_RC
tpm2_nv_readlock(TPMI_RH_NV_INDEX nv_index_handle, const char *nv_pwd)
{
	TPM_RC rc, rc_flush = TPM_RC_SUCCESS;
	TPMI_SH_AUTH_SESSION se_handle;
	NV_ReadLock_In in;

	IF_NULL_RETVAL_ERROR(tss_context, TSS_RC_NULL_PARAMETER);

	if ((nv_index_handle >> 24) != TPM_HT_NV_INDEX) {
		ERROR("bad index handle %x", nv_index_handle);
		return TSS_RC_BAD_HANDLE_NUMBER;
	}

	in.authHandle = nv_index_handle;
	in.nvIndex = nv_index_handle;

	// since we use this to read symetric keys, start an encrypted transport
	rc = tpm2_startauthsession(TPM_SE_HMAC, &se_handle, nv_index_handle, nv_pwd);
	if (TPM_RC_SUCCESS != rc)
		goto err;

	do {
		rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_NV_ReadLock,
			//TPM_RS_PW, nv_pwd, 0,
			se_handle, 0, TPMA_SESSION_CONTINUESESSION,
			TPM_RH_NULL, NULL, 0);
	} while (TPM_RC_RETRY == rc);

	rc_flush = tpm2_flushcontext(se_handle);

err:
	if (TPM_RC_SUCCESS != rc) {
		TSS_TPM_CMD_ERROR(rc, "CC_NV_ReadLock");
	} else {
		rc = rc_flush;
	}
	return rc;
}
