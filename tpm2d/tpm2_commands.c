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

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/tsstransmit.h>
#include <tss2/Unmarshal_fp.h>

#include <tss2/tssprint.h>

/************************************************************************************/
static char *
convert_bin_to_hex_new(const uint8_t *bin, int length)
{
	char *hex = mem_alloc0(sizeof(char)*length*2 + 1);

	for (int i=0; i < length; ++i) {
		// remember snprintf additionally writs a '0' byte
		snprintf(hex+i*2, 3, "%.2x", bin[i]);
	}

	return hex;
}

static uint8_t *
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

static char *
halg_id_to_string_new(TPM_ALG_ID alg_id)
{
	switch (alg_id) {
		case TPM_ALG_SHA1:
			return mem_printf("TPM_ALG_SHA1");
		case TPM_ALG_SHA256:
			return mem_printf("TPM_ALG_SHA256");
		case TPM_ALG_SHA384:
			return mem_printf("TPM_ALG_SHA384");
		default:
			return "NONE";
	}
}

static char *
tpm2d_marshal_structure_new(void *structure, MarshalFunction_t marshal_function)
{
	uint8_t *bin_stream = NULL;
	char *hex_stream = NULL;

	uint16_t written_size = 0;

	if (TPM_RC_SUCCESS != TSS_Structure_Marshal(&bin_stream, &written_size,
						structure, marshal_function)) {
		WARN("no data written to stream!");
		goto err;
	}

	hex_stream = convert_bin_to_hex_new(bin_stream, written_size*2 + 1);
err:
	mem_free(bin_stream);
	return hex_stream;
}

/************************************************************************************/

TPM_RC
tpm2_powerup(void)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

	IF_FALSE_RETVAL(TPM_RC_SUCCESS == (rc = TSS_Create(&tss_context)), rc);

	if (TPM_RC_SUCCESS != (rc = TSS_TransmitPlatform(tss_context, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform")))
		goto err;

	if (TPM_RC_SUCCESS != (rc = TSS_TransmitPlatform(tss_context, TPM_SIGNAL_POWER_ON, "TPM2_PowerOnPlatform")))
		goto err;

	rc = TSS_TransmitPlatform(tss_context, TPM_SIGNAL_NV_ON, "TPM2_NvOnPlatform");
err:
	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_PowerUp failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
	}

	return rc;
}

TPM_RC
tpm2_startup(TPM_SU startup_type)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;

	Startup_In in;
	in.startupType = startup_type;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

	IF_FALSE_RETVAL(TPM_RC_SUCCESS == (rc = TSS_Create(&tss_context)), rc);

	rc = TSS_Execute(tss_context, NULL, (COMMAND_PARAMETERS *)&in, NULL,
			 TPM_CC_Startup, TPM_RH_NULL, NULL, 0);

	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_StartUp failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
	}

	return rc;
}

TPM_RC
tpm2_selftest(void)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;

	SelfTest_In in;
	in.fullTest = YES;

	IF_FALSE_RETVAL(TPM_RC_SUCCESS == (rc = TSS_Create(&tss_context)), rc);

	rc = TSS_Execute(tss_context, NULL, (COMMAND_PARAMETERS *)&in, NULL,
	                 TPM_CC_SelfTest, TPM_RH_NULL, NULL, 0);

	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_SelfTest failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
	}

	return rc;
}

static TPM_RC
tpm2_fill_rsa_details(TPMT_PUBLIC *out_public_area, tpm2d_key_type_t key_type)
{
	ASSERT(out_public_area);

	out_public_area->parameters.rsaDetail.keyBits = 2048;
	out_public_area->parameters.rsaDetail.exponent = 0;

	switch (key_type) {
		case TPM2D_KEY_TYPE_STORAGE:
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
		default:
			ERROR("Keytype not supported for ecc keys!");
			return TPM_RC_VALUE;
			break;
	}

	return TPM_RC_SUCCESS;
}

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
		case TPM2D_KEY_TYPE_STORAGE:
			out_public_area->objectAttributes.val &= ~TPMA_OBJECT_SIGN;
			out_public_area->objectAttributes.val |= TPMA_OBJECT_DECRYPT;
			out_public_area->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
			break;
		case TPM2D_KEY_TYPE_SIGNING_U:
			out_public_area->objectAttributes.val |= TPMA_OBJECT_SIGN;
			out_public_area->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
			out_public_area->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
			break;
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
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;
	CreatePrimary_In in;
	CreatePrimary_Out out;
	TPMA_OBJECT object_attrs;

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
		in.inSensitive.t.sensitive.userAuth.t.size = 0;
	else if (TPM_RC_SUCCESS != (rc = TSS_TPM2B_StringCopy(
				&in.inSensitive.t.sensitive.userAuth.b,
				key_pwd, sizeof(TPMU_HA))))
			return rc;
	in.inSensitive.t.sensitive.data.t.size = 0;

	// fill in TPM2B_PUBLIC
	if (TPM_RC_SUCCESS != (rc = tpm2_public_area_helper(
			&in.inPublic.t.publicArea, object_attrs, key_type)))
		return rc;

	// TPM2B_DATA outsideInfo
	in.outsideInfo.t.size = 0;
	// Table 102 - TPML_PCR_SELECTION creationPCR
	in.creationPCR.count = 0;


	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

	if (TPM_RC_SUCCESS != (rc = TSS_Create(&tss_context)))
		return rc;

	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_CreatePrimary,
			TPM_RS_PW, hierachy_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_CreatePrimary failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
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

TPM_RC
tpm2_create_asym(TPMI_DH_OBJECT parent_handle, tpm2d_key_type_t key_type,
		uint32_t object_vals, const char *parent_pwd, const char *key_pwd,
		const char *file_name_priv_key, const char *file_name_pub_key)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;
	Create_In in;
	Create_Out out;
	TPMA_OBJECT object_attrs;

	in.parentHandle = parent_handle;
	object_attrs.val = object_vals;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

	// Table 134 - Definition of TPM2B_SENSITIVE_CREATE inSensitive
	if (key_pwd == NULL)
		in.inSensitive.t.sensitive.userAuth.t.size = 0;
	else if (TPM_RC_SUCCESS != (rc = TSS_TPM2B_StringCopy(
				&in.inSensitive.t.sensitive.userAuth.b,
				key_pwd, sizeof(TPMU_HA))))
			return rc;
	in.inSensitive.t.sensitive.data.t.size = 0;

	// fill in TPM2B_PUBLIC
	if (TPM_RC_SUCCESS != (rc = tpm2_public_area_helper(
			&in.inPublic.t.publicArea, object_attrs, key_type)))
		return rc;

	// TPM2B_DATA outsideInfo
	in.outsideInfo.t.size = 0;
	// Table 102 - TPML_PCR_SELECTION creationPCR
	in.creationPCR.count = 0;

	IF_FALSE_RETVAL(TPM_RC_SUCCESS == (rc = TSS_Create(&tss_context)), rc);

	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Create,
			TPM_RS_PW, parent_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_Create failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
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

	return rc;
}

TPM_RC
tpm2_load(TPMI_DH_OBJECT parent_handle, const char *parent_pwd,
		const char *file_name_priv_key, const char *file_name_pub_key,
		uint32_t *out_handle)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;
	Load_In in;
	Load_Out out;

        in.parentHandle = parent_handle;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

	if (TPM_RC_SUCCESS != (rc = TSS_File_ReadStructure(&in.inPrivate,
			(UnmarshalFunction_t)TPM2B_PRIVATE_Unmarshal,
			file_name_priv_key)))
		return rc;

	if (TPM_RC_SUCCESS != (rc = TSS_File_ReadStructure(&in.inPublic,
			(UnmarshalFunction_t)TPM2B_PUBLIC_Unmarshal,
			file_name_pub_key)))
		return rc;

	IF_FALSE_RETVAL(TPM_RC_SUCCESS == (rc = TSS_Create(&tss_context)), rc);

	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Load,
			TPM_RS_PW, parent_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_Load failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
		return rc;
	}

	// return handle to just created object
	*out_handle = out.objectHandle;

	return rc;
}

TPM_RC
tpm2_pcrextend(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg, const char *data)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;
	PCR_Extend_In in;
	TPMS_ATTEST tpms_attest;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

	if (strlen(data) > sizeof(TPMU_HA)) {
		ERROR("Data length %d exceeds hash size %d!", strlen(data), sizeof(TPMU_HA));
		return EXIT_FAILURE;
	}

	in.pcrHandle = pcr_index;

	// extend one bank
	in.digests.count = 1;

	// pad and set data
	in.digests.digests[0].hashAlg = TPM2D_HASH_ALGORITHM;
	memset((uint8_t *)&in.digests.digests[0].digest, 0, sizeof(TPMU_HA));
	memcpy((uint8_t *)&in.digests.digests[0].digest, data, strlen(data));

	IF_FALSE_RETVAL(TPM_RC_SUCCESS == (rc = TSS_Create(&tss_context)), rc);

	rc = TSS_Execute(tss_context, NULL,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_PCR_Extend,
			TPM_RS_PW, NULL, 0,
			TPM_RH_NULL, NULL, 0);

	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_PCR_Extend failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
	}

	return rc;
}

tpm2d_pcr_strings_t *
tpm2_pcrread_new(TPMI_DH_PCR pcr_index, TPMI_ALG_HASH hash_alg)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;
	PCR_Read_In in;
	PCR_Read_Out out;
	tpm2d_pcr_strings_t *pcr_strings = NULL;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

	/* Table 102 - Definition of TPML_PCR_SELECTION Structure */
	in.pcrSelectionIn.count = 1;
	/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */
	in.pcrSelectionIn.pcrSelections[0].hash = hash_alg;
	in.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0;
	in.pcrSelectionIn.pcrSelections[0].pcrSelect[pcr_index / 8] = 1 << (pcr_index % 8);

	IF_FALSE_RETVAL(TPM_RC_SUCCESS == (rc = TSS_Create(&tss_context)), NULL);

	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_PCR_Read,
			TPM_RH_NULL, NULL, 0);

	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_PCR_Read failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
		return NULL;
	}

	// finally fill the output structure with converted hex strings needed for protobuf
	pcr_strings = mem_alloc0(sizeof(tpm2d_pcr_strings_t));
	pcr_strings->halg_str = halg_id_to_string_new(in.pcrSelectionIn.pcrSelections[0].hash);
	pcr_strings->pcr_str = convert_bin_to_hex_new(out.pcrValues.digests[0].t.buffer,
						out.pcrValues.digests[0].t.size);
	return pcr_strings;
}

void
tpm2_pcrread_free(tpm2d_pcr_strings_t *pcr_strings)
{
	if (pcr_strings->halg_str)
		mem_free(pcr_strings->halg_str);
	if (pcr_strings->pcr_str)
		mem_free(pcr_strings->pcr_str);
	mem_free(pcr_strings);
}

tpm2d_quote_strings_t *
tpm2_quote_new(TPMI_DH_PCR pcr_indices, TPMI_DH_OBJECT sig_key_handle,
			const char *sig_key_pwd, const char *qualifying_data)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;
	Quote_In in;
	Quote_Out out;
	TPMS_ATTEST tpms_attest;
	uint8_t *qualifying_data_bin = NULL;
	tpm2d_quote_strings_t *quote_strings = NULL;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

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

	IF_FALSE_RETVAL(TPM_RC_SUCCESS == (rc = TSS_Create(&tss_context)), NULL);

	if (qualifying_data != NULL) {
		int length;
		qualifying_data_bin = convert_hex_to_bin_new(qualifying_data, &length);
		IF_NULL_RETVAL(qualifying_data_bin, NULL);
		if (TPM_RC_SUCCESS != (rc = TSS_TPM2B_Create(&in.qualifyingData.b,
				qualifying_data_bin, length, sizeof(TPMT_HA))))
			goto err;
	} else
		in.qualifyingData.t.size = 0;

	rc = TSS_Execute(tss_context, (RESPONSE_PARAMETERS *)&out,
			(COMMAND_PARAMETERS *)&in, NULL, TPM_CC_Quote,
			TPM_RS_PW, sig_key_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	if (rc != TPM_RC_SUCCESS)
		goto err;

	// check if input qualifying data matches output extra data
	BYTE *buf_byte = out.quoted.t.attestationData;
	INT32 size_int32 = out.quoted.t.size;
        if (TPM_RC_SUCCESS != (rc = TPMS_ATTEST_Unmarshal(&tpms_attest, &buf_byte, &size_int32)))
		goto err;
        if (!TSS_TPM2B_Compare(&in.qualifyingData.b, &tpms_attest.extraData.b))
		goto err;

	// finally fill the output structure with converted hex strings needed for protobuf
	quote_strings = mem_alloc0(sizeof(tpm2d_quote_strings_t));
	quote_strings->halg_str = halg_id_to_string_new(in.PCRselect.pcrSelections[0].hash);
	quote_strings->quoted_str = convert_bin_to_hex_new(out.quoted.t.attestationData,
							out.quoted.t.size);
	quote_strings->signature_str = tpm2d_marshal_structure_new(&out.signature,
					(MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshal);

	if (in.inScheme.scheme == TPM_ALG_RSASSA) {
		TSS_PrintAll("RSA signature", out.signature.signature.rsassa.sig.t.buffer,
					out.signature.signature.rsassa.sig.t.size);
	}

	if (qualifying_data_bin)
		mem_free(qualifying_data_bin);
	return quote_strings;
err:
	{
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_Quote failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
	}
	if (qualifying_data_bin)
		mem_free(qualifying_data_bin);
	return NULL;
}

void
tpm2_quote_free(tpm2d_quote_strings_t* quote_strings)
{
	if (quote_strings->halg_str)
		mem_free(quote_strings->halg_str);
	if (quote_strings->quoted_str)
		mem_free(quote_strings->quoted_str);
	if (quote_strings->signature_str)
		mem_free(quote_strings->signature_str);
	mem_free(quote_strings);
}

char *
tpm2_read_file_to_hex_string_new(const char *file_name)
{
	uint8_t *data_bin = NULL;
	size_t len;

	if (TPM_RC_SUCCESS != TSS_File_ReadBinaryFile(&data_bin, &len ,file_name))
		goto err;

	if (data_bin)
		mem_free(data_bin);
	return convert_bin_to_hex_new(data_bin, len);
err:
	if (data_bin)
		mem_free(data_bin);
	return NULL;
}

TPM_RC
tpm2_evictcontrol(TPMI_RH_HIERARCHY auth, char* auth_pwd, TPMI_DH_OBJECT obj_handle,
						 TPMI_DH_PERSISTENT persist_handle)
{
	TPM_RC rc = TPM_RC_SUCCESS;
	TPM_RC rc_del = TPM_RC_SUCCESS;
	TSS_CONTEXT *tss_context = NULL;

	EvictControl_In in;

	in.auth = auth;
	in.objectHandle = obj_handle;
	in.persistentHandle = persist_handle;

	IF_FALSE_RETVAL(TPM_RC_SUCCESS == (rc = TSS_Create(&tss_context)), rc);

	rc = TSS_Execute(tss_context, NULL, (COMMAND_PARAMETERS *)&in, NULL,
			TPM_CC_EvictControl,
			TPM_RS_PW, auth_pwd, 0,
			TPM_RH_NULL, NULL, 0);

	rc_del = TSS_Delete(tss_context);
	if (rc == TPM_RC_SUCCESS)
		rc = rc_del;
	else {
		const char *msg;
		const char *submsg;
		const char *num;
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		ERROR("CC_EvictControl failed, rc %08x: %s%s%s\n", rc, msg, submsg, num);
	}

	return rc;
}
