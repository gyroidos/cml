/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2026 Fraunhofer AISEC
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

// pkcs11 helper for token interface

#include "p11token.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/str.h"
#include "common/uuid.h"
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <openssl/pkcs7.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/cms.h>
#include <openssl/rand.h>

#define CRYPTOKI_GNU 1
#include "pkcs11-lib/pkcs11.h"

#define P11_LABEL_MAX_LEN 32
#define P11_SYM_KEY_BYTES 32 // 256bit key

#define P11_GCM_NONCE_BYTES 12
#define P11_GCM_TAG_BYTES 16

#define P11_CHECK_RV_RETURN(expr)                                                                  \
	do {                                                                                       \
		ck_rv_t rv = expr;                                                                 \
		if (rv != CKR_OK) {                                                                \
			ERROR("Pkcs11 operation '%s' returned Errorcode %lu\n", #expr, rv);        \
			return TOKEN_ERR_FATAL;                                                    \
		}                                                                                  \
	} while (0)

#define P11_CHECK_RV_GOTO(expr, label)                                                             \
	do {                                                                                       \
		ck_rv_t rv = expr;                                                                 \
		if (rv != CKR_OK) {                                                                \
			ERROR("Pkcs11 operation '%s' returned Errorcode %lu\n", #expr, rv);        \
			goto label;                                                                \
		}                                                                                  \
	} while (0)

struct p11token {
	char *module_path;
	// pkcs11 requires special label format
	unsigned char label[P11_LABEL_MAX_LEN];
	struct ck_function_list *ctx;
	ck_session_handle_t *sh;
	void *module;
	const token_t *token;
	ck_mechanism_type_t wrap_mech;
	bool initialized;
};

/**
 * OPENSSL helper functions (Primarily for PKCS7 / CMS support)
 */

typedef struct {
	ASN1_OCTET_STRING *nonce;
	ASN1_INTEGER *icvlen;
} GCM_PARAMS;

ASN1_SEQUENCE(GCM_PARAMS) = {
    ASN1_SIMPLE(GCM_PARAMS, nonce, ASN1_OCTET_STRING),
    ASN1_OPT(GCM_PARAMS, icvlen, ASN1_INTEGER),
} ASN1_SEQUENCE_END(GCM_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(GCM_PARAMS)

typedef enum { CIPHER_CLASS_GCM, CIPHER_CLASS_KEYWRAP } cipher_class_t;

typedef struct {
	cipher_class_t cipher_class;
	unsigned char nonce[P11_GCM_NONCE_BYTES]; /* GCM only */
} p11_cipher_params_t;

static int
int_pkcs11_wrap_to_pkcs7(const unsigned char *ciphertext, size_t ct_len,
			 const p11_cipher_params_t *params, unsigned char **out_der,
			 int *out_der_len)
{
	PKCS7 *p7 = NULL;
	X509_ALGOR *alg = NULL;
	ASN1_OCTET_STRING *enc_os = NULL;
	GCM_PARAMS *gp = NULL;
	unsigned char *param_der = NULL;
	ASN1_STRING *param_str = NULL;
	unsigned char *der = NULL;
	int der_len = 0;
	int ret = 0;

	*out_der = NULL;
	*out_der_len = 0;

	p7 = PKCS7_new();
	IF_NULL_GOTO(p7, err);

	IF_FALSE_GOTO(PKCS7_set_type(p7, NID_pkcs7_encrypted), err);

	alg = p7->d.encrypted->enc_data->algorithm;

	if (params->cipher_class == CIPHER_CLASS_GCM) {
		int param_der_len;

		gp = GCM_PARAMS_new();
		IF_NULL_GOTO(gp, err);
		IF_FALSE_GOTO(ASN1_OCTET_STRING_set(gp->nonce, params->nonce, P11_GCM_NONCE_BYTES),
			      err);
		gp->icvlen = ASN1_INTEGER_new();
		IF_NULL_GOTO(gp->icvlen, err);
		IF_FALSE_GOTO(ASN1_INTEGER_set(gp->icvlen, P11_GCM_TAG_BYTES), err);

		param_der_len = i2d_GCM_PARAMS(gp, &param_der);
		IF_TRUE_GOTO(param_der_len <= 0, err);

		param_str = ASN1_STRING_new();
		IF_NULL_GOTO(param_str, err);
		IF_FALSE_GOTO(ASN1_STRING_set(param_str, param_der, param_der_len), err);

		IF_FALSE_GOTO(X509_ALGOR_set0(alg, OBJ_nid2obj(NID_aes_256_gcm), V_ASN1_SEQUENCE,
					      param_str),
			      err);
		param_str = NULL; /* ownership transferred to alg */
	} else {
		IF_FALSE_GOTO(X509_ALGOR_set0(alg, OBJ_nid2obj(NID_id_aes256_wrap_pad),
					      V_ASN1_UNDEF, NULL),
			      err);
	}

	enc_os = ASN1_OCTET_STRING_new();
	IF_NULL_GOTO(enc_os, err);
	IF_FALSE_GOTO(ASN1_OCTET_STRING_set(enc_os, ciphertext, (int)ct_len), err);
	p7->d.encrypted->enc_data->enc_data = enc_os;
	enc_os = NULL;

	der_len = i2d_PKCS7(p7, &der);
	IF_TRUE_GOTO(der_len <= 0, err);

	*out_der = der;
	*out_der_len = der_len;
	ret = 1;

err:
	if (!ret) {
		ERROR("PKCS#7 wrap failed: %s", ERR_error_string(ERR_get_error(), NULL));
		OPENSSL_free(der);
		ASN1_OCTET_STRING_free(enc_os);
	}
	OPENSSL_free(param_der);
	ASN1_STRING_free(param_str);
	GCM_PARAMS_free(gp);
	PKCS7_free(p7);
	return ret;
}

static int
int_pkcs7_unwrap_to_pkcs11(const unsigned char *der, int der_len, p11_cipher_params_t *params,
			   unsigned char **ciphertext, size_t *ct_len)
{
	PKCS7 *p7 = NULL;
	const unsigned char *p = der;
	X509_ALGOR *alg = NULL;
	ASN1_OCTET_STRING *enc_content = NULL;
	const ASN1_OBJECT *alg_obj = NULL;
	GCM_PARAMS *gp = NULL;
	int ptype = 0;
	const void *pval = NULL;
	int nid;
	int ret = 0;

	memset(params, 0, sizeof(*params));
	*ciphertext = NULL;

	p7 = d2i_PKCS7(NULL, &p, der_len);
	IF_NULL_GOTO(p7, err);

	if (!PKCS7_type_is_encrypted(p7)) {
		ERROR("Not PKCS#7 EncryptedData");
		goto err;
	}

	alg = p7->d.encrypted->enc_data->algorithm;
	IF_NULL_GOTO(alg, err);

	X509_ALGOR_get0(&alg_obj, &ptype, &pval, alg);

	nid = OBJ_obj2nid(alg_obj);

	if (nid == NID_aes_256_gcm) {
		const ASN1_STRING *seq;
		const unsigned char *sp;

		params->cipher_class = CIPHER_CLASS_GCM;

		IF_TRUE_GOTO(ptype != V_ASN1_SEQUENCE || !pval, err);

		seq = (const ASN1_STRING *)pval;
		sp = ASN1_STRING_get0_data(seq);
		gp = d2i_GCM_PARAMS(NULL, &sp, ASN1_STRING_length(seq));
		IF_NULL_GOTO(gp, err);

		IF_TRUE_GOTO(gp->nonce->length != P11_GCM_NONCE_BYTES, err);
		memcpy(params->nonce, gp->nonce->data, P11_GCM_NONCE_BYTES);

		IF_TRUE_GOTO(gp->icvlen && ASN1_INTEGER_get(gp->icvlen) != P11_GCM_TAG_BYTES, err);

	} else if (nid == NID_id_aes256_wrap_pad) {
		params->cipher_class = CIPHER_CLASS_KEYWRAP;

	} else {
		ERROR("Unsupported cipher OID");
		goto err;
	}

	enc_content = p7->d.encrypted->enc_data->enc_data;
	IF_NULL_GOTO(enc_content, err);

	*ct_len = (size_t)ASN1_STRING_length(enc_content);
	*ciphertext = OPENSSL_memdup(ASN1_STRING_get0_data(enc_content), *ct_len);
	IF_NULL_GOTO(*ciphertext, err);

	ret = 1;

err:
	if (!ret) {
		ERROR("PKCS#7 unwrap failed: %s", ERR_error_string(ERR_get_error(), NULL));
		OPENSSL_free(*ciphertext);
		*ciphertext = NULL;
	}
	GCM_PARAMS_free(gp);
	PKCS7_free(p7);
	return ret;
}

/**
 * Internal Helper Functions
 */
static void
int_unload_module(void *module)
{
	ASSERT(module);
	dlclose(module);
}

static void *
int_load_module(const char *path, struct ck_function_list **ctx)
{
	void *module = dlopen(path, RTLD_LAZY);
	if (module == NULL) {
		ERROR("dlopen failed: %s\n", dlerror());
		return NULL;
	}

	/**
	 *  Maybe relevant if PKCS11 v3.0 is supported by the module and certain
	 *  > 3.0 functions are needed.
	 *  For now we just use the old way of getting the function list, which
	 *  is supported by all versions.
	 */
	/*ck_rv_t (*get_interface)(unsigned char *interface_name, struct ck_version *version,
				 struct ck_interface **interface_, ck_flags_t flags) =
		CAST(ck_rv_t (*)(unsigned char *interface_name, struct ck_version *version,
				 struct ck_interface **interface_, ck_flags_t flags))
			dlsym(module, "C_GetInterface");
	if (get_interface == NULL) {
		ERROR("dlsym failed: %s\n", dlerror());
		goto error;
	}
	struct ck_interface *interface = NULL;
	P11_CHECK_RV_GOTO(get_interface((unsigned char *)"PKCS 11", NULL, &interface, 0), error);
	*ctx = interface->function_list_ptr;*/

	ck_rv_t (*get_function_list)(struct ck_function_list **) =
		CAST(ck_rv_t(*)(struct ck_function_list **)) dlsym(module, "C_GetFunctionList");
	if (get_function_list == NULL) {
		ERROR("dlsym failed: %s\n", dlerror());
		goto error;
	}
	P11_CHECK_RV_GOTO(get_function_list(ctx), error);

	return module;

error:
	int_unload_module(module);
	return NULL;
}
/**
 * get next free slot id
*/
static ck_slot_id_t *
int_get_free_slot_id_new(struct ck_function_list *ctx)
{
	ASSERT(ctx);

	unsigned long slot_count = 0;
	ck_slot_id_t *p_slots = NULL;

	/**
	 * only slots that have a token present can be initialized with C_InitToken;
	 * use token_present=true consistently for both the count and the fill call
	 */
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(true, NULL, &slot_count), error);
	p_slots = (ck_slot_id_t *)mem_alloc(slot_count * sizeof(ck_slot_id_t));
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(true, p_slots, &slot_count), error);

	for (unsigned long i = 0; i < slot_count; i++) {
		ck_rv_t rv = CKR_OK;
		struct ck_token_info token_info;
		if ((rv = ctx->C_GetTokenInfo(p_slots[i], &token_info)) == CKR_OK) {
			// a free slot holds a token that is not yet initialized
			if (!(token_info.flags & CKF_TOKEN_INITIALIZED)) {
				ck_slot_id_t *free_slot = mem_alloc(sizeof(ck_slot_id_t));
				*free_slot = p_slots[i];

				mem_free(p_slots);
				return free_slot;
			}
		} else {
			WARN("Retrieving Info for slot %lu failed with %lu", p_slots[i], rv);
		}
	}

error:
	if (p_slots) {
		mem_free(p_slots);
	}
	return NULL;
}

/**
 * find token by label
*/
static ck_slot_id_t *
int_get_token_slot_id_new(struct ck_function_list *ctx, const unsigned char *label)
{
	ASSERT(ctx);
	ASSERT(label);

	// get slot list
	ck_slot_id_t *p_slots = NULL;
	unsigned long slot_count = 0;
	/**
	 * only slots with a token present can carry the label we search for; use
	 * token_present=true consistently so the fill call cannot need a larger
	 * buffer than was counted/allocated (would yield CKR_BUFFER_TOO_SMALL)
	 */
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(true, NULL, &slot_count), error);
	p_slots = (ck_slot_id_t *)mem_alloc(slot_count * sizeof(ck_slot_id_t));
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(true, p_slots, &slot_count), error);

	for (unsigned long i = 0; i < slot_count; i++) {
		ck_rv_t rv = CKR_OK;
		struct ck_token_info token_info;
		if ((rv = ctx->C_GetTokenInfo(p_slots[i], &token_info)) == CKR_OK) {
			if (0 ==
			    strncmp((char *)token_info.label, (char *)label, P11_LABEL_MAX_LEN)) {
				ck_slot_id_t *slot_id =
					(ck_slot_id_t *)mem_alloc(sizeof(ck_slot_id_t));
				*slot_id = p_slots[i];

				mem_free(p_slots);
				return slot_id;
			}
		} else {
			WARN("Retrieving Info for slot %lu failed with %lu", p_slots[i], rv);
		}
	}
error:
	if (p_slots) {
		mem_free(p_slots);
	}
	return NULL;
}

/**
 * Converts a string into a token label: must not be null-terminated according to spec
*/
static unsigned char *
int_token_label_new(const char *label)
{
	ASSERT(label);

	size_t len_label = strlen(label);
	unsigned char *token_label = mem_alloc0(P11_LABEL_MAX_LEN);
	if (len_label <= P11_LABEL_MAX_LEN) {
		memcpy(token_label, label, len_label);

		// pad remaining space
		for (size_t i = len_label; i < P11_LABEL_MAX_LEN; i++) {
			token_label[i] = ' ';
		}
	} else {
		// label is too long: truncate
		memcpy(token_label, label, P11_LABEL_MAX_LEN);
	}

	return token_label;
}

/**
 * Probe the token's supported key-wrapping mechanism and store it in
 * p11_token->wrap_mech (prefers AES_KEY_WRAP_KWP, falls back to AES_GCM).
 *
 * wrap_mech is not persisted, so it must be (re-)derived both on first-time
 * provisioning and whenever an existing token is re-opened (e.g. after an scd
 * restart); otherwise p11token_wrap_key would hit the "no supported mechanism"
 * default branch.
 *
 * @return TOKEN_ERR_OK on success, TOKEN_ERR_FATAL otherwise
*/
static token_err_t
int_probe_wrap_mech(struct ck_function_list *ctx, ck_slot_id_t slot, p11token_t *p11_token)
{
	ASSERT(ctx);
	ASSERT(p11_token);

	token_err_t ret = TOKEN_ERR_FATAL;
	unsigned long mech_count = 0;
	ck_mechanism_type_t *mech_list = NULL;

	P11_CHECK_RV_GOTO(ctx->C_GetMechanismList(slot, NULL, &mech_count), out);
	mech_list = (ck_mechanism_type_t *)mem_alloc(mech_count * sizeof(ck_mechanism_type_t));
	P11_CHECK_RV_GOTO(ctx->C_GetMechanismList(slot, mech_list, &mech_count), out);

	struct ck_mechanism_info mech_info;
	for (unsigned long i = 0; i < mech_count; i++) {
		switch (mech_list[i]) {
		case CKM_AES_GCM:
			P11_CHECK_RV_GOTO(ctx->C_GetMechanismInfo(slot, mech_list[i], &mech_info),
					  out);
			if ((mech_info.flags & CKF_ENCRYPT) && (mech_info.flags & CKF_DECRYPT)) {
				if (p11_token->wrap_mech != CKM_AES_KEY_WRAP_KWP) {
					p11_token->wrap_mech = CKM_AES_GCM;
					WARN("PKCS11: no proper mechanism supported, use AES_GCM fallback");
				}
			}
			break;
		case CKM_AES_KEY_WRAP_KWP:
			P11_CHECK_RV_GOTO(ctx->C_GetMechanismInfo(slot, mech_list[i], &mech_info),
					  out);
			if ((mech_info.flags & CKF_ENCRYPT) && (mech_info.flags & CKF_DECRYPT)) {
				p11_token->wrap_mech = CKM_AES_KEY_WRAP_KWP;
				INFO("PKCS11: use AES_KEY_WRAP_KWP");
				goto found;
			}
			break;
		default:
			continue;
		}
	}
found:
	if (p11_token->wrap_mech != CKM_AES_KEY_WRAP_KWP && p11_token->wrap_mech != CKM_AES_GCM) {
		ERROR("No supported encryption mechanism found");
		goto out;
	}
	ret = TOKEN_ERR_OK;
out:
	if (mech_list) {
		mem_free(mech_list);
	}
	return ret;
}

/**
 * Create new PKCS#11 token.
 * @param p11_token pointer to the PKCS#11 token structure
 * @param so_pin pin which should be used by the SO (only required for initialisation)
 * @param user_pin pin which should be used for day to day usage
 * @return TOKEN_ERR_OK on success
*/
static token_err_t
int_init_token(p11token_t *p11_token, const char *so_pin, const char *user_pin)
{
	ASSERT(p11_token);
	ASSERT(so_pin);
	ASSERT(user_pin);

	struct ck_function_list *ctx = NULL;
	ck_slot_id_t *slot = NULL;
	// load pkcs11-module (load dll at runtime)
	void *module = int_load_module(p11_token->module_path, &ctx);
	if (module == NULL) {
		ERROR("Could not load pkcs11 module");
		goto error_init;
	}

	// init library
	P11_CHECK_RV_GOTO(ctx->C_Initialize(NULL), error_init);

	// get free slot
	slot = int_get_free_slot_id_new(ctx);
	IF_TRUE_GOTO_ERROR(slot == NULL, error);

	// initialize token on free slot
	P11_CHECK_RV_GOTO(ctx->C_InitToken(*slot, (unsigned char *)so_pin, strlen(so_pin),
					   p11_token->label),
			  error);

	// probe and store the supported wrapping mechanism
	if (TOKEN_ERR_OK != int_probe_wrap_mech(ctx, *slot, p11_token)) {
		goto error;
	}

	// connect to token
	ck_session_handle_t sh;
	P11_CHECK_RV_GOTO(ctx->C_OpenSession(*slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL,
					     &sh),
			  error);

	// login as SO
	P11_CHECK_RV_GOTO(ctx->C_Login(sh, CKU_SO, (unsigned char *)so_pin, strlen(so_pin)),
			  error_session);

	// set user pin
	P11_CHECK_RV_GOTO(ctx->C_InitPIN(sh, (unsigned char *)user_pin, strlen(user_pin)),
			  error_session);

	// logout SO
	P11_CHECK_RV_GOTO(ctx->C_Logout(sh), error_session);

	// login as user
	P11_CHECK_RV_GOTO(ctx->C_Login(sh, CKU_USER, (unsigned char *)user_pin, strlen(user_pin)),
			  error_session);

	// create symmetric key
	ck_object_handle_t h_key;
	struct ck_mechanism mechanism = { CKM_AES_KEY_GEN, NULL, 0 };
	ck_key_type_t aes_type = CKK_AES;
	unsigned long length = P11_SYM_KEY_BYTES;
	bool y = true;
	bool n = false;
	struct ck_attribute aes_key_template[] = {
		{ CKA_KEY_TYPE, &aes_type, sizeof(aes_type) },
		{ CKA_TOKEN, &y, sizeof(y) },	    // persistently store key on token
		{ CKA_EXTRACTABLE, &n, sizeof(n) }, // key should not be extractable
		{ CKA_LABEL, p11_token->label, P11_LABEL_MAX_LEN },
		{ CKA_VALUE_LEN, &length, sizeof(length) },
	};
	P11_CHECK_RV_GOTO(ctx->C_GenerateKey(sh, &mechanism, aes_key_template,
					     ELEMENTSOF(aes_key_template), &h_key),
			  error_session);

	// logout user
	P11_CHECK_RV_GOTO(ctx->C_Logout(sh), error_session);

	// terminate token-session
	P11_CHECK_RV_GOTO(ctx->C_CloseSession(sh), error);

	// Unload Module
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
	int_unload_module(module);

	// free slot id ptr
	mem_free(slot);

	p11_token->initialized = true;
	return TOKEN_ERR_OK;
error_session:
	P11_CHECK_RV_GOTO(ctx->C_CloseSession(sh), error);
error:
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
error_init:
	if (slot) {
		mem_free(slot);
	}
	if (module) {
		int_unload_module(module);
	}
	return TOKEN_ERR_FATAL;
}

/**
 * Get token by label.
 * @param module_path path to PKCS#11 module library (e.g. libsofthsm2)
 * @param label label of the desired token
 * @return Success: pointer to token; Error: NULL
*/
static p11token_t *
int_token_by_label(const char *module_path, const char *label)
{
	ASSERT(module_path);
	ASSERT(label);

	struct ck_function_list *ctx = NULL;
	unsigned char *token_label = NULL;
	ck_slot_id_t *slot = NULL;
	// load module
	void *module = int_load_module(module_path, &ctx);
	if (module == NULL) {
		ERROR("Could not load pkcs11 module");
		goto error_init;
	}

	// init library
	P11_CHECK_RV_GOTO(ctx->C_Initialize(NULL), error_init);

	// check if token exists
	token_label = int_token_label_new(label);
	slot = int_get_token_slot_id_new(ctx, token_label);
	if (slot == NULL) {
		INFO("token for %s not found", label);
		goto error; // cleanup and return null
	}

	// cleanup
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
	int_unload_module(module);

	// if token exists create new token-object
	p11token_t *token = (p11token_t *)mem_new0(p11token_t, 1);
	token->module_path = mem_strdup(module_path);
	memcpy(token->label, token_label, P11_LABEL_MAX_LEN);
	// free label
	mem_free0(token_label);
	// free slot id ptr
	mem_free(slot);

	token->ctx = NULL;
	token->sh = NULL;
	token->module = NULL;
	token->initialized = true;
	return token;
error:
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
error_init:
	if (token_label) {
		mem_free(token_label);
	}
	if (slot) {
		mem_free(slot);
	}
	if (module) {
		int_unload_module(module);
	}
	return NULL;
}

// TODO: use pairing secret?
static token_err_t
p11token_unlock(void *int_token, const char *passwd, UNUSED const unsigned char *pairing_secret,
		UNUSED size_t pairing_sec_len)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);
	ASSERT(passwd);

	ck_slot_id_t *slot_id = NULL;

	token_err_t ret = TOKEN_ERR_FATAL;

	if (token_is_locked_till_reboot(p11_token->token)) {
		WARN("PKCS11 token: too many failed unlock attempts");
		return TOKEN_ERR_LOCKED_TILL_REBOOT;
	}

	/**
	 * An open session handle is the ground truth for "already unlocked".
	 * Do not rely on the generic token->locked flag here: p11token_unlock may
	 * be invoked directly (e.g. from p11token_change_pin) without going through
	 * the token_unlock() wrapper that maintains that flag.
	 */
	if (p11_token->sh) {
		WARN("Pkcs11 token is already unlocked");
		return TOKEN_ERR_OK;
	}
	// load library and connect to token
	p11_token->module = int_load_module(p11_token->module_path, &p11_token->ctx);
	if (p11_token->module == NULL) {
		ERROR("Could not load pkcs11 module");
		goto error_init;
	}

	P11_CHECK_RV_GOTO(p11_token->ctx->C_Initialize(NULL), error_init);

	// search token
	slot_id = int_get_token_slot_id_new(p11_token->ctx, p11_token->label);
	IF_TRUE_GOTO_ERROR(slot_id == NULL, error);
	// create session handle
	p11_token->sh = (ck_session_handle_t *)mem_alloc0(sizeof(ck_session_handle_t));

	// connect to token
	P11_CHECK_RV_GOTO(p11_token->ctx->C_OpenSession(*slot_id,
							CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL,
							NULL, p11_token->sh),
			  error);

	/**
	 * wrap_mech is not persisted; (re-)derive it on every unlock so a wrap
	 * after an scd restart does not fail with "no supported mechanism"
	 */
	if (0 == p11_token->wrap_mech &&
	    TOKEN_ERR_OK != int_probe_wrap_mech(p11_token->ctx, *slot_id, p11_token)) {
		goto error;
	}

	mem_free(slot_id);
	slot_id = NULL;

	// login
	switch (p11_token->ctx->C_Login(*p11_token->sh, CKU_USER, (unsigned char *)passwd,
					strlen(passwd))) {
	case CKR_OK:
		return TOKEN_ERR_OK;
	case CKR_PIN_INCORRECT:
		ret = TOKEN_ERR_PW;
		break;
	default:
		DEBUG("C_Login returnvalue unexpected");
	}

	P11_CHECK_RV_GOTO(p11_token->ctx->C_CloseSession(*p11_token->sh), error);
error:
	if (p11_token->sh) {
		mem_free(p11_token->sh);
		p11_token->sh = NULL;
	}
	if (slot_id) {
		mem_free(slot_id);
	}
	P11_CHECK_RV_GOTO(p11_token->ctx->C_Finalize(NULL), error_init);
	p11_token->ctx = NULL;
error_init:

	if (p11_token->module) {
		int_unload_module(p11_token->module);
		p11_token->module = NULL;
	}
	return ret;
}

static token_err_t
p11token_lock(void *int_token)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);

	/**
	 * Tear down based on our own session state, not the generic token->locked
	 * flag: when called directly (e.g. from p11token_change_pin) that flag is
	 * not maintained, and keying off it would skip C_Logout/C_CloseSession/
	 * C_Finalize/dlclose, leaking the session and leaving the module
	 * C_Initialize'd (breaking the next unlock with CKR_CRYPTOKI_ALREADY_INITIALIZED).
	 */
	if (NULL == p11_token->sh) {
		WARN("Pkcs11 token is already locked");
		return TOKEN_ERR_OK;
	}

	P11_CHECK_RV_RETURN(p11_token->ctx->C_Logout(*p11_token->sh));

	P11_CHECK_RV_RETURN(p11_token->ctx->C_CloseSession(*p11_token->sh));
	mem_free0(p11_token->sh);
	p11_token->sh = NULL;

	P11_CHECK_RV_RETURN(p11_token->ctx->C_Finalize(NULL));
	p11_token->ctx = NULL;

	if (p11_token->module) {
		int_unload_module(p11_token->module);
		p11_token->module = NULL;
	}

	return TOKEN_ERR_OK;
}

static token_err_t
p11token_wrap_key(void *int_token, UNUSED const char *label, unsigned char *plain_key,
		  size_t plain_key_len, unsigned char **wrapped_key, int *wrapped_key_len)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);
	ASSERT(plain_key);
	ASSERT(wrapped_key);
	ASSERT(wrapped_key_len);

	token_err_t ret = TOKEN_ERR_FATAL;

	unsigned char *ct = NULL;

	if (token_is_locked(p11_token->token)) {
		ERROR("p11token_wrap_key: token is locked");
		ret = TOKEN_ERR_LOCKED;
		goto error;
	}

	/**
	 * get wrapping key handle
	 * currently there is only one, therefore we can keep the search template simple
	 */
	ck_key_type_t aes_key_type = CKK_AES;
	struct ck_attribute search_template[] = {
		{ CKA_KEY_TYPE, &aes_key_type, sizeof(aes_key_type) },
	};
	P11_CHECK_RV_GOTO(p11_token->ctx->C_FindObjectsInit(*p11_token->sh, search_template,
							    ELEMENTSOF(search_template)),
			  error);
	ck_object_handle_t h_key;
	unsigned long num_objects_found;
	P11_CHECK_RV_GOTO(p11_token->ctx->C_FindObjects(*p11_token->sh, &h_key, 1,
							&num_objects_found),
			  error);
	P11_CHECK_RV_GOTO(p11_token->ctx->C_FindObjectsFinal(*p11_token->sh), error);
	if (0 == num_objects_found) {
		ERROR("\nwrapping key not found\n");
		goto error;
	}

	unsigned char iv[P11_GCM_NONCE_BYTES] = { 0 };
	struct ck_gcm_params gcm_params;
	struct ck_mechanism wrap_mechanism;
	switch (p11_token->wrap_mech) {
	case CKM_AES_GCM:
		P11_CHECK_RV_GOTO(p11_token->ctx->C_GenerateRandom(*p11_token->sh, iv,
								   P11_GCM_NONCE_BYTES),
				  error);
		gcm_params.iv_ptr = iv;
		gcm_params.iv_len = P11_GCM_NONCE_BYTES;
		gcm_params.iv_bits = P11_GCM_NONCE_BYTES * 8;
		gcm_params.aad_ptr = NULL;
		gcm_params.aad_len = 0;
		gcm_params.tag_bits = P11_GCM_TAG_BYTES * 8; // == 16b tag
		wrap_mechanism.mechanism = CKM_AES_GCM;
		wrap_mechanism.parameter = &gcm_params;
		wrap_mechanism.parameter_len = sizeof(gcm_params);
		break;
	case CKM_AES_KEY_WRAP_KWP:
		wrap_mechanism.mechanism = CKM_AES_KEY_WRAP_KWP;
		wrap_mechanism.parameter = NULL;
		wrap_mechanism.parameter_len = 0;
		break;
	default:
		ERROR("no supported mechanism for encryption found");
		goto error;
	}

	P11_CHECK_RV_GOTO(p11_token->ctx->C_EncryptInit(*p11_token->sh, &wrap_mechanism, h_key),
			  error);
	/**
	 *  retrieve buffer size; PKCS#11 expects a ck_ulong (8 byte on LP64), so use a
	 *  dedicated local instead of aliasing the caller's int out-param
	 */
	unsigned long ct_len = 0;
	P11_CHECK_RV_GOTO(p11_token->ctx->C_Encrypt(*p11_token->sh, plain_key, plain_key_len, NULL,
						    &ct_len),
			  error);
	ct = (unsigned char *)mem_alloc0(ct_len);
	IF_TRUE_GOTO_DEBUG(NULL == ct, error);
	P11_CHECK_RV_GOTO(p11_token->ctx->C_Encrypt(*p11_token->sh, plain_key, plain_key_len, ct,
						    &ct_len),
			  error);
	IF_TRUE_GOTO_ERROR(ct_len > INT_MAX, error);

	// wrap ciphertext in PKCS#7 structure
	p11_cipher_params_t wrap_params = { .cipher_class = (p11_token->wrap_mech == CKM_AES_GCM) ?
								    CIPHER_CLASS_GCM :
								    CIPHER_CLASS_KEYWRAP };
	memcpy(wrap_params.nonce, iv, P11_GCM_NONCE_BYTES);
	if (!int_pkcs11_wrap_to_pkcs7(ct, ct_len, &wrap_params, wrapped_key, wrapped_key_len)) {
		ERROR("Failed to serialize wrapped key to PKCS#7");
		goto error;
	}

	mem_free0(ct);

	return TOKEN_ERR_OK;
error:
	if (ct) {
		// assure memory is cleared before freeing, as it may contain sensitive data
		mem_memset0(ct, ct_len);
		mem_free0(ct);
	}
	return ret;
}

static token_err_t
p11token_unwrap_key(void *int_token, UNUSED const char *label, unsigned char *wrapped_key,
		    size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);
	ASSERT(wrapped_key);
	ASSERT(plain_key);
	ASSERT(plain_key_len);

	token_err_t ret = TOKEN_ERR_FATAL;

	unsigned char *pt = NULL;

	if (token_is_locked(p11_token->token)) {
		ERROR("p11token_unwrap_key: token is locked");
		ret = TOKEN_ERR_LOCKED;
		goto error;
	}

	// get ciphertext and cipher params from PKCS#7 structure
	unsigned char *ct = NULL;
	size_t ct_len;
	p11_cipher_params_t cipher_params;
	if (!int_pkcs7_unwrap_to_pkcs11(wrapped_key, wrapped_key_len, &cipher_params, &ct,
					&ct_len)) {
		ERROR("Failed to parse PKCS#7 structure");
		goto error;
	}

	/**
	 * get wrapping key handle
	 * currently there is only one, therefore we can keep the search template simple
	 */
	ck_key_type_t aes_key_type = CKK_AES;
	struct ck_attribute search_template[] = {
		{ CKA_KEY_TYPE, &aes_key_type, sizeof(aes_key_type) },
	};
	P11_CHECK_RV_GOTO(p11_token->ctx->C_FindObjectsInit(*p11_token->sh, search_template,
							    ELEMENTSOF(search_template)),
			  error);
	ck_object_handle_t h_key;
	unsigned long num_objects_found;
	P11_CHECK_RV_GOTO(p11_token->ctx->C_FindObjects(*p11_token->sh, &h_key, 1,
							&num_objects_found),
			  error);
	P11_CHECK_RV_GOTO(p11_token->ctx->C_FindObjectsFinal(*p11_token->sh), error);
	if (0 == num_objects_found) {
		goto error;
	}

	struct ck_gcm_params gcm_params;
	struct ck_mechanism wrap_mechanism;
	switch (cipher_params.cipher_class) {
	case CIPHER_CLASS_GCM:
		gcm_params.iv_ptr = cipher_params.nonce;
		gcm_params.iv_len = P11_GCM_NONCE_BYTES;
		gcm_params.iv_bits = P11_GCM_NONCE_BYTES * 8;
		gcm_params.aad_ptr = NULL;
		gcm_params.aad_len = 0;
		gcm_params.tag_bits = P11_GCM_TAG_BYTES * 8;
		wrap_mechanism.mechanism = CKM_AES_GCM;
		wrap_mechanism.parameter = &gcm_params;
		wrap_mechanism.parameter_len = sizeof(gcm_params);
		break;
	case CIPHER_CLASS_KEYWRAP:
		wrap_mechanism.mechanism = CKM_AES_KEY_WRAP_KWP;
		wrap_mechanism.parameter = NULL;
		wrap_mechanism.parameter_len = 0;
		break;
	default:
		ERROR("no supported mechanism for encryption found");
		goto error;
	}

	P11_CHECK_RV_GOTO(p11_token->ctx->C_DecryptInit(*p11_token->sh, &wrap_mechanism, h_key),
			  error);
	/**
	 * PKCS#11 expects a ck_ulong (8 byte on LP64), so use a dedicated local
	 * instead of aliasing the caller's int out-param
	 */
	unsigned long pt_len = 0;
	P11_CHECK_RV_GOTO(p11_token->ctx->C_Decrypt(*p11_token->sh, ct, ct_len, NULL, &pt_len),
			  error);
	pt = (unsigned char *)mem_alloc0(pt_len);
	IF_TRUE_GOTO_DEBUG(NULL == pt, error);
	P11_CHECK_RV_GOTO(p11_token->ctx->C_Decrypt(*p11_token->sh, ct, ct_len, pt, &pt_len),
			  error);
	IF_TRUE_GOTO_ERROR(pt_len > INT_MAX, error);
	*plain_key = pt;
	*plain_key_len = (int)pt_len;

	return TOKEN_ERR_OK;
error:
	if (pt) {
		// assure memory is cleared before freeing, as it may contain sensitive data
		mem_memset0(pt, pt_len);
		mem_free0(pt);
	}
	return ret;
}

static token_err_t
p11token_change_pin(void *int_token, const char *oldpass, const char *newpass,
		    UNUSED const unsigned char *pairing_secret, UNUSED size_t pairing_sec_len,
		    UNUSED bool is_provisioning)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);
	ASSERT(oldpass);
	ASSERT(newpass);

	token_err_t ret = TOKEN_ERR_FATAL;

	if (!p11_token->initialized) {
		DEBUG("Token not initialized, creating new token");
		/**
		 *  The SO PIN is generated randomly, used once to initialize the token
		 *  and then discarded: the token is intentionally locked down so it can
		 *  never again be SO-administered (re-init / SO-PIN change impossible).
		 */
		unsigned char random_mem[32];
		if (1 != RAND_bytes(random_mem, sizeof(random_mem))) {
			ERROR("Failed to generate random SO PIN");
			return TOKEN_ERR_FATAL;
		}
		str_t *so_pin = str_hexdump_new(random_mem, sizeof(random_mem));
		mem_memset0(random_mem, sizeof(random_mem));
		if (!so_pin) {
			ERROR("Failed to hex-encode SO PIN");
			return TOKEN_ERR_FATAL;
		}
		ret = int_init_token(p11_token, str_buffer(so_pin), newpass);
		str_free(so_pin, true);
	} else {
		DEBUG("Token already initialized, changing pin");
		ret = p11token_unlock(p11_token, oldpass, NULL, 0);
		if (TOKEN_ERR_OK != ret) {
			goto out;
		}

		P11_CHECK_RV_GOTO(p11_token->ctx->C_SetPIN(
					  *p11_token->sh, (unsigned char *)oldpass, strlen(oldpass),
					  (unsigned char *)newpass, strlen(newpass)),
				  out);
	}
out:
	/**
	 * Re-lock the token for cleanup, but preserve any earlier error: a wrong
	 * PIN must surface as TOKEN_ERR_PW (mapped to CHANGE_PIN_FAILED), and an
	 * init failure must stay fatal - neither may be masked by a successful
	 * lock of the (already-locked) token.
	 */
	if (TOKEN_ERR_OK == ret)
		ret = p11token_lock(p11_token);
	else
		p11token_lock(p11_token);
	return ret;
}

tokentype_t
p11token_get_type()
{
	return TOKEN_TYPE_PKCS11;
}

/**
 * lock token and cleanup data structure
*/
static void
p11token_free(void *int_token)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);
	ASSERT(p11_token->module_path);

	if (!token_is_locked(p11_token->token)) {
		WARN("token is not locked");
		if (TOKEN_ERR_OK != p11token_lock(int_token)) {
			ERROR("p11token_lock before free failed");
		}
	}

	mem_free(p11_token->module_path);
	mem_free(p11_token);
}

static token_operations_t p11token_ops = {
	.lock = p11token_lock,
	.unlock = p11token_unlock,
	.wrap_key = p11token_wrap_key,
	.unwrap_key = p11token_unwrap_key,
	.change_passphrase = p11token_change_pin,
	.send_apdu = NULL,
	.reset_auth = NULL,
	.get_atr = NULL,
	.get_type = p11token_get_type,
	.token_free = p11token_free,
};

void *
p11token_new(token_t *token, token_operations_t **ops, const char *module_path)
{
	ASSERT(token);
	ASSERT(ops);
	ASSERT(module_path);
	p11token_t *p11_token = int_token_by_label(module_path, uuid_string(token_get_uuid(token)));

	// create new token if not found
	if (p11_token == NULL) {
		DEBUG("Token not found, creating new token");
		unsigned char *token_label =
			int_token_label_new(uuid_string(token_get_uuid(token)));
		p11_token = (p11token_t *)mem_new0(p11token_t, 1);
		p11_token->module_path = mem_strdup(module_path);
		memcpy(p11_token->label, token_label, P11_LABEL_MAX_LEN);
		// free label
		mem_free0(token_label);
		p11_token->ctx = NULL;
		p11_token->sh = NULL;
		p11_token->module = NULL;
		p11_token->wrap_mech =
			0; // Just a placeholder value, will be set during initialization
		p11_token->initialized = false;
	}

	IF_NULL_RETVAL_ERROR(p11_token, NULL);

	p11_token->token = token;
	*ops = &p11token_ops;

	return p11_token;
}