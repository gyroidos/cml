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
#include "pkcs11-lib/libpkcs11.h"
#include <string.h>
#include <stdbool.h>

#define P11TOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3
#define P11_LABEL_MAX_LEN 32

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
			fprintf(stderr, "Pkcs11 operation '%s' returned Errorcode %lu\n", #expr,   \
				rv);                                                               \
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
};

// Helper Functions
/**
 * get next free slot id
*/
static ck_slot_id_t *
int_get_free_slot_id_new(struct ck_function_list *ctx)
{
	ASSERT(ctx);

	unsigned long slot_count = 0;
	ck_slot_id_t *p_slots = NULL;

	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(false, NULL, &slot_count), error);
	p_slots = (ck_slot_id_t *)mem_alloc(slot_count * sizeof(ck_slot_id_t));
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(false, p_slots, &slot_count), error);

	for (unsigned long i = 0; i < slot_count; i++) {
		ck_rv_t rv = CKR_OK;
		struct ck_slot_info slot_info;
		if ((rv = ctx->C_GetSlotInfo(p_slots[i], &slot_info)) == CKR_OK) {
			if ((i == p_slots[i])) {
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
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(true, NULL, &slot_count), error);
	p_slots = (ck_slot_id_t *)mem_alloc(slot_count * sizeof(ck_slot_id_t));
	P11_CHECK_RV_GOTO(ctx->C_GetSlotList(false, p_slots, &slot_count), error);

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
int_p11_token_label_new(const char *label)
{
	ASSERT(label);

	size_t len_label = strlen(label);
	unsigned char *token_label = mem_alloc0(P11_LABEL_MAX_LEN);
	if (len_label <= P11_LABEL_MAX_LEN) {
		memcpy(token_label, label, len_label);

		// pad remaining space
		for (size_t i = len_label + 1; i < P11_LABEL_MAX_LEN; i++) {
			token_label[i] = ' ';
		}
	} else {
		// label is too long: truncate
		memcpy(token_label, label, P11_LABEL_MAX_LEN);
	}

	return token_label;
}

/**
 * Create new PKCS#11 token.
 * @param module_path path to PKCS1#11 module library (e.g. libsofthsm2)
 * @param so_pin pin which should be used by the SO (only required for initialisation)
 * @param user_pin pin which should be used for day to day usage
 * @param label name of the new PKCS#11 token
 * @return Success: pointer to the newly created token, Error: NULL
*/
static p11token_t *
p11token_create_p11(const char *module_path, const char *so_pin, const char *user_pin,
		    const char *label)
{
	ASSERT(module_path);
	ASSERT(so_pin);
	ASSERT(user_pin);
	ASSERT(label);

	struct ck_function_list *ctx = NULL;
	ck_slot_id_t *slot = NULL;
	unsigned char *token_label = NULL;
	// load pkcs11-module (load dll at runtime)
	void *module = C_LoadModule(module_path, &ctx);
	if (module == NULL) {
		ERROR("Could not load pkcs11 module");
	}

	// init library
	P11_CHECK_RV_GOTO(ctx->C_Initialize(NULL), error_init);

	// get free slot
	slot = int_get_free_slot_id_new(ctx);
	IF_TRUE_GOTO_ERROR(slot == NULL, error);

	// sanitize label
	token_label = int_p11_token_label_new(label);

	// initialize token on free slot
	P11_CHECK_RV_GOTO(ctx->C_InitToken(*slot, (unsigned char *)so_pin, strlen(so_pin),
					   (unsigned char *)token_label),
			  error);

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
	unsigned long length = 32; // size in bytes -> 256bit key
	bool y = true;
	bool n = false;
	struct ck_attribute aes_key_template[] = {
		{ CKA_KEY_TYPE, &aes_type, sizeof(aes_type) },
		{ CKA_TOKEN, &y, sizeof(y) },	    // persistently store key on token
		{ CKA_EXTRACTABLE, &n, sizeof(n) }, // key should not be extractable
		{ CKA_LABEL, &label, strlen(label) },
		{ CKA_VALUE_LEN, &length, sizeof(length) },
	};
	P11_CHECK_RV_GOTO(ctx->C_GenerateKey(sh, &mechanism, aes_key_template,
					     ELEMENTSOF(aes_key_template), &h_key),
			  error_session);

	// logout user
	P11_CHECK_RV_GOTO(ctx->C_Logout(sh), error_session);

	// terminate token-session
	P11_CHECK_RV_GOTO(ctx->C_CloseSession(sh), error);

	// free slot id ptr
	mem_free(slot);

	// Unload Module
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
	C_UnloadModule(module);

	// return new token data
	p11token_t *token = (p11token_t *)mem_new0(p11token_t, 1);
	token->module_path = mem_strdup(module_path);
	memcpy(token->label, token_label, P11_LABEL_MAX_LEN);
	// free label
	mem_free0(token_label);
	token->ctx = NULL;
	token->sh = NULL;
	token->module = NULL;
	return token;
error_session:
	P11_CHECK_RV_GOTO(ctx->C_CloseSession(sh), error);
error:
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
error_init:
	if (slot) {
		mem_free(slot);
	}
	if (token_label) {
		mem_free(token_label);
	}
	C_UnloadModule(module);
	return NULL;
}

/**
 * Get token by label.
 * @param module_path path to PKCS#11 module library (e.g. libsofthsm2)
 * @param label label of the desired token
 * @return Success: pointer to token; Error: NULL
*/
static p11token_t *
p11token_token_by_label(const char *module_path, const char *label)
{
	ASSERT(module_path);
	ASSERT(label);

	struct ck_function_list *ctx = NULL;
	unsigned char *token_label = NULL;
	ck_slot_id_t *slot = NULL;
	// load module
	void *module = C_LoadModule(module_path, &ctx);
	if (module == NULL) {
		ERROR("Could not load pkcs11 module");
	}

	// init library
	P11_CHECK_RV_GOTO(ctx->C_Initialize(NULL), error_init);

	// check if token exists
	token_label = int_p11_token_label_new(label);
	slot = int_get_token_slot_id_new(ctx, token_label);
	if (slot == NULL) {
		INFO("token for %s not found", label);
		goto error; // cleanup and return null
	}

	// cleanup
	P11_CHECK_RV_GOTO(ctx->C_Finalize(NULL), error_init);
	C_UnloadModule(module);

	// if token exists create new token-object
	p11token_t *token = (p11token_t *)mem_new0(p11token_t, 1);
	token->module_path = mem_strdup(module_path);
	memcpy(token->label, token_label, P11_LABEL_MAX_LEN);
	// free label
	mem_free0(token_label);
	token->ctx = NULL;
	token->sh = NULL;
	token->module = NULL;
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
	C_UnloadModule(module);
	return NULL;
}

// TODO: use pairing secret?
token_err_t
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

	if (!token_is_locked(p11_token->token)) {
		WARN("Pkcs11 token is already unlocked");
		return TOKEN_ERR_OK;
	}
	// load library and connect to token
	p11_token->module = C_LoadModule(p11_token->module_path, &p11_token->ctx);
	if (p11_token->module == NULL) {
		ERROR("Could not load pkcs11 module");
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

	C_UnloadModule(p11_token->module);
	return ret;
}

token_err_t
p11token_lock(void *int_token)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);

	P11_CHECK_RV_RETURN(p11_token->ctx->C_Logout(*p11_token->sh));

	P11_CHECK_RV_RETURN(p11_token->ctx->C_CloseSession(*p11_token->sh));
	free(p11_token->sh);
	p11_token->sh = NULL;

	P11_CHECK_RV_RETURN(p11_token->ctx->C_Finalize(NULL));
	p11_token->ctx = NULL;

	C_UnloadModule(p11_token->module);

	return TOKEN_ERR_OK;
}

token_err_t
p11token_wrap_key(void *int_token, UNUSED const char *label, unsigned char *plain_key,
		  size_t plain_key_len, unsigned char **wrapped_key, int *wrapped_key_len)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);
	ASSERT(plain_key);
	ASSERT(wrapped_key);
	ASSERT(wrapped_key_len);

	token_err_t ret = TOKEN_ERR_FATAL;

	unsigned char *ptr = NULL;

	if (token_is_locked(p11_token->token)) {
		ERROR("p11token_wrap_key: token is locked");
		ret = TOKEN_ERR_LOCKED;
		goto error;
	}

	// get wrapping key handle
	// currently there is only one, therefore we can keep the search template simple
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

	// wrap key
	/**
	 * static default IV as defined in RFC 3394
	 * TODO: investigate whether a random IV which is passed along with the
	 * 			wrapped key is possible and desirable
	 */
	unsigned char iv[] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
			       0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
	struct ck_mechanism wrap_mechanism = {
		CKM_AES_CBC_PAD,
		iv,
		ELEMENTSOF(iv),
	};
	P11_CHECK_RV_GOTO(p11_token->ctx->C_EncryptInit(*p11_token->sh, &wrap_mechanism, h_key),
			  error);
	// retrieve buffer size
	P11_CHECK_RV_GOTO(p11_token->ctx->C_Encrypt(*p11_token->sh, plain_key, plain_key_len, NULL,
						    (long unsigned int *)wrapped_key_len),
			  error);
	ptr = (unsigned char *)mem_alloc0(*wrapped_key_len);
	IF_TRUE_GOTO_DEBUG(NULL == ptr, error);
	P11_CHECK_RV_GOTO(p11_token->ctx->C_Encrypt(*p11_token->sh, plain_key, plain_key_len, ptr,
						    (long unsigned int *)wrapped_key_len),
			  error);
	*wrapped_key = ptr;
	return TOKEN_ERR_OK;
error:
	if (ptr) {
		mem_free0(ptr);
	}
	return ret;
}

token_err_t
p11token_unwrap_key(void *int_token, UNUSED const char *label, unsigned char *wrapped_key,
		    size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);
	ASSERT(wrapped_key);
	ASSERT(plain_key);
	ASSERT(plain_key_len);

	token_err_t ret = TOKEN_ERR_FATAL;

	unsigned char *ptr = NULL;

	if (token_is_locked(p11_token->token)) {
		ERROR("p11token_wrap_key: token is locked");
		ret = TOKEN_ERR_LOCKED;
		goto error;
	}

	// get wrapping key handle
	// currently there is only one, therefore we can keep the template simple
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
	// unwrap key
	/**
	 * static default IV as defined in RFC 3394
	 * TODO: investigate whether a random IV which is passed along with the
	 * 			wrapped key is possible and desirable
	 */
	unsigned char iv[] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6,
			       0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
	struct ck_mechanism wrap_mechanism = {
		CKM_AES_CBC_PAD,
		iv,
		ELEMENTSOF(iv),
	};
	P11_CHECK_RV_GOTO(p11_token->ctx->C_DecryptInit(*p11_token->sh, &wrap_mechanism, h_key),
			  error);
	P11_CHECK_RV_GOTO(p11_token->ctx->C_Decrypt(*p11_token->sh, wrapped_key, wrapped_key_len,
						    NULL, (long unsigned int *)plain_key_len),
			  error);
	ptr = (unsigned char *)mem_alloc0(*plain_key_len);
	IF_TRUE_GOTO_DEBUG(NULL == ptr, error);
	P11_CHECK_RV_GOTO(p11_token->ctx->C_Decrypt(*p11_token->sh, wrapped_key, wrapped_key_len,
						    ptr, (long unsigned int *)plain_key_len),
			  error);
	*plain_key = ptr;

	return TOKEN_ERR_OK;
error:
	if (ptr) {
		mem_free0(ptr);
	}
	return ret;
}

token_err_t
p11token_change_pin(void *int_token, const char *oldpass, const char *newpass,
		    UNUSED const unsigned char *pairing_secret, UNUSED size_t pairing_sec_len,
		    UNUSED bool is_provisioning)
{
	p11token_t *p11_token = int_token;
	ASSERT(p11_token);
	ASSERT(oldpass);
	ASSERT(newpass);

	token_err_t ret = p11token_unlock(p11_token, oldpass, NULL, 0);
	if (TOKEN_ERR_OK != ret) {
		goto error;
	}

	P11_CHECK_RV_GOTO(p11_token->ctx->C_SetPIN(*p11_token->sh, (unsigned char *)oldpass,
						   strlen(oldpass), (unsigned char *)newpass,
						   strlen(newpass)),
			  error);

	return p11token_lock(p11_token);
error:
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
void
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

	p11token_t *p11_token =
		p11token_token_by_label(module_path, uuid_string(token_get_uuid(token)));

	// create new token if not found
	if (p11_token == NULL) {
		// create random so_pin
		unsigned char *random_mem = (unsigned char *)file_read_new("/dev/urandom", 32);
		ASSERT(random_mem);
		str_t *so_pin = str_hexdump_new(random_mem, 32);
		ASSERT(so_pin);
		free(random_mem);
		p11_token = p11token_create_p11(module_path, str_buffer(so_pin), TOKEN_DEFAULT_PASS,
						uuid_string(token_get_uuid(token)));
		str_free(so_pin, true);
	}

	IF_NULL_RETVAL_ERROR(p11_token, NULL);

	p11_token->token = token;
	*ops = &p11token_ops;

	return p11_token;
}