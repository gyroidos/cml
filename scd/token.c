/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
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

#include "token.h"
#include "softtoken.h"
#include "usbtoken.h"
#include "p11token.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/event.h"
#include "common/uuid.h"
#include "common/protobuf.h"
#include "common/list.h"
#include "common/str.h"
#include "common/fd.h"
#include "common/file.h"
#include "unistd.h"

/**
 *  generic token.
 */
struct token {
	void *int_token; // internal token implementation

	uuid_t *uuid;			// token uuid
	bool locked;			// whether the token is locked or not
	unsigned wrong_unlock_attempts; // wrong consecutive password attempts

	token_operations_t *ops; // token type specific operations
};

token_err_t
token_lock(token_t *token)
{
	ASSERT(token);
	ASSERT(token->ops->lock);
	int res = token->ops->lock(token->int_token);
	if (res == TOKEN_ERR_OK) {
		token->locked = true;
	}
	return res;
}

token_err_t
token_unlock(token_t *token, const char *passwd, const unsigned char *pairing_secret,
	     size_t pairing_sec_len)
{
	ASSERT(token);
	ASSERT(token->ops->unlock);
	int res = token->ops->unlock(token->int_token, passwd, pairing_secret, pairing_sec_len);
	if (res == 0) {
		token->locked = false;
	} else if (res == TOKEN_ERR_PW) {
		token->wrong_unlock_attempts++;
	}
	// TODO: also increase in case of other errors?
	return res;
}

bool
token_is_locked(const token_t *token)
{
	ASSERT(token);
	return token->locked;
}

bool
token_is_locked_till_reboot(const token_t *token)
{
	ASSERT(token);
	return token->wrong_unlock_attempts >= TOKEN_MAX_WRONG_UNLOCK_ATTEMPTS;
}

token_err_t
token_wrap_key(token_t *token, const char *label, unsigned char *plain_key, size_t plain_key_len,
	       unsigned char **wrapped_key, int *wrapped_key_len)
{
	ASSERT(token);
	ASSERT(token->ops->wrap_key);
	return token->ops->wrap_key(token->int_token, label, plain_key, plain_key_len, wrapped_key,
				    wrapped_key_len);
}

token_err_t
token_unwrap_key(token_t *token, const char *label, unsigned char *wrapped_key,
		 size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len)
{
	ASSERT(token);
	ASSERT(token->ops->unwrap_key);
	return token->ops->unwrap_key(token->int_token, label, wrapped_key, wrapped_key_len,
				      plain_key, plain_key_len);
}

token_err_t
token_change_passphrase(token_t *token, const char *oldpass, const char *newpass,
			const unsigned char *pairing_secret, size_t pairing_sec_len,
			bool is_provisioning)
{
	ASSERT(token);
	ASSERT(token->ops->change_passphrase);
	return token->ops->change_passphrase(token->int_token, oldpass, newpass, pairing_secret,
					     pairing_sec_len, is_provisioning);
}

token_err_t
token_send_apdu(token_t *token, unsigned char *apdu, size_t apdu_len, unsigned char *brsp,
		size_t brsp_len)
{
	ASSERT(token);
	if (token->ops->send_apdu == NULL) {
		TRACE("token_send_apdu not implemented for this tokentype");
		return TOKEN_ERR_OK;
	}
	return token->ops->send_apdu(token->int_token, apdu, apdu_len, brsp, brsp_len);
}

token_err_t
token_reset_auth(token_t *token, unsigned char *brsp, size_t brsp_len)
{
	ASSERT(token);
	if (token->ops->reset_auth == NULL) {
		TRACE("token_reset_auth not implemented for this tokentype");
		return TOKEN_ERR_OK;
	}
	return token->ops->reset_auth(token->int_token, brsp, brsp_len);
}

token_err_t
token_get_atr(token_t *token, unsigned char *brsp, size_t brsp_len)
{
	ASSERT(token);
	if (token->ops->get_atr == NULL) {
		TRACE("token_get_atr not implementend for this tokentype");
		return TOKEN_ERR_OK;
	}
	return token->ops->get_atr(token->int_token, brsp, brsp_len);
}

token_t *
token_new(tokentype_t type, const char *token_info, const char *uuid)
{
	ASSERT(token_info);
	ASSERT(uuid);

	token_t *new_token;
	new_token = mem_new0(token_t, 1);
	if (!new_token) {
		ERROR("Could not allocate new token_t");
		return NULL;
	}

	// init common fields
	new_token->uuid = uuid_new(uuid);
	ASSERT(new_token->uuid);
	new_token->locked = true;

	switch (type) {
	case (TOKEN_TYPE_NONE): {
		WARN("Create token with internal type 'NONE' selected. No token will be created.");
		goto err;
	}
	case (TOKEN_TYPE_SOFT): {
		DEBUG("Create token with internal type 'SOFT'");
		new_token->int_token = softtoken_new(new_token, &new_token->ops, token_info);
		if (!new_token->int_token) {
			ERROR("Creation of softtoken failed");
			goto err;
		}
		break;
	}
#ifdef SC_CARDSERVICE
	case (TOKEN_TYPE_USB): {
		DEBUG("Create token with internal type 'USB'");
		new_token->int_token = usbtoken_new(new_token, &new_token->ops, token_info);
		if (!new_token->int_token) {
			ERROR("Creation of usbtoken failed");
			goto err;
		}
		break;
	}
#endif // SC_CARDSERVICE
#ifdef ENABLEPKCS11
	case (TOKEN_TYPE_PKCS11): {
		DEBUG("Create token with internal type 'PKCS11'");
		new_token->int_token = p11token_new(new_token, &new_token->ops, token_info);
		if (!new_token->int_token) {
			ERROR("Creation of p11token failed");
			goto err;
		}
		break;
	}
#endif // ENABLEPKCS11
	default:
		ERROR("Unrecognized token type");
		goto err;
	}

	return new_token;

err:
	mem_free0(new_token);
	return NULL;
}

tokentype_t
token_get_type(token_t *token)
{
	ASSERT(token);
	ASSERT(token->ops->get_type);
	return token->ops->get_type();
}

uuid_t *
token_get_uuid(const token_t *token)
{
	ASSERT(token);
	return token->uuid;
}

void
token_free(token_t *token)
{
	IF_NULL_RETURN(token);

	if (token->int_token) {
		ASSERT(token->ops->token_free);
		token->ops->token_free(token->int_token);
		token->int_token = NULL;
	}
	if (token->uuid) {
		uuid_free(token->uuid);
	}
	mem_free0(token);
}
