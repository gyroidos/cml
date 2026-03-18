/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#include "softtoken.h"

#include "common/ssl_util.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/uuid.h"

#include <string.h>

#define SOFTTOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3

struct softtoken {
	const token_t *token; // token to which holds this internal softtoken (1:1 reference)
	char *token_file;     // absolute path to softtoken w. filename
	EVP_PKEY *pkey;	      // holds the token public key pair when unlocked
	X509 *cert;	      // holds the token's certificate, if available
	STACK_OF(X509) * ca;  // holds the token's certificate chain, if available
};

/**
 * creates a new pkcs12 softtoken.
 */
int
softtoken_create_p12(const char *filename, const char *passwd, const char *name)
{
	ASSERT(filename);
	ASSERT(passwd);
	ASSERT(name);

	// instruct openssl to initialize a context without using the tpm as an engine
	if (ssl_init(false, NULL) == -1) {
		ERROR("Failed to initialize OpenSSL stack for softtoken");
		return -1;
	}

	if (ssl_create_pkcs12_token(filename, NULL, passwd, name, RSA_SSA_PADDING) != 0) {
		ERROR("Unable to create pkcs12 token");
		return -1;
	}

	ssl_free();
	return 0;
}

/**
 * removes a pkcs12 token file.
 */
void
softtoken_remove_p12(softtoken_t *token)
{
	ASSERT(token);

	int rc = remove(token->token_file);
	if (rc != 0)
		ERROR("Failed to remove %s. Return code: %d", token->token_file, rc);
}

softtoken_t *
softtoken_new_from_p12(const char *filename)
{
	ASSERT(filename);

	softtoken_t *token = mem_new0(softtoken_t, 1);
	token->token_file = mem_strdup(filename);
	token->pkey = NULL;
	token->cert = NULL;
	token->ca = NULL;

	return token;
}

token_err_t
softtoken_change_passphrase(void *int_token, const char *oldpass, const char *newpass,
			    UNUSED const unsigned char *pairing_secret,
			    UNUSED size_t pairing_sec_len, UNUSED bool is_provisioning)
{
	softtoken_t *st_token = int_token;
	ASSERT(st_token);
	if (ssl_newpass_pkcs12_token(st_token->token_file, oldpass, newpass) == 0) {
		return TOKEN_ERR_OK;
	}
	return TOKEN_ERR_FATAL;
}

/**
 * Free key and certificate data.
 * TODO distinguish private/secret data (which must be removed when locking)
 *      and public data (which can be left available)
 */
static void
softtoken_free_secrets(softtoken_t *token)
{
	ASSERT(token);
	if (token->pkey) {
		// TODO check if we need to erase (overwrite) private key data from memory
		EVP_PKEY_free(token->pkey);
		token->pkey = NULL;
	}
	if (token->cert) {
		X509_free(token->cert);
		token->cert = NULL;
	}
	if (token->ca) {
		sk_X509_pop_free(token->ca, X509_free);
		token->ca = NULL;
	}
}

void
softtoken_free(void *int_token)
{
	softtoken_t *st_token = int_token;
	IF_NULL_RETURN(st_token);
	softtoken_remove_p12(st_token);
	softtoken_free_secrets(st_token);

	if (st_token->token_file)
		mem_free0(st_token->token_file);

	mem_free0(st_token);
}

token_err_t
softtoken_wrap_key(void *int_token, UNUSED const char *label, unsigned char *plain_key,
		   size_t plain_key_len, unsigned char **wrapped_key, int *wrapped_key_len)
{
	softtoken_t *st_token = int_token;
	ASSERT(st_token);
	// TODO allow wrapping (encryption with public key) even with locked token?
	if (token_is_locked(st_token->token)) {
		WARN("Trying to wrap key with locked token.");
		return TOKEN_ERR_LOCKED;
	}

	if (ssl_wrap_key(st_token->pkey, plain_key, plain_key_len, wrapped_key, wrapped_key_len) ==
	    0) {
		return TOKEN_ERR_OK;
	}
	return TOKEN_ERR_FATAL;
}

token_err_t
softtoken_unwrap_key(void *int_token, UNUSED const char *label, unsigned char *wrapped_key,
		     size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len)
{
	softtoken_t *st_token = int_token;
	ASSERT(st_token);

	if (token_is_locked(st_token->token)) {
		WARN("Trying to unwrap key with locked token.");
		return TOKEN_ERR_LOCKED;
	}

	if (ssl_unwrap_key(st_token->pkey, wrapped_key, wrapped_key_len, plain_key,
			   plain_key_len) == 0) {
		return TOKEN_ERR_OK;
	}
	return TOKEN_ERR_FATAL;
}

token_err_t
softtoken_unlock(void *int_token, const char *passphrase,
		 UNUSED const unsigned char *pairing_secret, UNUSED size_t pairing_sec_len)
{
	softtoken_t *st_token = int_token;
	ASSERT(st_token);

	if (!token_is_locked(st_token->token)) {
		WARN("Token is alread unlocked, returning");
		return TOKEN_ERR_OK;
	} else if (token_is_locked_till_reboot(st_token->token)) {
		WARN("Token is locked till reboot, returning");
		return TOKEN_ERR_LOCKED_TILL_REBOOT;
	}

	if (!file_exists(st_token->token_file)) {
		ERROR("No token present");
		return TOKEN_ERR_FATAL;
	}
	int res = ssl_read_pkcs12_token(st_token->token_file, passphrase, &st_token->pkey,
					&st_token->cert, &st_token->ca);
	if (res == -1) {
		// wrong password
		softtoken_free_secrets(st_token); // just to be sure
		return TOKEN_ERR_PW;
	} else if (res == 0) {
		return TOKEN_ERR_OK;
	}

	// should not be reached
	return TOKEN_ERR_FATAL;
}

token_err_t
softtoken_lock(void *int_token)
{
	softtoken_t *st_token = int_token;
	ASSERT(st_token);
	if (token_is_locked(st_token->token)) {
		DEBUG("Token is already locked, returning.");
		return TOKEN_ERR_OK;
	}

	softtoken_free_secrets(st_token);

	return TOKEN_ERR_OK;
}

tokentype_t
softtoken_get_type()
{
	return TOKEN_TYPE_SOFT;
}

static token_operations_t softtoken_ops = {
	.lock = softtoken_lock,
	.unlock = softtoken_unlock,
	.wrap_key = softtoken_wrap_key,
	.unwrap_key = softtoken_unwrap_key,
	.change_passphrase = softtoken_change_passphrase,
	.send_apdu = NULL,
	.reset_auth = NULL,
	.get_atr = NULL,
	.get_type = softtoken_get_type,
	.token_free = softtoken_free,
};

void *
softtoken_new(token_t *token, token_operations_t **ops, const char *softtoken_dir)
{
	ASSERT(token);
	ASSERT(softtoken_dir);
	char *token_file = NULL;

	token_file = mem_printf("%s/%s%s", softtoken_dir, uuid_string(token_get_uuid(token)),
				STOKEN_DEFAULT_EXT);
	if (!file_exists(token_file)) {
		if (softtoken_create_p12(token_file, TOKEN_DEFAULT_PASS,
					 uuid_string(token_get_uuid(token))) != 0) {
			ERROR("Could not create new softtoken file");
			mem_free0(token_file);
			goto err;
		}
	}
	softtoken_t *st_token = softtoken_new_from_p12(token_file);
	if (!st_token) {
		ERROR("Creation of softtoken failed");
		mem_free0(token_file);
		goto err;
	}
	st_token->token = token;
	*ops = &softtoken_ops;
	mem_free0(token_file);
	return st_token;
err:
	return NULL;
}
