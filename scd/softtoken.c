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
#include "token.h"

#include "common/ssl_util.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/uuid.h"

#include <string.h>

#define SOFTTOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3

struct softtoken {
	char *token_file;		// absolute path to softtoken w. filename
	bool locked;			// whether the token is locked or not
	unsigned wrong_unlock_attempts; // wrong consecutive password attempts
	EVP_PKEY *pkey;			// holds the token public key pair when unlocked
	X509 *cert;			// holds the token's certificate, if available
	STACK_OF(X509) * ca;		// holds the token's certificate chain, if available
	uuid_t *token_uuid;
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
	token->locked = true;
	token->wrong_unlock_attempts = 0;
	token->pkey = NULL;
	token->cert = NULL;
	token->ca = NULL;

	return token;
}

int
softtoken_change_passphrase(softtoken_t *token, const char *oldpass, const char *newpass)
{
	ASSERT(token);
	return ssl_newpass_pkcs12_token(token->token_file, oldpass, newpass);
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
softtoken_free(softtoken_t *token)
{
	ASSERT(token);

	softtoken_free_secrets(token);

	if (token->token_file)
		mem_free0(token->token_file);

	mem_free0(token);
}

int
softtoken_wrap_key(softtoken_t *token, const unsigned char *plain_key, size_t plain_key_len,
		   unsigned char **wrapped_key, int *wrapped_key_len)
{
	ASSERT(token);
	// TODO allow wrapping (encryption with public key) even with locked token?
	if (softtoken_is_locked(token)) {
		WARN("Trying to wrap key with locked token.");
		return -1;
	}
	return ssl_wrap_key(token->pkey, plain_key, plain_key_len, wrapped_key, wrapped_key_len);
}

int
softtoken_unwrap_key(softtoken_t *token, const unsigned char *wrapped_key, size_t wrapped_key_len,
		     unsigned char **plain_key, int *plain_key_len)
{
	ASSERT(token);
	if (softtoken_is_locked(token)) {
		WARN("Trying to unwrap key with locked token.");
		return -1;
	}
	return ssl_unwrap_key(token->pkey, wrapped_key, wrapped_key_len, plain_key, plain_key_len);
}

bool
softtoken_is_locked_till_reboot(softtoken_t *token)
{
	ASSERT(token);
	return token->wrong_unlock_attempts >= SOFTTOKEN_MAX_WRONG_UNLOCK_ATTEMPTS;
}

bool
softtoken_is_locked(softtoken_t *token)
{
	ASSERT(token);
	return token->locked;
}

int
softtoken_unlock(softtoken_t *token, char *passphrase)
{
	ASSERT(token);

	if (!softtoken_is_locked(token)) {
		WARN("Token is alread unlocked, returning");
		return 0;
	}

	if (softtoken_is_locked_till_reboot(token)) {
		WARN("Token is locked till reboot, returning");
		return -1;
	}

	if (!file_exists(token->token_file)) {
		ERROR("No token present");
		return -1;
	}
	int res = ssl_read_pkcs12_token(token->token_file, passphrase, &token->pkey, &token->cert,
					&token->ca);
	if (res == -1) // wrong password
		token->wrong_unlock_attempts++;
	else if (res == 0) {
		token->locked = false;
		token->wrong_unlock_attempts = 0;
	}
	// TODO what to do with wrong_unlock_attempts if unlock failed for some other reason?

	if (res != 0)
		softtoken_free_secrets(token); // just to be sure

	return res;
}

int
softtoken_lock(softtoken_t *token)
{
	ASSERT(token);

	if (softtoken_is_locked(token)) {
		DEBUG("Token is already locked, returning.");
		return 0;
	}

	softtoken_free_secrets(token);
	token->locked = true;
	return 0;
}

/**
 * scd_token interface implementation
 */

static int
int_lock_st(scd_token_t *token)
{
	ASSERT(token);
	ASSERT(token->int_token);
	return softtoken_lock((softtoken_t *)token->int_token);
}

static int
int_unlock_st(scd_token_t *token, char *passwd, UNUSED unsigned char *pairing_secret,
	      UNUSED size_t pairing_sec_len)
{
	ASSERT(token);
	ASSERT(token->int_token);
	return softtoken_unlock((softtoken_t *)token->int_token, passwd);
}

static bool
int_is_locked_st(scd_token_t *token)
{
	return softtoken_is_locked((softtoken_t *)token->int_token);
}

static bool
int_is_locked_till_reboot_st(scd_token_t *token)
{
	return softtoken_is_locked_till_reboot((softtoken_t *)token->int_token);
}

static int
int_wrap_st(scd_token_t *token, UNUSED char *label, unsigned char *plain_key, size_t plain_key_len,
	    unsigned char **wrapped_key, int *wrapped_key_len)
{
	return softtoken_wrap_key((softtoken_t *)token->int_token, plain_key, plain_key_len,
				  wrapped_key, wrapped_key_len);
}

static int
int_unwrap_st(scd_token_t *token, UNUSED char *label, unsigned char *wrapped_key,
	      size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len)
{
	return softtoken_unwrap_key((softtoken_t *)token->int_token, wrapped_key, wrapped_key_len,
				    plain_key, plain_key_len);
}

static int
int_change_pw_st(scd_token_t *token, const char *oldpass, const char *newpass,
		 UNUSED unsigned char *pairing_secret, UNUSED size_t pairing_sec_len,
		 UNUSED bool is_provisioning)
{
	return softtoken_change_passphrase((softtoken_t *)token->int_token, oldpass, newpass);
}

static int
int_send_apdu_st(UNUSED scd_token_t *token, UNUSED unsigned char *apdu, UNUSED size_t apdu_len,
		 UNUSED unsigned char *brsp, UNUSED size_t brsp_len)
{
	ERROR("send_apdu() not meaningful to softtoken. Aborting ...");
	return -1;
}

static int
int_reset_auth_st(UNUSED scd_token_t *token, UNUSED unsigned char *brsp, UNUSED size_t brsp_len)
{
	ERROR("reset_auth() not meaningful to softtoken. Aborting ...");
	return -1;
}

static int
int_get_atr_st(UNUSED scd_token_t *token, UNUSED unsigned char *brsp, UNUSED size_t brsp_len)
{
	ERROR("get_atr() not meaningful to softtoken. Aborting ...");
	return -1;
}

static scd_tokentype_t
int_get_tokentype(UNUSED scd_token_t *token)
{
	return SOFT;
}

static uuid_t *
int_get_uuid(scd_token_t *token)
{
	ASSERT(token);
	softtoken_t *stoken = (softtoken_t *)token->int_token;
	return stoken->token_uuid;
}

static bool
int_has_internal_token(scd_token_t *token, const void *int_token)
{
	ASSERT(token);

	if (token->int_token == int_token)
		return true;

	return false;
}

static void
int_free(scd_token_t *token)
{
	TRACE("Removing softtoken %s", uuid_string(token->get_uuid(token)));
	softtoken_remove_p12((softtoken_t *)token->int_token);
	softtoken_free((softtoken_t *)token->int_token);
}

scd_token_t *
softtoken_token_new(const char *softtoken_dir, const char *uuid)
{
	ASSERT(softtoken_dir);
	ASSERT(uuid);
	scd_token_t *new_token;
	char *token_file = NULL;

	new_token = mem_new0(scd_token_t, 1);
	if (!new_token) {
		ERROR("Could not allocate new scd_token_t");
		return NULL;
	}

	new_token->int_token = softtoken_new_from_p12(token_file);
	if (!new_token->int_token) {
		ERROR("Creation of softtoken failed");
		mem_free0(token_file);
		goto err;
	}

	((softtoken_t *)(new_token->int_token))->token_uuid = uuid_new(uuid);
	if (!((softtoken_t *)(new_token->int_token))->token_uuid) {
		ERROR("Could not allocate memory for token_uuid");
		goto err;
	}

	token_file = mem_printf("%s/%s%s", softtoken_dir, uuid, STOKEN_DEFAULT_EXT);
	if (!file_exists(token_file)) {
		if (softtoken_create_p12(token_file, STOKEN_DEFAULT_PASS, uuid) != 0) {
			ERROR("Could not create new softtoken file");
			mem_free0(token_file);
			goto err;
		}
	}

	mem_free0(token_file);

	new_token->lock = int_lock_st;
	new_token->unlock = int_unlock_st;
	new_token->is_locked = int_is_locked_st;
	new_token->is_locked_till_reboot = int_is_locked_till_reboot_st;
	new_token->wrap_key = int_wrap_st;
	new_token->unwrap_key = int_unwrap_st;
	new_token->change_passphrase = int_change_pw_st;
	new_token->reset_auth = int_reset_auth_st;
	new_token->get_atr = int_get_atr_st;
	new_token->send_apdu = int_send_apdu_st;
	new_token->get_type = int_get_tokentype;
	new_token->get_uuid = int_get_uuid;
	new_token->has_internal_token = int_has_internal_token;
	new_token->free = int_free;

	return new_token;

err:
	if (new_token->get_uuid(new_token))
		uuid_free(new_token->get_uuid(new_token));
	if (new_token->int_token)
		mem_free0(new_token->int_token);
	if (new_token)
		mem_free0(new_token);

	return NULL;
}
