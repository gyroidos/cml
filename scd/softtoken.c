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

#include "softtoken.h"
#include "ssl_util.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"

#include <string.h>

#define SOFTTOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3

struct softtoken {
	char *token_file; // absolute path to softtoken w. filename
	bool locked;	    // whether the token is locked or not
	unsigned wrong_unlock_attempts; // wrong consecutive password attempts
	EVP_PKEY *pkey; // holds the token public key pair when unlocked
	X509 *cert; // holds the token's certificate, if available
	STACK_OF(X509) *ca; // holds the token's certificate chain, if available
};

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
softtoken_change_passphrase(softtoken_t *token, const char *oldpass,
					const char *newpass)
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
		mem_free(token->token_file);

	mem_free(token);
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
softtoken_unlock(softtoken_t *token, char *passphrase) {

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
	int res = ssl_read_pkcs12_token(token->token_file, passphrase,
			&token->pkey, &token->cert, &token->ca);
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
softtoken_lock(softtoken_t *token) {

	ASSERT(token);

	if (softtoken_is_locked(token)) {
		DEBUG("Token is already locked, returning.");
		return 0;
	}

	softtoken_free_secrets(token);
	token->locked = true;
	return 0;
}
