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

#ifndef TOKEN_H
#define TOKEN_H

#include "common/uuid.h"

#include <stdbool.h>
#include <stddef.h>

#define TOKEN_DEFAULT_PASS "trustme"
#define TOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3

#define MAX_APDU_BUF_LEN 4096

//has to be kept in sync with smartcard.h
// clang-format off
#define SCD_TOKENCONTROL_SOCKET SOCK_PATH(tokencontrol)
// clang-format on

/**
 * Token Error
 */
typedef enum token_err {
	TOKEN_ERR_OK = 0,
	TOKEN_ERR_FATAL = -1,
	TOKEN_ERR_PW = -2,
	TOKEN_ERR_LOCKED = -3,
	TOKEN_ERR_LOCKED_TILL_REBOOT = -4,
} token_err_t;

/**
 *  Generic token type
 */
typedef struct token token_t;

/**
 * Choice of supported token types.
 * Must be kept in sync with scd.proto
 */
typedef enum tokentype { TOKEN_TYPE_NONE, TOKEN_TYPE_SOFT, TOKEN_TYPE_USB } tokentype_t;

typedef struct token_operations {
	token_err_t (*lock)(void *int_token);
	token_err_t (*unlock)(void *int_token, char *passwd, unsigned char *pairing_secret,
			      size_t pairing_sec_len);

	token_err_t (*wrap_key)(void *int_token, char *label, unsigned char *plain_key,
				size_t plain_key_len, unsigned char **wrapped_key,
				int *wrapped_key_len);

	token_err_t (*unwrap_key)(void *int_token, char *label, unsigned char *wrapped_key,
				  size_t wrapped_key_len, unsigned char **plain_key,
				  int *plain_key_len);

	token_err_t (*change_passphrase)(void *int_token, const char *oldpass, const char *newpass,
					 unsigned char *pairing_secret, size_t pairing_sec_len,
					 bool is_provisioning);
	token_err_t (*send_apdu)(void *int_token, unsigned char *apdu, size_t apdu_len,
				 unsigned char *brsp, size_t brsp_len);
	token_err_t (*reset_auth)(void *int_token, unsigned char *brsp, size_t brsp_len);
	token_err_t (*get_atr)(void *int_token, unsigned char *brsp, size_t brsp_len);
	tokentype_t (*get_type)();
	void (*token_free)(void *int_token);
} token_operations_t;

// SCD TOKEN API

/**
 * locks a token
 * @param token the token to lock
 * @return 0 on success or < 0 on error
 */
token_err_t
token_lock(token_t *token);

/**
 * unlocks a token with a password.
 * @param token the token to unlock
 * @param passwd the user pin/passwd for the token
 * @param pairing_sec the platform-bound pairing secret
 * @param pairing_sec_len the length of the pairing secret
 * @return 0 on success or < 0 on error
 */
token_err_t
token_unlock(token_t *token, char *passwd, unsigned char *pairing_secret, size_t pairing_sec_len);

/**
 * checks whether the token is locked or not
 * @param token the token to check
 * @return false if token is unlocked or true if it is locked
 */
bool
token_is_locked(const token_t *token);

/**
 * checks whether the token is locked or not till next reboot
 * @param token the token to check
 * @return false if token is not or true if it is locked until next reboot
 */
bool
token_is_locked_till_reboot(const token_t *token);

/**
 * wraps a symmetric container key plain_key of length plain_key_len with a
 * symmetric key provided by the token into a wrapped key wrapped_key of
 * length wrapped_key_len
 * @param token the token to wrap the key with
 * @param label key derivation parameter to be used to derive the wrapping key
 * @param label_len the length of @param label
 * @param plain_key the key to be wrapped
 * @param plain_key_len the length of @param plain_key
 * @param wrapped_key the resulting wrapped key
 * @param wrapped_key_len the length of @param wrapped_key
 * @return 0 on success or < 0 on error
 */
token_err_t
token_wrap_key(token_t *token, char *label, unsigned char *plain_key, size_t plain_key_len,
	       unsigned char **wrapped_key, int *wrapped_key_len);

/**
 * unwraps a symmetric container key wrapped_key of length wrapped_key_len with a
 * symmetric key provided key into the plain key plain_key of length plain_key_len
 * @param token the token to unwrap the key with
 * @param label key derivation parameter to be used to derive the wrapping key
 * @param label_len the length of @param label
 * @param wrapped_key the wrapped key that should be unwrapped
 * @param wrapped_key_len the length of @param wrapped_key
 * @param plain_key the resulting plain key
 * @param plain_key_len the length of @param plain_key
 * @return 0 on success or < 0 on error
 */
token_err_t
token_unwrap_key(token_t *token, char *label, unsigned char *wrapped_key, size_t wrapped_key_len,
		 unsigned char **plain_key, int *plain_key_len);

/**
 * Changes the pasphrase/pin of the underlying low level structure
 * of the token
 * @param token the token whose pin/passwd should be changed
 * @param oldpass the currently valid pin/passwd
 * @param newpass the new user pin/passwd
 * @param pairing_sec the platform-bound pairing secret
 * @param pairing_sec_len the length of the pairing secret
 * @param is_provisioning if true the function interprets @param oldpass as
 * 		previously set transport pin and tries to unlock the token directly with it to provision
 * 		it with a new authentication code derived from both the new user pin @param newpass
 * 		and the pairing secret @param pairing_sec.
 * 		If false, the function derives authentication codes both for the old and new user pin.
 * @return  0 on success or < 0 on error
 */
token_err_t
token_change_passphrase(token_t *token, const char *oldpass, const char *newpass,
			unsigned char *pairing_secret, size_t pairing_sec_len,
			bool is_provisioning);

/**
 * Sends an APDU to the token and receive the response.
 * @param token the token to communicate with
 * @param apdu the apdu byte arry to send to the token
 * @param apdu_len legnth of @param apdu
 * @param brsp the buffer for the response
 * @param brsp_len the size of @param Brsp
 * @return  0 on success or < 0 on error
 */
token_err_t
token_send_apdu(token_t *token, unsigned char *apdu, size_t apdu_len, unsigned char *brsp,
		size_t brsp_len);

/**
 * Resets the authentication status of the token using the cached authentication code.
 * @param brsp the buffer for the response
 * @param brsp_len the size of @param Brsp
 * @return  0 on success or < 0 on error

 */
token_err_t
token_reset_auth(token_t *token, unsigned char *brsp, size_t brsp_len);

/**
 * Gets the ATR from the token.
 * @param brsp the buffer for the response
 * @param brsp_len the size of @param Brsp
 * @return  0 on success or < 0 on error
 */
token_err_t
token_get_atr(token_t *token, unsigned char *brsp, size_t brsp_len);

/**
 * returns the token's type.
 * @param token the token to operate on
 *
 * @return the type of the scd token
 */
tokentype_t
token_get_type(token_t *token);

/**
 * returns the token's uuid.
 * @param token the token to operate on
 *
 * @return pointer to the uuid of the token on success or else NULL
 */
uuid_t *
token_get_uuid(const token_t *token);

/**
 * creates a new generic token
 * calls the respective create function for the selected type of token and
 * sets the function pointer appropriately
 * @param type the type of token to create
 * @param token_info information about the token used by the constructor
 * @param uuid the uuid to assign to the token
 *
 * @return pointer to the newly created generic token on success or else NULL
 */
token_t *
token_new(tokentype_t type, const char *token_info, const char *uuid);

/**
 * frees a generic scd token
 * @param token the token to be freed
 *
 * @return void
 */
void
token_free(token_t *token);

#endif /* TOKEN_H */
