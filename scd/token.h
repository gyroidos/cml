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

#ifndef TOKEN_H
#define TOKEN_H

#include "common/uuid.h"
#include "common/list.h"

#include <stdbool.h>
#include <stddef.h>

#define STOKEN_DEFAULT_PASS "trustme"

/**
 *  Generic token type
 */
typedef struct scd_token scd_token_t;

/**
 * Choice of supported token types.
 * Must be kept in sync with scd.proto
 */
typedef enum scd_tokentype { NONE, SOFT, USB } scd_tokentype_t;

/**
 *  generic scd_token.
 */
struct scd_token {
	void *int_token; // internal token implementation

	int (*lock)(scd_token_t *token);
	int (*unlock)(scd_token_t *token, char *passwd, unsigned char *pairing_secret,
		      size_t pairing_sec_len);

	bool (*is_locked)(scd_token_t *token);
	bool (*is_locked_till_reboot)(scd_token_t *token);

	int (*wrap_key)(scd_token_t *token, char *label, unsigned char *plain_key,
			size_t plain_key_len, unsigned char **wrapped_key, int *wrapped_key_len);

	int (*unwrap_key)(scd_token_t *token, char *label, unsigned char *wrapped_key,
			  size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len);

	int (*change_passphrase)(scd_token_t *token, const char *oldpass, const char *newpass,
				 unsigned char *pairing_secret, size_t pairing_sec_len,
				 bool is_provisioning);
	int (*send_apdu)(scd_token_t *token, unsigned char *apdu, size_t apdu_len,
			 unsigned char *brsp, size_t brsp_len);
	int (*reset_auth)(scd_token_t *token, unsigned char *brsp, size_t brsp_len);
	int (*get_atr)(scd_token_t *token, unsigned char *brsp, size_t brsp_len);

	scd_tokentype_t (*get_type)(scd_token_t *token);
	uuid_t *(*get_uuid)(scd_token_t *token);
	bool (*has_internal_token)(scd_token_t *token, const void *int_token);
	void (*free)(scd_token_t *token);
};

#endif /* TOKEN_H */
