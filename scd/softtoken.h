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

#ifndef SOFTTOKEN_H
#define SOFTTOKEN_H

#include <stdbool.h>
#include <stddef.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

typedef struct softtoken softtoken_t;

/**
 * instantiates a new softtoken structure
 */
softtoken_t *
softtoken_new_from_p12(const char *filename);

/**
 * Changes the pasphrase/pin of the underlying low level structure
 * of the softtoken token.
 */
int
softtoken_change_passphrase(softtoken_t *token, const char *oldpass,
					const char *newpass);

/**
 * unlocks a softtoken with a password.
 * stores the token private key in the structure
 */
int
softtoken_unlock(softtoken_t *token, char *passphrase);

/**
 * locks a softtoken by freeing the private key
 * reference in the softtoken
 */
int
softtoken_lock(softtoken_t *token);

/**
 * checks whether the softtoken is locked or not
 */
bool
softtoken_is_locked(softtoken_t *token);

/**
 * checks whether the softtoken is locked or not till next reboot
 */
bool
softtoken_is_locked_till_reboot(softtoken_t *token);

/**
 * frees a softtoken structure
 */
void
softtoken_free(softtoken_t *token);

/**
 * wraps a symmetric container key plain_key of length plain_key_len with a
 * user public key pubkey into a wrapped key wrapped_key of legnth wrapped_key_len
 */
int
softtoken_wrap_key(softtoken_t *token, const unsigned char *plain_key, size_t plain_key_len,
		unsigned char **wrapped_key, int *wrapped_key_len);

/**
 * unwraps a symmetric container key wrapped_key of length wrapped_key_len with a
 * user's private key into the plain key plain_key of legnth plain_key_len
 */
int
softtoken_unwrap_key(softtoken_t *token, const unsigned char *wrapped_key, size_t wrapped_key_len,
		unsigned char **plain_key, int *plain_key_len);

#endif /* SOFTTOKEN_H */

