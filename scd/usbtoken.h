/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#ifndef USBTOKEN_H
#define USBTOKEN_H

#include <stdbool.h>
#include <stddef.h>

typedef struct usbtoken usbtoken_t;

/** 
 * Initializes a usb token
 * TODO: select and init only desired usb token
 */
usbtoken_t *
usbtoken_init(void);

/**
 * unlocks a usbtoken with a password.
 * stores the token private key in the structure
 */
int
usbtoken_unlock(usbtoken_t *token, char *passwd, 
				unsigned char *pairing_secret, size_t pairing_sec_len);
/**
 * locks a usbtoken by freeing the private key
 * reference in the usbtoken
 */
int
usbtoken_lock(usbtoken_t *token);

/**
 * checks whether the usbtoken is locked or not
 */
bool
usbtoken_is_locked(usbtoken_t *token);

/**
 * checks whether the usbtoken is locked or not till next reboot
 */
bool
usbtoken_is_locked_till_reboot(usbtoken_t *token);

/**
 * frees a usbtoken structure
 */
void
usbtoken_free(usbtoken_t *token);

/**
 * wraps a symmetric container key plain_key of length plain_key_len with a
 * symmetric key provided by the token into a wrapped key wrapped_key of
 * length wrapped_key_len
 */
int
usbtoken_wrap_key(usbtoken_t *token, unsigned char *label, size_t label_len,
				  unsigned char *plain_key, size_t plain_key_len,
				  unsigned char **wrapped_key, int *wrapped_key_len);

/**
 * unwraps a symmetric container key wrapped_key of length wrapped_key_len with a
 * symmetric key provided key into the plain key plain_key of length plain_key_len
 */
int
usbtoken_unwrap_key(usbtoken_t *token, unsigned char *label, size_t label_len,
					unsigned char *wrapped_key, size_t wrapped_key_len,
		    		unsigned char **plain_key, int *plain_key_len);

/**
 * Changes the pasphrase/pin of the underlying low level structure
 * of the softtoken token.
 */
int
usbtoken_change_passphrase(usbtoken_t *token, const char *oldpass, const char *newpass);


#endif