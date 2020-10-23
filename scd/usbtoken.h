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

#define MAX_APDU_BUF_LEN 4096

typedef struct usbtoken usbtoken_t;

#ifdef ENABLESCHSM

/**
 * Initializes a usb token, iff the serial number of the usb token reader matches
 * @param serial the iSerial of the usb reader of the token
 * @return pointer to the usbtoken structure on success or NULL on error
 */
usbtoken_t *
usbtoken_new(const char *serial);

/**
 * unlocks a usbtoken with a password.
 * stores the token private key in the structure
 * @param token the usbtoken to unlock
 * @param passwd the user pin/passwd for the token
 * @param pairing_sec the platform-bound pairing secret
 * @param pairing_sec_len the length of the pairing secret
 * @return 0 on success or < 0 on error
 */
int
usbtoken_unlock(usbtoken_t *token, char *passwd, unsigned char *pairing_secret,
		size_t pairing_sec_len);

/**
 * locks a usbtoken by freeing the private key
 * reference in the usbtoken
 * @param token the usbtoken to lock
 * @return 0 on success or < 0 on error
 */
int
usbtoken_lock(usbtoken_t *token);

/**
 * checks whether the usbtoken is locked or not
 * @param token the usbtoken to check
 * @return false if token is unlocked or true if it is locked
 */
bool
usbtoken_is_locked(usbtoken_t *token);

/**
 * checks whether the usbtoken is locked or not till next reboot
 * @param token the usbtoken to check
 * @return false if token is not or true if it is locked until next reboot
 */
bool
usbtoken_is_locked_till_reboot(usbtoken_t *token);

/**
 * frees a usbtoken structure
 * @param token the usbtoken to free
 */
void
usbtoken_free(usbtoken_t *token);

/**
 * wraps a symmetric container key plain_key of length plain_key_len with a
 * symmetric key provided by the token into a wrapped key wrapped_key of
 * length wrapped_key_len
 * @param token the usbtoken to wrap the key with
 * @param label key derivation parameter to be used to derive the wrapping key
 * @param label_len the length of @param label
 * @param plain_key the key to be wrapped
 * @param plain_key_len the length of @param plain_key
 * @param wrapped_key the resulting wrapped key
 * @param wrapped_key_len the length of @param wrapped_key
 * @return 0 on success or < 0 on error
 */
int
usbtoken_wrap_key(usbtoken_t *token, unsigned char *label, size_t label_len,
		  unsigned char *plain_key, size_t plain_key_len, unsigned char **wrapped_key,
		  int *wrapped_key_len);

/**
 * unwraps a symmetric container key wrapped_key of length wrapped_key_len with a
 * symmetric key provided key into the plain key plain_key of length plain_key_len
 * @param token the usbtoken to unwrap the key with
 * @param label key derivation parameter to be used to derive the wrapping key
 * @param label_len the length of @param label
 * @param wrapped_key the wrapped key that should be unwrapped
 * @param wrapped_key_len the length of @param wrapped_key
 * @param plain_key the resulting plain key
 * @param plain_key_len the length of @param plain_key
 * @return 0 on success or < 0 on error
 */
int
usbtoken_unwrap_key(usbtoken_t *token, unsigned char *label, size_t label_len,
		    unsigned char *wrapped_key, size_t wrapped_key_len, unsigned char **plain_key,
		    int *plain_key_len);

/**
 * Changes the pasphrase/pin of the underlying low level structure
 * of the usbtoken
 * @param token the usbtoken whose pin/passwd should be changed
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
int
usbtoken_change_passphrase(usbtoken_t *token, const char *oldpass, const char *newpass,
			   unsigned char *pairing_secret, size_t pairing_sec_len,
			   bool is_provisioning);

/**
 * Sends an APDU to the usbtoken and receive the response.
 * @param token the usbtoken to communicate with
 * @param apdu the apdu byte arry to send to the token
 * @param apdu_len legnth of @param apdu
 * @param brsp the buffer for the response
 * @param brsp_len the size of @param Brsp
 * @return  0 on success or < 0 on error
 */
int
usbtoken_send_apdu(usbtoken_t *token, unsigned char *apdu, size_t apdu_len, unsigned char *brsp,
		   size_t lr);

/**
 * Resets the authentication status of the usbtoken using the cached authentication code.
 * @param brsp the buffer for the response
 * @param brsp_len the size of @param Brsp
 * @return  0 on success or < 0 on error

 */
int
usbtoken_reset_auth(usbtoken_t *token, unsigned char *brsp, size_t brsp_len);

/**
 * Gets the ATR from the usbtoken.
 * @param brsp the buffer for the response
 * @param brsp_len the size of @param Brsp
 * @return  0 on success or < 0 on error
 */
int
usbtoken_get_atr(usbtoken_t *token, unsigned char *brsp, size_t brsp_len);

#endif

#endif // ENABLESCHSM
