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

#include "usbtoken.h"
#include "ssl_util.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include "common/macro.h"

#include "common/mem.h"
#include "common/file.h"

#include <ctapi.h>

#include "sc-hsm-cardservice.h"

#define TOKEN_MAX_AUTH_CODE_LEN 16
#define TOKEN_KEY_LEN 32 /* must be coordonated with ssl_util.c */

/* TODO: investigate enforcement done by hardware token */
#define USBTOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3 


static unsigned char requesticc[] = {0x20,0x12,0x00,0x01,0x00};

struct usbtoken {
	/* Identify the usb device to be used */
	// int major;
	// int minor;
	// char *serial;

	int ctn;				// card terminal number

	bool locked;			// whether the token is locked or not
	unsigned wrong_unlock_attempts; // wrong consecutive password attempts
};

/*
 * Dump the memory pointed to by <mem>
 * TODO: remove
 */
static void dump(unsigned char *mem, int len)
{
	while(len--) {
		printf("%02x", *mem);
		mem++;
	}

	printf("\n");
}

/*
 * Request card
 *
 */
static int requestICC(int ctn)
{
	unsigned char Brsp[260];
	unsigned short lr;
	unsigned char dad, sad;
	int rc;

	TRACE("USBTOKEN: requestICC");

	dad = 1;   /* Reader */
	sad = 2;   /* Host */
	lr = sizeof(Brsp);

	rc = CT_data((unsigned short)ctn, &dad, &sad, sizeof(requesticc),
                    (unsigned char *) &requesticc, &lr, Brsp);
	if (rc != OK) {
		ERROR("CT_data failedwith code: %d", rc);
		return rc;
	}				

	DEBUG("USBTOKEN: ATR: ");
	dump(Brsp, lr);

	if((Brsp[0] == 0x64) || (Brsp[0] == 0x62)) {
		ERROR("No card present or card reset error");
		return -1;
	}

	return 0;
}

/**
 * Produce a key value by derivation from the master key
 *
 * @param ctn the card terminal number
 * @param label he derivation parameter (aka label), must NOT be NULL
 * @return < 0 for error or 0
 * 
 * TODO: make params const where possible
 */
static int produceKey(int ctn, unsigned char *label, size_t label_len,
                        unsigned char *key, size_t key_len)
{
	int rc;

	TRACE("USBTOKEN: produceKey");

	unsigned char def_label[] = "disk1";

	if ((NULL == label) || (0 == label_len)) {
		WARN("USBTOKEN: no 'label' provided for key derivation; using default label");
		rc = deriveKey(ctn, 1, def_label, sizeof(def_label), key, key_len);
	} else {
		rc = deriveKey(ctn, 1, label, label_len, key, key_len);
	}

	if (rc < 0) {
		ERROR("USBTOKEN: deriveKey failed");
		return rc;
	}

    DEBUG("Usbtoken generated key:");
	dump(key, key_len); /* TODO: remove */

	return 0;
}

/**
 * Report the status of the PIN
 *
 * @param sw the SW1/SW2 status word returned by the VERIFY or CHANGE REFERENCE DATA command
 */
static void reportPinStatus(int sw) {
	switch(sw) {
	case 0x6700:
		DEBUG("USBTOKEN: Wrong PIN length. Pairing secret missing ?");
		break;
	case 0x6983:
		DEBUG("USBTOKEN: PIN blocked");
		break;
	case 0x6984:
		DEBUG("USBTOKEN: PIN in transport state");
		break;
	default:
		if ((sw & 0x63C0) == 0x63C0) {
			int rc = sw & 0xF;

			if (rc > 1) {
				ERROR("USBTOKEN: PIN wrong, %d tries remaining", rc);
			} else {
				ERROR("USBTOKEN: PIN wrong, one try remaining");
			}
		}
	}
}

/**
 * Perform user authentication, potentially including the pairing secret
 *
 * @param ctn the card terminal number
 * @return < 0 for error or 0
 * 
 * TODO: reports false length of PIN as dedicated error. Is that really desirable?
 */
static int authenticateUser(int ctn, char *pin, size_t pin_len,
                            unsigned char *pairing_secret, size_t pairing_sec_len)
{
	int rc, ofs;
	unsigned char code[TOKEN_MAX_AUTH_CODE_LEN]; /* TODO: is this length limited by the token? */

	TRACE("USBTOKEN: authenticateUser");

	if ((pin == NULL) || (pin_len == 0)) {
		ERROR("No PIN provided");
		return -1;
	}
	
    if ((pin_len +  pairing_sec_len) > sizeof(code) ) {
        ERROR("PIN and pairing secret combined must not exceed %d",
				TOKEN_MAX_AUTH_CODE_LEN);
        return -1;
    }

    ofs = 0;

	TRACE("USBTOKEN: pairing_sec_len: %d", (int) pairing_sec_len);
	TRACE("USBTOKEN: pin_len: %d", (int) pin_len);
	
    if (pairing_secret != NULL) {
		memcpy(code, pairing_secret, pairing_sec_len);
		ofs = pairing_sec_len;
	}

	memcpy(code + ofs, (unsigned char *)pin, strlen(pin));
	ofs += pin_len;

	TRACE("USBTOKEN: Total authentication code len: %d", ofs);

	rc = verifyPIN(ctn, code, ofs);

	memset(code, 0, sizeof(code));

	if (rc != 0x9000) {
		reportPinStatus(rc);
		return -1;
	}

	return 0;
}

/** 
 * Initializes a usb token
 * TODO: select and init only desired usb token
 */
usbtoken_t *
usbtoken_init(void) {
	unsigned short lr;
	int rc;
	unsigned char readers[4096],*po; /* TODO */
	usbtoken_t *token = NULL;

	TRACE("USBTOKEN: usbtoken_init");

	token = mem_new0(usbtoken_t, 1);
	ASSERT(token);

	token->locked = true;

	lr = sizeof(readers);
	CT_list(readers, &lr, 0);

	if (lr <= 0) {
		ERROR("No token found.");
		return NULL;
	}

	po = readers;
	unsigned short port = *po << 8 | *(po + 1);
	po += 2;

	DEBUG("USBTOKEN: using token %04x : %s\n", port, po);

	token->ctn = 0;

	rc = CT_init(token->ctn, port);
	requestICC(token->ctn);

	rc = queryPIN(token->ctn);

	if (rc != 0x9000) {
		selectHSM(token->ctn);
		rc = queryPIN(token->ctn);
	}

	TRACE("Usbtoken initialized");
	return token;
}

/** scd interface to usbtoken **/

int
usbtoken_change_passphrase(usbtoken_t *token, const char *oldpass, const char *newpass)
{
	ASSERT(token);

	TRACE("USBTOKEN: usbtoken_change_passphrase");

	/* TODO */
	ASSERT(oldpass);
	ASSERT(newpass);

//	return ssl_newpass_pkcs12_token(token->token_file, oldpass, newpass);
	ERROR("Usbtoken PIN changing not implemented yet");
	return -1;
}

/**
 * Free secrets.
 */
static void
usbtoken_free_secrets(usbtoken_t *token)
{
	ASSERT(token);

	TRACE("USBTOKEN: usbtoken_free_secrets");
	
 	/* TODO: are there any secrets to be freed? */
}

void
usbtoken_free(usbtoken_t *token)
{
	ASSERT(token);

	TRACE("USBTOKEN: usbtoken_free");

	usbtoken_free_secrets(token);

	mem_free(token);
}


/**
 * Wraps the plain key.
 */
int
usbtoken_wrap_key(usbtoken_t *token, unsigned char *label, size_t label_len,
				  unsigned char *plain_key, size_t plain_key_len,
				  unsigned char **wrapped_key, int *wrapped_key_len)
{
	ASSERT(token);

	ASSERT(plain_key);
	ASSERT(wrapped_key);
	ASSERT(wrapped_key_len);
	ASSERT(plain_key_len);

	int rc;
	unsigned char key[TOKEN_KEY_LEN];

	TRACE("USBTOKEN: usbtoken_wrap_key");

	// TODO allow wrapping (encryption with public key) even with locked token?
	if (usbtoken_is_locked(token)) {
		WARN("Trying to wrap key with locked token.");
		return -1;
	}

	produceKey(token->ctn, label, label_len, key, sizeof(key));

	const unsigned char *kek = key;
	rc = ssl_wrap_key_sym(kek, plain_key, plain_key_len, wrapped_key, wrapped_key_len);

	if (0 != rc) {
		ERROR("ssl_wrap_key_sym failed");
		return -1;
	}

	return rc;
}

int
usbtoken_unwrap_key(usbtoken_t *token, unsigned char *label, size_t label_len,
					unsigned char *wrapped_key, size_t wrapped_key_len,
		    		unsigned char **plain_key, int *plain_key_len)
{
	ASSERT(token);
	ASSERT(wrapped_key);
	ASSERT(plain_key);
	ASSERT(plain_key_len);

	ASSERT(wrapped_key_len);

	TRACE("USBTOKEN: usbtoken_unwrap_key");

	int rc;
	unsigned char key[TOKEN_KEY_LEN];

	if (usbtoken_is_locked(token)) {
		WARN("Trying to unwrap key with locked token.");
		return -1;
	}
	
	produceKey(token->ctn, label, label_len, key, sizeof(key));

	const unsigned char *kek = key;
	TRACE("Call ssl_unwrap_unkey_sym");
	rc = ssl_unwrap_key_sym(kek, wrapped_key, wrapped_key_len, plain_key, plain_key_len);

	if (0 != rc) {
		ERROR("ssl_unwrap_key_sym failed");
		return -1;
	}
	
	TRACE("USBTOKEN: key unwrap successful");
	return rc;	
}

bool
usbtoken_is_locked_till_reboot(usbtoken_t *token)
{
	ASSERT(token);
	
	TRACE("USBTOKEN: usbtoken_is_locked_till_reboot");

	return token->wrong_unlock_attempts >= USBTOKEN_MAX_WRONG_UNLOCK_ATTEMPTS;
}

bool
usbtoken_is_locked(usbtoken_t *token)
{
	ASSERT(token);
	
	TRACE("USBTOKEN: usbtoken_is_locked");
	
	return token->locked;
}

int
usbtoken_available(void)
{
	/* TODO */

	TRACE("USBTOKEN: usbtoken_is_available");

	return 0;
}

int
usbtoken_unlock(usbtoken_t *token, char *passwd, 
				unsigned char *pairing_secret, size_t pairing_sec_len)
{
	ASSERT(token);
	ASSERT(passwd);

	TRACE("USBTOKEN: usbtoken_unlock");

	if (!usbtoken_is_locked(token)) {
		WARN("Token is alread unlocked, returning");
		return 0;
	}

	if (usbtoken_is_locked_till_reboot(token)) {
		WARN("Token is locked till reboot, returning");
		return -1;
	}

	if (0 != usbtoken_available()) {
		ERROR("Usb token not available!");
		return -1;
	}

	int res = authenticateUser(token->ctn, passwd, strlen(passwd), 
								pairing_secret, pairing_sec_len);
	if (res == -1) {// wrong password
		token->wrong_unlock_attempts++;
		ERROR("Usbtoken unlock failed (wrong PW)");
	} else if (res == 0) {
		token->locked = false;
		token->wrong_unlock_attempts = 0;
		DEBUG("Usbtoken unlock successful");
	} else {
		ERROR("Usbtoken unlock failed");
	}
	// TODO what to do with wrong_unlock_attempts if unlock failed for some other reason?

	if (res != 0)
		usbtoken_free_secrets(token); // just to be sure

	return res;
}

/**
 * locks the usb token
 * TODO: this should actually lock the HW token nad not just set a flag
 */
int
usbtoken_lock(usbtoken_t *token)
{
	ASSERT(token);

	TRACE("USBTOKEN: usbtoken_lock");

	if (usbtoken_is_locked(token)) {
		DEBUG("USBTOKEN: Token is already locked, returning.");
		return 0;
	}

	/* TODO: actually lock hardware token */

	// usbtoken_free_secrets(token);
	token->locked = true;
	return 0;
}
