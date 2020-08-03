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

#include "sc-hsm-cardservice.h"
#include <ctapi.h>

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define TOKEN_MAX_AUTH_CODE_LEN 16
#define TOKEN_KEY_LEN 32 /* must be coordinated with ssl_util.c */

#define MAX_CT_READERS_SIZE 4096

/* TODO: investigate enforcement done by hardware token */
#define USBTOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3

#define USBTOKEN_SUCCESS 0x9000

static unsigned short g_ctn = 0;

/* following are implementation specific byte arrays used to commuicate with 'sc-hsm' tokens
 * manufactored by CardContact.
 * See https://github.com/CardContact/sc-hsm-embedded for more information.
 */
static const unsigned char requesticc[] = { 0x20, 0x12, 0x00, 0x01, 0x00 };

static unsigned char skd_dskkey[] = { 0xA8, 0x2F, 0x30, 0x13, 0x0C, 0x11, 0x44, 0x69, 0x73, 0x6B,
				      0x45, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6F, 0x6E,
				      0x4B, 0x65, 0x79, 0x30, 0x08, 0x04, 0x01, 0x01, 0x03, 0x03,
				      0x07, 0xC0, 0x10, 0xA0, 0x06, 0x30, 0x04, 0x02, 0x02, 0x00,
				      0x80, 0xA1, 0x06, 0x30, 0x04, 0x30, 0x02, 0x04, 0x00 };

static unsigned char algo_dskkey[] = { 0x91, 0x01, 0x99 };

struct usbtoken {
	char *serial;

	unsigned short ctn;  // card terminal number
	unsigned short port; // usb port of token reader

	bool locked;			// whether the token is locked or not
	unsigned wrong_unlock_attempts; // wrong consecutive password attempts

	// the authentication code is cached as long as the token remains unlocked
	unsigned char *auth_code;
	size_t auth_code_len;
};

/**
 * Derive an authentication code from a parining secret and a user pin/passwd.
 * TODO: use an actual KDF
 * @param pin the user pin for the token
 * @param pair_sec the platform-bound paring secret
 * @param pair_sec_len length of the pairing secret
 * @param auth_code_buf buffer to hold the authentication code derived from both the user pin and the pairing secret
 * @param buf_len the size of the buffer which holds the authentication code
 *
 * @return the length of the authentication code in Byte
 */
static int
get_auth_code(const char *pin, const unsigned char *pair_sec, size_t pair_sec_len,
	      unsigned char *auth_code_buf, size_t buf_len)
{
	int ofs = 0;

	int pin_len = strlen(pin);

	ASSERT(auth_code_buf);

	TRACE("USBTOKEN: pairing_sec_len: %zu", pair_sec_len);
	TRACE("USBTOKEN: pin_len: %d", pin_len);

	if ((pin == NULL) || (strlen(pin) == 0)) {
		ERROR("No PIN provided");
		return -1;
	}

	if ((pin_len + pair_sec_len) > buf_len) {
		ERROR("PIN and pairing secret combined must not exceed %d",
		      TOKEN_MAX_AUTH_CODE_LEN);
		return -1;
	}

	if (pair_sec != NULL) {
		memcpy(auth_code_buf, pair_sec, pair_sec_len);
		ofs = pair_sec_len;
	}

	memcpy(auth_code_buf + ofs, (unsigned char *)pin, pin_len);
	ofs += pin_len;

	return ofs;
}

#define CT_APDU_RESPONSE_BUF_SIZE 260
/*
 * Request card
 */
static int
requestICC(int ctn)
{
	unsigned short lr;
	unsigned char dad, sad;
	int rc = -1;
	unsigned char *Brsp = mem_alloc0(CT_APDU_RESPONSE_BUF_SIZE);
	if (!Brsp) {
		ERROR("Could not allocate memory for APDU repsonse buffer");
		goto out;
	}

	dad = 1; /* Reader */
	sad = 2; /* Host */
	lr = CT_APDU_RESPONSE_BUF_SIZE;

	rc = CT_data((unsigned short)ctn, &dad, &sad, sizeof(requesticc),
		     (unsigned char *)&requesticc, &lr, Brsp);
	if (rc != 0) {
		ERROR("CT_data failed with code: %d", rc);
		goto out;
	}

	if ((Brsp[0] == 0x64) || (Brsp[0] == 0x62)) {
		ERROR("No card present or card reset error");
		rc = -1;
		goto out;
	}

	mem_free(Brsp);
	return 0;

out:
	mem_free(Brsp);
	return rc;
}

/**
 * Perform user authentication, potentially including the pairing secret
 *
 * @param ctn the card terminal number
 * @return 0 on success or else -1
 */
static int
authenticateUser(int ctn, unsigned char *auth_code, size_t auth_code_len)
{
	int rc = verifyPIN(ctn, auth_code, auth_code_len);

	if (rc != USBTOKEN_SUCCESS) {
		ERROR("Could not authenticate user to usb token, token rc: 0x%04x", rc);
		return -1;
	}

	return 0;
}

/**
 * Produce a key by derivation from the master key
 *
 * @param ctn the card terminal number
 * @param label the derivation parameter (aka label), must NOT be NULL
 * @return 0 on succes or else < 0
 */
static int
produceKey(usbtoken_t *token, unsigned char *label, size_t label_len, unsigned char *key,
	   size_t key_len)
{
	int rc;

	if ((authenticateUser(token->ctn, token->auth_code, token->auth_code_len)) < 0) {
		// this should not possibly happen; TODO: handle properly if it happens anyway
		ERROR("Failed to authenticate to token");
		return -1;
	}

	if ((NULL == label) || (0 == label_len)) {
		ERROR("No label was provided for key derivation");
		return -1;
	} else {
		rc = deriveKey(token->ctn, 1, label, label_len, key, key_len);
	}

	if (rc < 0) {
		ERROR("USBTOKEN: deriveKey failed");
		return rc;
	}

	return 0;
}

/**
 * returns the port of the desired reader
 *
 * @param readers a buffer that contains port numbers and associated reader names
 *	as returned from CT_list()
 * @param lr actual length of @param readers
 * @param serial the serial number of the usb smartcard reader
 * @param port the port reader with the given serial or NULL
 * @return 0 on success
 */
int
token_filter_by_serial(const unsigned char *readers, const unsigned short lr, const char *serial,
		       unsigned short *port)
{
	ASSERT(readers);
	ASSERT(serial);

	char *po;
	unsigned short idx;
	unsigned short iport;

	char *s = (char *)mem_memcpy(readers, lr);
	/* readers: |-|-|---15---|---X---|-|-|
	 *	 fields  1 2     3       4    5 6
	 * 		1: uint8_t libusb_get_bus_number()
	 * 		2: uint8_t libusb_get_device_address
	 * 		3: string  "SmartCard-HSM ("
	 * 		4: string  iSerialNumber
	 * 		5: string  ")"
	 * 		6: NULL byte to delimit next reader
	 */
	po = s;
	idx = 0;

	while (idx < lr) {
		iport = *po << 8 | *(po + 1);
		po += 2;
		idx += 2;

		po += 15;

		size_t s_len = strlen(po) - 1;

		if ((s_len > 0) && (strncmp(po, serial, s_len) == 0)) {
			TRACE("USBTOKEN: token_filter_by_serial() found reader with serial: %s at port 0x%04x",
			      serial, iport);
			*port = iport;
			mem_free(s);
			return 0;
		}

		po += 15 + s_len + 1;
		idx += 15 + s_len + 1;
	}

	*port = 0;
	mem_free(s);
	return -1;
}

/**
 * initializes the ctapi interface to the token reader.
 * If the reader is unplugged during runtime this will ensure it is either
 * reaquired using the correct usb port or not at all
 * @param token the usbtoken which the ctapi interface should be initilized to
 * @return 0 on success or -1 else
 */
static int
usbtoken_init_ctapi_int(usbtoken_t *token)
{
	ASSERT(token);

	int rc = -1;
	unsigned short lr, port;
	unsigned char *readers = mem_alloc0(MAX_CT_READERS_SIZE);
	if (!readers) {
		ERROR("Failed to allocate memory for ct_reader");
		goto err;
	}

	lr = MAX_CT_READERS_SIZE;
	CT_list(readers, &lr, 0);

	if (lr <= 0) {
		ERROR("No usb token reader found.");
		goto err;
	}

	rc = token_filter_by_serial(readers, lr, token->serial, &port);
	if (rc != 0) {
		ERROR("Could not find specified token reader with serial %s", token->serial);
		goto err;
	}
	token->port = port;

	rc = CT_init(token->ctn, port);
	if (rc != 0) {
		ERROR("USBTOKEN: Token reader initialization failed. Ret code: %d", rc);
		goto err;
	}

	rc = requestICC(token->ctn);
	if (rc != 0) {
		ERROR("requestICC failed for token with ctn: %hu and port: %hu", token->ctn,
		      token->port);
		goto err;
	}

	rc = queryPIN(token->ctn);
	if (rc != USBTOKEN_SUCCESS) {
		rc = selectHSM(token->ctn);
		if (rc != 0) {
			ERROR("selectHSM failed for token with ctn: %hu and port: %hu", token->ctn,
			      token->port);
			goto err;
		}
		rc = queryPIN(token->ctn);
		DEBUG("usbtoken_init queryPIN: 0x%04x", rc);
	}

	mem_free(readers);
	return 0;

err:
	mem_free(readers);
	return -1;
}

/**
 * Initializes a usb token
 */
usbtoken_t *
usbtoken_new(const char *serial)
{
	ASSERT(serial);

	int rc;
	usbtoken_t *token = NULL;

	token = mem_new0(usbtoken_t, 1);
	ASSERT(token);

	token->locked = true;
	token->ctn = g_ctn++;
	token->serial = mem_strdup(serial);
	if (!token->serial) {
		ERROR("USBTOKEN: Allocating meory for token uuid failed");
		goto err;
	}

	rc = usbtoken_init_ctapi_int(token);
	if (rc != 0) {
		ERROR("Failed to initialize ctapi interface to usb token reader");
		goto err;
	}

	token->locked = true;

	/* close the usb connection to the reader so other components can communicate with it */
	if (0 != CT_close(token->ctn)) {
		ERROR("Closing CT interface to token failed.");
	}

	TRACE("Usbtoken initialized");
	return token;

err:
	mem_free(token->serial);
	mem_free(token);
	return NULL;
}

static int
provision_auth_code(usbtoken_t *token, const char *tpin, const char *newpass,
		    unsigned char *pairing_secret, size_t pairing_sec_len)
{
	TRACE("USBTOKEN: provision_auth_code");

	ASSERT(token);
	ASSERT(tpin);
	ASSERT(newpass);
	ASSERT(pairing_secret);

	int rc;
	int newcode_len;
	unsigned char newcode[TOKEN_MAX_AUTH_CODE_LEN];

	rc = usbtoken_init_ctapi_int(token);
	if (rc != 0) {
		ERROR("Failed to initialize ctapi interface to usb token reader");
		rc = -1;
		goto out;
	}

	rc = queryPIN(token->ctn);
	if (rc != 0x6984) {
		ERROR("USBTOKEN: Pin is not in tranport state. Aborting");
		rc = -1;
		goto out;
	}

	newcode_len =
		get_auth_code(newpass, pairing_secret, pairing_sec_len, newcode, sizeof(newcode));
	if (newcode_len < 0) {
		ERROR("Could not derive new authentication code");
		rc = -1;
		goto out;
	}

	rc = changePIN(token->ctn, (unsigned char *)tpin, strlen(tpin), newcode, newcode_len);

	memset(newcode, 0, sizeof(newcode));

	if (rc != USBTOKEN_SUCCESS) {
		ERROR("Provisioning of usbtoken failed. Token rc: 0x%04x", rc);
		rc = -1;
		goto out;
	}

	/* after pairing (pin should no longer be in transport state), we generate a
	 * master secret from which the subsequent keys can be derived.
	 * Device initialization must only be possible for user in possession of SO-PIN
	 */
	rc = generateSymmetricKey(token->ctn, 1, algo_dskkey, sizeof(algo_dskkey));
	if (rc < 0) {
		ERROR("USBTOKEN: generateSymmetricKey() failed with code: %d", rc);
		rc = -1;
		goto out;
	}

	rc = writeKeyDescription(token->ctn, 1, skd_dskkey, sizeof(skd_dskkey));
	if (rc < 0) {
		ERROR("USBTOKEN: writeKeyDescription() failed with code: %d", rc);
		rc = -1;
	}

out:
	if (0 != CT_close(token->ctn)) {
		ERROR("Closing CT interface to token failed.");
	}
	return rc;
}

static int
change_user_pin(usbtoken_t *token, const char *oldpass, const char *newpass,
		unsigned char *pairing_secret, size_t pairing_sec_len)
{
	TRACE("USBTOKEN: change_user_pin");

	ASSERT(token);
	ASSERT(oldpass);
	ASSERT(newpass);
	ASSERT(pairing_secret);

	int rc;
	int oldcode_len, newcode_len;
	unsigned char oldcode[TOKEN_MAX_AUTH_CODE_LEN];
	unsigned char newcode[TOKEN_MAX_AUTH_CODE_LEN];

	rc = usbtoken_init_ctapi_int(token);
	if (rc != 0) {
		ERROR("Failed to initialize ctapi interface to usb token reader");
		rc = -1;
		goto out;
	}

	newcode_len =
		get_auth_code(newpass, pairing_secret, pairing_sec_len, newcode, sizeof(newcode));
	if (newcode_len < 0) {
		ERROR("Could not derive new authentication code");
		rc = -1;
		goto out;
	}

	oldcode_len =
		get_auth_code(oldpass, pairing_secret, pairing_sec_len, oldcode, sizeof(oldcode));
	if (oldcode_len < 0) {
		ERROR("Could not derive old authentication code");
		rc = -1;
		goto out;
	}

	rc = changePIN(token->ctn, oldcode, oldcode_len, newcode, newcode_len);

	memset(newcode, 0, sizeof(newcode));
	memset(oldcode, 0, sizeof(oldcode));

	if (rc != USBTOKEN_SUCCESS) {
		ERROR("Changing user pin of usbtoken failed. Token rc: 0x%04x", rc);
		rc = -1;
	} else
		rc = 0;

out:
	if (0 != CT_close(token->ctn)) {
		ERROR("Closing CT interface to token failed.");
	}
	return rc;
}

/** scd interface to usbtoken **/

int
usbtoken_change_passphrase(usbtoken_t *token, const char *oldpass, const char *newpass,
			   unsigned char *pairing_secret, size_t pairing_sec_len,
			   bool is_provisioning)
{
	TRACE("USBTOKEN: usbtoken_change_passphrase");

	ASSERT(token);
	ASSERT(oldpass);
	ASSERT(newpass);

	return (is_provisioning ?
			provision_auth_code(token, oldpass, newpass, pairing_secret,
					    pairing_sec_len) :
			change_user_pin(token, oldpass, newpass, pairing_secret, pairing_sec_len));
}

/**
 * Free secrets.
 */
static void
usbtoken_free_secrets(usbtoken_t *token)
{
	TRACE("USBTOKEN: usbtoken_free_secrets");

	ASSERT(token);

	memset(token->auth_code, 0, token->auth_code_len);
	mem_free(token->auth_code);
}

void
usbtoken_free(usbtoken_t *token)
{
	TRACE("USBTOKEN: usbtoken_free");

	ASSERT(token);

	mem_free(token->serial);
	usbtoken_free_secrets(token);

	mem_free(token);
	g_ctn--;
}

/**
 * Wraps the plain key.
 */
int
usbtoken_wrap_key(usbtoken_t *token, unsigned char *label, size_t label_len,
		  unsigned char *plain_key, size_t plain_key_len, unsigned char **wrapped_key,
		  int *wrapped_key_len)
{
	TRACE("USBTOKEN: usbtoken_wrap_key");

	ASSERT(token);
	ASSERT(plain_key);
	ASSERT(wrapped_key);
	ASSERT(wrapped_key_len);

	int rc = -1;
	unsigned char key[TOKEN_KEY_LEN];

	if (usbtoken_is_locked(token)) {
		ERROR("Trying to wrap key with locked token.");
		return -1;
	}

	rc = usbtoken_init_ctapi_int(token);
	if (rc != 0) {
		ERROR("Failed to initialize ctapi interface to usb token reader");
		goto out;
	}

	rc = produceKey(token, label, label_len, key, sizeof(key));
	if (rc < 0) {
		ERROR("Failed to get derived key from usbtoken");
		rc = -1;
		goto out;
	}

	const unsigned char *kek = key;
	rc = ssl_wrap_key_sym(kek, plain_key, plain_key_len, wrapped_key, wrapped_key_len);

	if (0 != rc) {
		ERROR("ssl_wrap_key_sym failed");
		rc = -1;
		goto out;
	}

out:
	if (0 != CT_close(token->ctn)) {
		ERROR("Closing CT interface to token failed.");
	}
	return rc;
}

int
usbtoken_unwrap_key(usbtoken_t *token, unsigned char *label, size_t label_len,
		    unsigned char *wrapped_key, size_t wrapped_key_len, unsigned char **plain_key,
		    int *plain_key_len)
{
	TRACE("USBTOKEN: usbtoken_unwrap_key");

	ASSERT(token);
	ASSERT(wrapped_key);
	ASSERT(plain_key);
	ASSERT(plain_key_len);

	int rc;
	unsigned char key[TOKEN_KEY_LEN];

	if (usbtoken_is_locked(token)) {
		ERROR("Trying to unwrap key with locked token.");
		return -1;
	}

	rc = usbtoken_init_ctapi_int(token);
	if (rc != 0) {
		ERROR("Failed to initialize ctapi interface to usb token reader");
		goto out;
	}

	rc = produceKey(token, label, label_len, key, sizeof(key));
	if (rc < 0) {
		ERROR("Failed to get derived key from usbtoken");
		rc = -1;
		goto out;
	}

	const unsigned char *kek = key;
	rc = ssl_unwrap_key_sym(kek, wrapped_key, wrapped_key_len, plain_key, plain_key_len);

	if (0 != rc) {
		ERROR("ssl_unwrap_key_sym failed");
		rc = -1;
		goto out;
	}

	TRACE("USBTOKEN: key unwrap successful");

out:
	if (0 != CT_close(token->ctn)) {
		ERROR("Closing CT interface to token failed.");
	}
	return rc;
}

bool
usbtoken_is_locked_till_reboot(usbtoken_t *token)
{
	ASSERT(token);
	return (token->wrong_unlock_attempts >= USBTOKEN_MAX_WRONG_UNLOCK_ATTEMPTS);
}

bool
usbtoken_is_locked(usbtoken_t *token)
{
	ASSERT(token);
	return token->locked;
}

int
usbtoken_unlock(usbtoken_t *token, char *passwd, unsigned char *pairing_secret,
		size_t pairing_sec_len)
{
	TRACE("USBTOKEN: usbtoken_unlock");

	ASSERT(token);
	ASSERT(passwd);

	if (!usbtoken_is_locked(token)) {
		WARN("Token is already unlocked, returning");
		return 0;
	}

	if (usbtoken_is_locked_till_reboot(token)) {
		WARN("Token is locked till reboot, returning");
		return -1;
	}

	int auth_code_len = 0;
	unsigned char code[TOKEN_MAX_AUTH_CODE_LEN];

	auth_code_len = get_auth_code(passwd, pairing_secret, pairing_sec_len, code, sizeof(code));
	if (auth_code_len < 0) {
		ERROR("Could not derive authentication code");
		return -1;
	}

	int rc = usbtoken_init_ctapi_int(token);
	if (rc != 0) {
		ERROR("Failed to initialize ctapi interface to usb token reader");
		return -1;
	}

	rc = authenticateUser(token->ctn, code, auth_code_len);
	if (rc == -1) { // wrong password
		token->wrong_unlock_attempts++;
		ERROR("Usbtoken unlock failed (wrong PW)");
	} else if (rc == 0) {
		token->locked = false;
		token->wrong_unlock_attempts = 0;
		token->auth_code_len = auth_code_len;
		token->auth_code = mem_memcpy(code, token->auth_code_len);
		DEBUG("Usbtoken unlock successful");
	} else {
		ERROR("Usbtoken unlock failed");
	}
	// TODO what to do with wrong_unlock_attempts if unlock failed for some other reason?

	if (rc != 0)
		usbtoken_free_secrets(token); // just to be sure

	memset(code, 0, sizeof(code));

	if (0 != CT_close(token->ctn)) {
		ERROR("Closing CT interface to token failed.");
	}
	return rc;
}

int
usbtoken_reset(usbtoken_t *token)
{
	ASSERT(token);

	if (usbtoken_is_locked_till_reboot(token)) {
		WARN("Token is locked till reboot, returning");
		return -1;
	}

	int auth_code_len = 0;
	unsigned char code[TOKEN_MAX_AUTH_CODE_LEN];

	auth_code_len = get_auth_code(passwd, pairing_secret, pairing_sec_len, code, sizeof(code));
	if (auth_code_len < 0) {
		ERROR("Could not derive authentication code");
		return -1;
	}

	int rc = usbtoken_init_ctapi_int(token);
	if (rc != 0) {
		ERROR("Failed to initialize ctapi interface to usb token reader");
		return -1;
	}

	rc = authenticateUser(token->ctn, code, auth_code_len);
	if (rc == -1) { // wrong password
		token->wrong_unlock_attempts++;
		ERROR("Usbtoken unlock failed (wrong PW)");
	} else if (rc == 0) {
		token->locked = false;
		token->wrong_unlock_attempts = 0;
		token->auth_code_len = auth_code_len;
		token->auth_code = mem_memcpy(code, token->auth_code_len);
		DEBUG("Usbtoken unlock successful");
	} else {
		ERROR("Usbtoken unlock failed");
	}
	// TODO what to do with wrong_unlock_attempts if unlock failed for some other reason?

	if (rc != 0)
		usbtoken_free_secrets(token); // just to be sure

	memset(code, 0, sizeof(code));

	if (0 != CT_close(token->ctn)) {
		ERROR("Closing CT interface to token failed.");
	}
	return rc;
}

/**
 * locks the usb token.
 * Does only set the flag. We need to be able to forward the unlocked token into
 * a container so that it can operate on it.
 * NOTE: leaves the authentication code in memory so that the container can request
 * 		unlocking the token without requiring the user to re-enter the pin.
 */
int
usbtoken_lock(usbtoken_t *token)
{
	TRACE("USBTOKEN: usbtoken_lock");

	ASSERT(token);

	if (usbtoken_is_locked(token))
		DEBUG("USBTOKEN: Token is already locked, returning.");
	else
		token->locked = true;

	return 0;
}

int
usbtoken_send_apdu(usbtoken_t *token, unsigned char *apdu, size_t apu_len, unsigned char *brsp,
		   size_t brsp_len)
{
	ASSERT(token);
	ASSERT(apdu);
	ASSERT(brsp);

	unsigned short lr;
	unsigned char dad, sad;
	int rc = -1;

	int rc = usbtoken_init_ctapi_int(token);
	if (rc != 0) {
		ERROR("Failed to initialize ctapi interface to usb token reader");
		goto out;
	}

	dad = 1; /* destination: Reader */
	sad = 2; /* source: Host */
	lr = brsp_len;

	rc = CT_data((unsigned short)ctn, &dad, &sad, apdu_len, apdu, &lr, Brsp);
	if (rc != 0) {
		ERROR("CT_data failed with code: %d", rc);
		goto out;
	}

	if (0 != CT_close(token->ctn)) {
		ERROR("Closing CT interface to token failed.");
	}
	return lr;

err:
	return rc;
}
