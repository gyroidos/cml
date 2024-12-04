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
#include "token.h"
#include "usbtoken.h"
#include "scd.h"
#include "control.h"

#include "sc-hsm-lib/cardservice.h"
#include <ctapi.h>

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/list.h"
#include "common/str.h"
#include "common/ssl_util.h"
#include "common/event.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define TOKEN_MAX_AUTH_CODE_LEN 16
#define TOKEN_KEY_LEN 32 /* must be coordinated with ssl_util.c */

#define MAX_CT_READERS_SIZE 4096

/* TODO: investigate enforcement done by hardware token */
#define USBTOKEN_MAX_WRONG_UNLOCK_ATTEMPTS 3

#define USBTOKEN_SE_COMM_MAX_RETRIES 5
#define USBTOKEN_SE_COMM_TIMEOUT 10000 // check if card is still present every 10 sec

#define USBTOKEN_SUCCESS 0x9000
#define USBTOKEN_FUNCTION_NOT_SUPPORTED 0x6A81

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

static unsigned short g_ctn = 0;
static list_t *ctn_available_list = NULL; // already used but closed ctns less than g_ctn

static unsigned char aid_unselectable[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };

struct usbtoken {
	char *serial;

	unsigned short ctn;  // card terminal number
	unsigned short port; // usb port of token reader

	bool locked;			// whether the token is locked or not
	unsigned wrong_unlock_attempts; // wrong consecutive password attempts

	// the authentication code is cached as long as the token remains unlocked
	unsigned char *auth_code;
	size_t auth_code_len;

	unsigned char *latr; // ATR of last reset
	size_t latr_len;

	bool se_comm;	     // state to show if communication to SE (card) is available
	int se_comm_retries; // retry attempt after card removal (handle power glitches)
	bool timer_fast;     // switch to fast timer for reconnect
	event_timer_t *se_comm_watchdog_timer; // timer to check if card is removed

	struct cardService *cs; // API of underlying SE
};

static unsigned short
ctn_get_unused(void)
{
	unsigned short ctn;

	if (!ctn_available_list) {
		ctn = g_ctn++;
	} else {
		unsigned short *ctn_available = ctn_available_list->data;
		ctn = *ctn_available;
		mem_free0(ctn_available);
		ctn_available_list = list_unlink(ctn_available_list, ctn_available_list);
	}

	return ctn;
}

static void
ctn_set_available(unsigned short ctn)
{
	unsigned short *ctn_available = mem_new0(unsigned short, 1);
	*ctn_available = ctn;
	ctn_available_list = list_append(ctn_available_list, ctn_available);
}

/**
 * Derive an authentication code from a pairing secret and a user pin/passwd.
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

static bool
usbtoken_is_card_present(usbtoken_t *token)
{
	ASSERT(token);

	unsigned char rsp[256] = { 0 };
	unsigned short SW1SW2 = 0;

	int rc = -1;

	rc = processAPDU(token->ctn, 0, 0x00, 0x70, 0x80, 0x00, sizeof(aid_unselectable),
			 aid_unselectable, 0, rsp, sizeof(rsp), &SW1SW2);
	if (rc < 0) {
		ERROR("processAPDU failed with code: %d", rc);
		return false;
	}

#ifdef DEBUG_BUILD
	str_t *dump = str_hexdump_new(rsp, rc);
	TRACE("Select response: len: %d, apdu_data: '%s' [0x%04x]", rc,
	      dump ? str_buffer(dump) : "", SW1SW2);
	str_free(dump, true);
#endif

	if (SW1SW2 != USBTOKEN_FUNCTION_NOT_SUPPORTED) {
		ERROR("SE not present");
		return false;
	}

	return true;
}

static int
usbtoken_reset_schsm_sess(usbtoken_t *token, unsigned char *brsp, size_t brsp_len)
{
	ASSERT(token);
	ASSERT(brsp);

	int lr = requestICC(token->ctn, brsp, brsp_len);
	if (lr < 0) {
		ERROR("requestICC failed for token with ctn: %hu and port: %hu", token->ctn,
		      token->port);
		goto err;
	}
	if (NULL != token->latr)
		mem_free0(token->latr);
	token->latr = mem_memcpy(brsp, lr);
	token->latr_len = lr;

	// get cardservice
	struct cardService *cs = getCardService(token->ctn);

	IF_TRUE_GOTO_ERROR(cs == NULL, err);
	token->cs = cs;

	// check if card is operational
	int rc = token->cs->getLifeCycleState(token->ctn);
	if (!(rc == LC_CONFIGURED || rc == LC_OPERATIONAL)) {
		ERROR("USBTOKEN: card is in unsupported life cycle state: rc: 0x%04x. Aborting...",
		      rc);
		goto err;
	}

	token->se_comm = true;
	return lr;
err:
	return -1;
}

static void
usbtoken_se_comm_watchdog_cb(event_timer_t *timer, void *data);

/*
 * Reconnect to the SE
 *
 * @param token usb token on which the SE com should be reconnected
 * return true on successful reconnect or false otherwise
 */
static bool
usbtoken_se_reconnect(usbtoken_t *token)
{
	size_t brsp_len = MAX_APDU_BUF_LEN;
	unsigned char brsp[MAX_APDU_BUF_LEN] = { 0 };

	int ret = usbtoken_reset_schsm_sess(token, brsp, brsp_len);

	token->se_comm = (ret < 0) ? false : true;

	if (token->se_comm && token->se_comm_watchdog_timer == NULL) {
		token->se_comm_watchdog_timer =
			event_timer_new(USBTOKEN_SE_COMM_TIMEOUT, EVENT_TIMER_REPEAT_FOREVER,
					usbtoken_se_comm_watchdog_cb, token);
		event_add_timer(token->se_comm_watchdog_timer);
	}

	return token->se_comm;
}

static void
usbtoken_se_comm_switch_timer(usbtoken_t *token, bool fast)
{
	if (token->timer_fast == fast)
		return;

	// remove current timer
	event_remove_timer(token->se_comm_watchdog_timer);
	event_timer_free(token->se_comm_watchdog_timer);

	int new_timeout = fast ? 1000 : USBTOKEN_SE_COMM_TIMEOUT;

	/*
	 * add timer with new timeout:
	 * fast timer for reconnecting, coarse timer during connection
	 */
	token->timer_fast = fast;
	token->se_comm_watchdog_timer = event_timer_new(new_timeout, EVENT_TIMER_REPEAT_FOREVER,
							usbtoken_se_comm_watchdog_cb, token);
	event_add_timer(token->se_comm_watchdog_timer);
}

static void
usbtoken_se_comm_watchdog_cb(UNUSED event_timer_t *timer, void *data)
{
	usbtoken_t *token = data;
	ASSERT(data);

	if (token->se_comm && usbtoken_is_card_present(token))
		return;

	token->se_comm_retries++;
	TRACE("Card error retries: %d", token->se_comm_retries);

	if (usbtoken_se_reconnect(token)) {
		INFO("Successfully reconnected to SE after temporary communication error.");
		token->se_comm_retries = 0;

		// set coarse timeout, since we are connected again
		usbtoken_se_comm_switch_timer(token, false);
		return;
	}

	// set fast timer for reconnecting
	usbtoken_se_comm_switch_timer(token, true);

	if (token->se_comm_retries >= USBTOKEN_SE_COMM_MAX_RETRIES) {
		DEBUG("Notify cmld about removal of SE.");

		scd_token_t *t = scd_get_token_from_int_token(token);
		const char *uuid = t ? uuid_string(token_get_uuid(t)) : NULL;
		if (scd_control_send_event(SCD_EVENT_SE_REMOVED, uuid) < 0)
			WARN("No listener connected, notification not send");

		event_remove_timer(token->se_comm_watchdog_timer);
		event_timer_free(token->se_comm_watchdog_timer);
		token->se_comm_watchdog_timer = NULL;
	}
}

/**
 * Perform user authentication, potentially including the pairing secret
 *
 * @param token usb token with the SE to which the user should be authenticated
 * @return 0 on success or else -1
 */
static int
authenticateUser(usbtoken_t *token)
{
	int rc;

retry:
	rc = token->cs->verifyPIN(token->ctn, token->auth_code, token->auth_code_len);
	if (rc == ERR_TRANS) {
		token->se_comm = false;
		if (usbtoken_se_reconnect(token))
			goto retry;
	}

	if (rc < 0) {
		ERROR("Could not authenticate user to usb token, token rc: %d!", rc);
		return -1;
	}

	if (rc != USBTOKEN_SUCCESS) {
		ERROR("Could not authenticate user to usb token, token rc: 0x%04x", rc);
		return -2;
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

	if ((rc = authenticateUser(token)) < 0) {
		ERROR("Failed to authenticate to token");
		return rc;
	}

	if ((NULL == label) || (0 == label_len)) {
		ERROR("No label was provided for key derivation");
		return -1;
	} else {
		rc = token->cs->deriveKey(token->ctn, label, label_len, key, key_len);
	}

	if (rc < 0) {
		ERROR("USBTOKEN: deriveKey failed");
		return -1;
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
	 *   fields  1 2     3       4    5 6
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
		TRACE("reader string at offset '%u': '%s'", idx, readers + idx);

		/*
		 * advance po offset to beginning of field 4
		 */
		po += 15;

		size_t s_len = strlen(po);

		/*
		 * string at po now contains 4 and 5, "<iSerialNumber>)".
		 * thus, strip ")" for comparison
		 */
		if ((s_len > 0) && (strncmp(po, serial, s_len - 1) == 0)) {
			TRACE("USBTOKEN: token_filter_by_serial() found reader"
			      " with serial: %s at port 0x%04x",
			      serial, iport);
			*port = iport;
			mem_free0(s);
			return 0;
		}

		/*
		 * advance pointers to the next reader string
		 */
		po += s_len + 1;
		idx += 15 + s_len + 1;
	}

	*port = 0;
	mem_free0(s);
	return -1;
}

/**
 * initializes the ctapi interface to the token reader.
 * If the reader is unplugged during runtime this will ensure it is either
 * reaquired using the correct usb port or not at all
 * @param token the usbtoken which the ctapi interface should be initilized to
 * @param brsp the buffer to hold the response from the ICC
 * @param brsp_len length of @param brsp
 * @return 0 on success or -1 else
 */
static int
usbtoken_init_ctapi_int(usbtoken_t *token, unsigned char *brsp, size_t brsp_len)
{
	ASSERT(token);

	int rc = -1;
	unsigned short lr = MAX_CT_READERS_SIZE;
	unsigned short port = 0;
	unsigned char *readers = mem_alloc0(lr);

	rc = CT_list(readers, &lr, 0);
	if (0 != rc) {
		ERROR("CT_list failed with code: %d", rc);
		goto err;
	}

	if (lr <= 0) {
		ERROR("USB_Enumerate returned illegal lr: %d", lr);
		goto err;
	}

	rc = token_filter_by_serial(readers, lr, token->serial, &port);
	if (rc != 0) {
		ERROR("Could not find specified token reader with serial %s", token->serial);
		goto err;
	}
	mem_free0(readers);
	token->port = port;

	rc = CT_init(token->ctn, port);
	if (rc != 0) {
		ERROR("USBTOKEN: Token reader initialization failed. Ret code: %d", rc);
		goto err;
	}

	if (0 > usbtoken_reset_schsm_sess(token, brsp, brsp_len)) {
		WARN("Could not initiate schsm session, SE not yet present.");
	} else {
		token->se_comm_watchdog_timer =
			event_timer_new(USBTOKEN_SE_COMM_TIMEOUT, EVENT_TIMER_REPEAT_FOREVER,
					usbtoken_se_comm_watchdog_cb, token);
		event_add_timer(token->se_comm_watchdog_timer);
	}

	DEBUG("Successfully initialized CTAPI session for reader with serial  %s", token->serial);

	return 0;

err:
	mem_free0(readers);
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
	unsigned char *brsp = NULL;

	brsp = mem_new0(unsigned char, MAX_APDU_BUF_LEN);
	size_t brsp_len = MAX_APDU_BUF_LEN;

	token = mem_new0(usbtoken_t, 1);
	IF_NULL_RETVAL_ERROR(token, NULL);

	token->locked = true;
	token->se_comm = false;
	token->ctn = ctn_get_unused();
	token->serial = mem_strdup(serial);
	IF_NULL_GOTO_ERROR(token->serial, err);

	rc = usbtoken_init_ctapi_int(token, brsp, brsp_len);
	mem_free0(brsp);
	if (rc != 0) {
		ERROR("Failed to initialize ctapi interface to usb token reader");
		ctn_set_available(token->ctn);
		goto err;
	}

	token->locked = true;

	TRACE("Usbtoken initialized");
	return token;

err:
	mem_free0(token->serial);
	mem_free0(token);
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

retry:
	rc = token->cs->getLifeCycleState(token->ctn);
	if (rc == ERR_TRANS) {
		token->se_comm = false;
		if (usbtoken_se_reconnect(token)) {
			goto retry;
		}
	} else if (rc != LC_CONFIGURED) {
		ERROR("USBTOKEN: Token is not in tranport state. Aborting...");
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

	rc = token->cs->changePIN(token->ctn, (unsigned char *)tpin, strlen(tpin), newcode,
				  newcode_len);

	mem_memset0(newcode, sizeof(newcode));

	if (rc != USBTOKEN_SUCCESS) {
		ERROR("Provisioning of usbtoken failed. Token rc: 0x%04x", rc);
		rc = -1;
		goto out;
	}

	rc = token->cs->generateMasterKey(token->ctn);
	if (rc < 0) {
		ERROR("USBTOKEN: generateMasterKey() failed with code: %d", rc);
		rc = -1;
		goto out;
	}

	// token successfully initialized
	rc = 0;

out:
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

retry:
	rc = token->cs->changePIN(token->ctn, oldcode, oldcode_len, newcode, newcode_len);
	if (rc == ERR_TRANS) {
		token->se_comm = false;
		if (usbtoken_se_reconnect(token))
			goto retry;
	}

	mem_memset0(newcode, sizeof(newcode));
	mem_memset0(oldcode, sizeof(oldcode));

	if (rc != USBTOKEN_SUCCESS) {
		ERROR("Changing user pin of usbtoken failed. Token rc: 0x%04x", rc);
		rc = -1;
	} else
		rc = 0;

out:
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

	if (!token->se_comm && (!usbtoken_se_reconnect(token))) {
		ERROR("SE not present!");
		token->se_comm = false;
		return -1;
	}

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
	IF_NULL_RETURN(token->auth_code);

	mem_memset0(token->auth_code, token->auth_code_len);
	mem_free0(token->auth_code);
}

void
usbtoken_free(usbtoken_t *token)
{
	TRACE("USBTOKEN: usbtoken_free");

	ASSERT(token);

	event_remove_timer(token->se_comm_watchdog_timer);
	event_timer_free(token->se_comm_watchdog_timer);

	if (0 != CT_close(token->ctn)) {
		ERROR("Closing CT interface (ctn=%d) to token failed.", token->ctn);
	} else {
		DEBUG("Closing CT interface (ctn=%d) done.", token->ctn);
		ctn_set_available(token->ctn);
	}

	mem_free0(token->latr);

	mem_free0(token->serial);
	usbtoken_free_secrets(token);

	mem_free0(token);
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

	if (!token->se_comm && (!usbtoken_se_reconnect(token))) {
		ERROR("SE not present!");
		token->se_comm = false;
		return -1;
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

	if (!token->se_comm && (!usbtoken_se_reconnect(token))) {
		ERROR("SE not present!");
		token->se_comm = false;
		return -1;
	}

	rc = produceKey(token, label, label_len, key, sizeof(key));
	if (rc < 0) {
		ERROR("Failed to get derived key from usbtoken");
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

	if (!token->se_comm && (!usbtoken_se_reconnect(token))) {
		ERROR("SE not present!");
		token->se_comm = false;
		return -1;
	}

	int auth_code_len = 0;
	unsigned char code[TOKEN_MAX_AUTH_CODE_LEN];

	auth_code_len = get_auth_code(passwd, pairing_secret, pairing_sec_len, code, sizeof(code));
	if (auth_code_len < 0) {
		ERROR("Could not derive authentication code");
		return -1;
	}

	token->auth_code_len = auth_code_len;
	token->auth_code = mem_memcpy(code, token->auth_code_len);

	int rc = authenticateUser(token);
	if (rc == -2) { // wrong password
		token->wrong_unlock_attempts++;
		ERROR("Usbtoken unlock failed (wrong PW)");
	} else if (rc == 0) {
		token->locked = false;
		token->wrong_unlock_attempts = 0;
		DEBUG("Usbtoken unlock successful");
	} else {
		ERROR("Usbtoken unlock failed");
		token->wrong_unlock_attempts = 0;
	}

	if (rc != 0)
		usbtoken_free_secrets(token); // just to be sure

	mem_memset0(code, sizeof(code));

	return rc;
}

/* See sc-hsm-embedded/src/pkcs11/token-sc-hsm.c:sc_hsm_logout() as reference */
int
usbtoken_reset_auth(usbtoken_t *token, unsigned char *brsp, size_t brsp_len)
{
	ASSERT(token);
	int rc = -1;
	int lr = -1;

	DEBUG("usbtoken_reset_auth");

	if (usbtoken_is_locked_till_reboot(token)) {
		WARN("Token is locked till reboot, returning");
		return -1;
	}

	if ((!token->auth_code) || (token->auth_code_len <= 0)) {
		ERROR("Authentication code not available to reset usbtoken");
		return -1;
	}

	lr = usbtoken_reset_schsm_sess(token, brsp, brsp_len);
	if (lr < 0) {
		ERROR("usbtoken_reset_schsm rc code: 0x%04x", lr);
		return lr;
	}

	rc = authenticateUser(token);
	if (rc == -2) { // wrong password
		ERROR("Usbtoken authentication reset failed (wrong PW). This should not happen");
	} else if (rc == 0) {
		DEBUG("Usbtoken authentication reset successful");
	} else {
		ERROR("Usbtoken reset failed");
	}

	return lr;
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
usbtoken_send_apdu(usbtoken_t *token, unsigned char *apdu, size_t apdu_len, unsigned char *brsp,
		   size_t brsp_len)
{
	ASSERT(token);
	ASSERT(apdu);
	ASSERT(brsp);

	TRACE("usbtoken_send_apdu");

	unsigned short lr;
	unsigned char dad, sad;

	dad = 0; /* destination: Card */
	sad = 2; /* source: Host */
	lr = brsp_len;

#ifdef DEBUG_BUILD
	str_t *dump = str_hexdump_new(apdu, apdu_len);
	TRACE("Sending APDU to USB token: len: %zu, apdu: %s", apdu_len, str_buffer(dump));
	str_free(dump, true);
#endif

	if (!token->se_comm && (!usbtoken_se_reconnect(token))) {
		ERROR("SE not present!");
		token->se_comm = false;
		return -1;
	}

	int rc;
retry:
	rc = CT_data(token->ctn, &dad, &sad, apdu_len, apdu, &lr, brsp);
	if (rc == ERR_TRANS) {
		token->se_comm = false;
		if (usbtoken_se_reconnect(token))
			goto retry;
	}

	if (rc != 0) {
		ERROR("CT_data failed with code: %d", rc);
		return -1;
	}

#ifdef DEBUG_BUILD
	dump = str_hexdump_new(brsp, lr);
	TRACE("Received APDU from USB token: len: %d, apdu: %s", lr, str_buffer(dump));
	str_free(dump, true);
#endif

	return lr;
}

int
usbtoken_get_atr(usbtoken_t *token, unsigned char *buf, size_t buflen)
{
	ASSERT(token);
	ASSERT(buf);

	if (buflen < token->latr_len) {
		ERROR("Given buffer to small to hold last ATR");
		return -1;
	}

	memcpy(buf, token->latr, token->latr_len);

	return token->latr_len;
}

#ifdef DEBUG_BUILD
static void INIT
usbtoken_init(void)
{
	DEBUG("Creating libctccid log directory at /var/tmp/sc-hsm-embedded");
	dir_mkdir_p("/var/tmp/sc-hsm-embedded", 0755);
}
#endif
