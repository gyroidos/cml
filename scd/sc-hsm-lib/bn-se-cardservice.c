/**
 * Mini card service for key generator
 *
 * Copyright (c) 2020, CardContact Systems GmbH, Minden, Germany
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of CardContact Systems GmbH nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CardContact Systems GmbH BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file sc-hsm-cardservice.c
 * @author Andreas Schwier
 * @brief Minimal BN-SE card service for the key generator
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ctapi.h>
#include "cardservice.h"

static unsigned char aid[] = { 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x01, 0x03 };

/**
 * Select the BN-SE application on the device
 *
 * @param ctn the card terminal number
 * @return < 0 in case of an error or SW1/SW2 return by the token.
 */
static int
selectSE(int ctn)
{
	unsigned char rdata[256];
	unsigned short SW1SW2;
	int rc;

	rc = processAPDU(ctn, 0, 0x00, 0xA4, 0x04, 0x04, sizeof(aid), aid, 0, rdata, sizeof(rdata),
			 &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	return SW1SW2;
}

/**
 * Query the PIN status
 *
 * @param ctn the card terminal number
 * @return < 0 in case of an error or SW1/SW2
 */
static int
queryPIN(int ctn)
{
	unsigned short SW1SW2;
	int rc;

	rc = processAPDU(ctn, 0, 0x00, 0x20, 0x00, 0x81, 0, NULL, 0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	return SW1SW2;
}

/**
 * Query the Life-Cycle status to check if the SE is operational
 *
 * @param ctn the card terminal number
 * @return < 0 in case of an error or one of LC_xx
 */
static int
getLifeCycleState(int ctn)
{
	unsigned char rdata[256];
	unsigned short SW1SW2;
	int rc;

	rc = processAPDU(ctn, 0, 0x80, 0x02, 0x00, 0x00, 0, NULL, 0, rdata, sizeof(rdata), &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	if (SW1SW2 == 0x6A81) {
		return LC_TERMINATED;
	}

	if (SW1SW2 != 0x9000) {
		return -1;
	}

	if (rdata[0] != 0x80 && rdata[1] != 0x01) {
		return -1;
	}

	return rdata[2];
}

/**
 * Verify the User PIN
 *
 * @param ctn the card terminal number
 * @param pin the PIN
 * @param pinlen the length of the PIN
 *
 * @return < 0 in case of an error or SW1/SW2
 */
static int
verifyPIN(int ctn, unsigned char *pin, int pinlen)
{
	unsigned short SW1SW2;
	int rc;

	if ((pin == NULL) || (pinlen > 16)) {
		return -1;
	}

	rc = processAPDU(ctn, 0, 0x00, 0x20, 0x00, 0x81, pinlen, pin, 0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	return SW1SW2;
}

/**
 * Change PIN
 *
 * @param ctn the card terminal number
 * @param oldpin the old PIN
 * @param oldpinlen the length of the old PIN
 * @param newpin the new PIN
 * @param newpinlen the length of the new PIN
 * @return < 0 in case of an error or SW1/SW2
 */
static int
changePIN(int ctn, unsigned char *oldpin, int oldpinlen, unsigned char *newpin, int newpinlen)
{
	unsigned short SW1SW2;
	int rc;

	if ((oldpin == NULL) || (oldpinlen > 16) || (newpin == NULL) || (newpinlen > 16)) {
		return -1;
	}

	rc = verifyPIN(ctn, oldpin, oldpinlen);

	if (rc != 0x9000) {
		return rc;
	}

	rc = processAPDU(ctn, 0, 0x00, 0x24, 0x00, 0x81, newpinlen, newpin, 0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	if (SW1SW2 != 0x9000) {
		return SW1SW2;
	}

	rc = verifyPIN(ctn, newpin, newpinlen);

	return rc;
}

/**
 * Generate AES-128 key as master secret
 *
 * @param ctn the card terminal number
 * @param id the key id on the device
 * @param algo the list of supported algorithms
 * @param algolen the length of the algorithm list
 * @return < 0 in case of an error or SW1/SW2
 */
static int
generateMasterKey(int ctn)
{
	unsigned short SW1SW2;
	int rc;

	rc = processAPDU(ctn, 0, 0x00, 0x48, 0x00, 0x00, 0, NULL, 0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	return SW1SW2;
}

/**
 * Derive a key from the master key
 *
 * @param ctn the card terminal number
 * @param label the derivation parameter (aka label)
 * @param labellen the length of the label
 * @param keybuff a 32 byte key buffer
 * @param keybuff the length of the key buffer
 * @return < 0 in case of an error or SW1/SW2
 */
static int
deriveKey(int ctn, unsigned char *label, int labellen, unsigned char *keybuff, int keybufflen)
{
	unsigned short SW1SW2;
	int rc;

	if ((label == NULL) || (labellen > 127) || (keybuff == NULL) || (keybufflen != 32)) {
		return -1;
	}

	rc = processAPDU(ctn, 0, 0x80, 0x78, 0, 0x00, labellen, label, keybufflen, keybuff,
			 keybufflen, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	return SW1SW2;
}

/**
 * Terminate SE
 *
 * @param ctn the card terminal number
 * @return < 0 in case of an error or SW1/SW2
 */
static int
terminate(int ctn)
{
	unsigned short SW1SW2;
	int rc;

	rc = processAPDU(ctn, 0, 0x80, 0xF0, 0x00, 0x7F, 0, NULL, 0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	return SW1SW2;
}

struct cardService *
getBNSECardService()
{
	static struct cardService cs = { "BN-SE",

					 selectSE,	    NULL,      queryPIN,
					 getLifeCycleState, verifyPIN, changePIN,
					 generateMasterKey, deriveKey, terminate };

	return &cs;
}
