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
 * @brief Minimal card service for key generator
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ctapi.h>
#include "cardservice.h"

static unsigned char requesticc[] = { 0x20, 0x12, 0x00, 0x01, 0x00 };

#ifdef DEBUG_BUILD
/**
 * Dump the memory pointed to by <mem>
 *
 * @param mem the memory area to dump
 * @param len the length of the memory area
 */
void
dump(unsigned char *mem, int len)
{
	while (len--) {
		printf("%02x ", *mem);
		mem++;
	}

	printf("\n");
}
#endif

/*
 * Request card
 *
 * @param ctn the card terminal number
 * @param atr the buffer to receive the Answer-To-Reset of the SE
 * @param atrlen the length of the ATR buffer
 * @return < 0 in case of an error or the length of the ATR
 */
int
requestICC(int ctn, unsigned char *atr, int atrbufflen)
{
	unsigned char Brsp[260];
	unsigned short lr;
	unsigned char dad, sad;
	int rc;

	dad = 1; /* Reader */
	sad = 2; /* Host */
	lr = sizeof(Brsp);

	rc = CT_data((unsigned short)ctn, &dad, &sad, sizeof(requesticc),
		     (unsigned char *)&requesticc, &lr, Brsp);

	if (rc != 0) {
		return -1;
	}

	if ((Brsp[0] == 0x64) || (Brsp[0] == 0x62)) {
		return -1;
	}

	lr -= 2;
	if (lr > atrbufflen) {
		return -1;
	}

	memcpy(atr, Brsp, lr);

#ifdef DEBUG_BUILD
	printf("ATR: ");
	dump(Brsp, lr);
#endif

	return lr;
}

/**
 * Process an ISO 7816 APDU with the underlying CT-API terminal hardware.
 *
 * @param ctn the card terminal number
 * @param todad the destination address in the CT-API protocol
 * @param CLA  Class byte of instruction
 * @param INS Instruction byte
 * @param P1 Parameter P1
 * @param P2 Parameter P2
 * @param OutLen Length of outgoing data (Lc)
 * @param OutData Outgoing data or NULL if none
 * @param InLen Length of incoming data (Le)
 * @param InData Input buffer for incoming data
 * @param InSize buffer size
 * @param SW1SW2 Address of short integer to receive SW1SW2
 * @return the number of bytes received, excluding SW1SW2 or < 0 in case of an error
 */
int
processAPDU(int ctn, int todad, unsigned char CLA, unsigned char INS, unsigned char P1,
	    unsigned char P2, int OutLen, unsigned char *OutData, int InLen, unsigned char *InData,
	    int InSize, unsigned short *SW1SW2)
{
	int rv, rc;
	unsigned short lenr;
	unsigned char dad, sad;
	unsigned char scr[MAX_APDULEN], *po;

	/* Reset status word */
	*SW1SW2 = 0x0000;

	scr[0] = CLA;
	scr[1] = INS;
	scr[2] = P1;
	scr[3] = P2;
	po = scr + 4;
	rv = 0;

	if (OutData && OutLen) {
		if ((OutLen <= 255) && (InLen <= 255)) {
			*po++ = (unsigned char)OutLen;
		} else {
			*po++ = 0;
			*po++ = (unsigned char)(OutLen >> 8);
			*po++ = (unsigned char)(OutLen & 0xFF);
		}

		memcpy(po, OutData, OutLen);
		po += OutLen;
	}

	if (InData && InSize) {
		if ((InLen <= 255) && (OutLen <= 255)) {
			*po++ = (unsigned char)InLen;
		} else {
			if (InLen >= 65556) {
				InLen = 0;
			}

			if (!OutData) {
				*po++ = 0;
			}

			*po++ = (unsigned char)(InLen >> 8);
			*po++ = (unsigned char)(InLen & 0xFF);
		}
	}

#ifdef DEBUG_BUILD
	printf("C: ");
	dump(scr, po - scr);
#endif

	sad = HOST;
	dad = todad;
	lenr = sizeof(scr);

	rc = CT_data(ctn, &dad, &sad, po - scr, scr, &lenr, scr);

	if (rc < 0) {
		memset(scr, 0, sizeof(scr));
		return rc;
	}

#ifdef DEBUG_BUILD
	printf("R: ");
	dump(scr, lenr);
#endif

	rv = lenr - 2;

	if (rv > InSize) {
		rv = InSize;
	}

	if (InData) {
		memcpy(InData, scr, rv);
	}

	*SW1SW2 = (scr[lenr - 2] << 8) + scr[lenr - 1];

	memset(scr, 0, sizeof(scr));
	return (rv);
}

/**
 * Detect SE and obtain a suitable card service
 *
 * @param ctn the card terminal number
 * @param atr the Answer-To-Reset of the SE
 * @param atrlen the length of the ATR
 * @return the card service
 */
struct cardService *
getCardService(int ctn)
{
	struct cardService *cs;

	cs = getBNSECardService();
	if (cs && (cs->selectSE)(ctn) == 0x9000) {
		return cs;
	}

	cs = getSmartCardHSMCardService();
	if (cs && (cs->selectSE)(ctn) == 0x9000) {
		return cs;
	}

	return NULL;
}
