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

#ifndef SCD_H
#define SCD_H

#include "token.h"

#ifdef ANDROID
#else
#include "scd.pb-c.h"
#endif

#define PROVISIONING_MODE_FILE "/tmp/_provisioning_"

// Do not edit! The provisioning script requires this path (also trustme-main.mk and its dummy provsg folder)
#define SCD_TOKEN_DIR "/data/cml/tokens"
#define SSIG_ROOT_CERT SCD_TOKEN_DIR "/ssig_rootca.cert"
#define LOCALCA_ROOT_CERT SCD_TOKEN_DIR "/localca_rootca.cert"
#define TRUSTED_CA_STORE SCD_TOKEN_DIR "/ca"

#define DEVICE_CERT_FILE SCD_TOKEN_DIR "/device.cert"
#define DEVICE_CSR_FILE SCD_TOKEN_DIR "/device.csr"
// Only used on platforms without TPM, otherwise TPM-bound key is used
#define DEVICE_KEY_FILE SCD_TOKEN_DIR "/device.key"

/**
 * Returns the type of the token
 */
scd_tokentype_t
scd_proto_to_tokentype(const DaemonToToken *msg);

/**
 * Creates a new scd token structure.
 */
int
scd_token_new(const DaemonToToken *msg);

/**
 * Returns an existing scd token.
 */
scd_token_t *
scd_get_token(scd_token_t type, char *tuuid)

	/**
 * Returns an existing scd token.
 * This is a convience wrapper for scd_get_token(scd_token_t type, char *tuuid).
 */
	scd_token_t *scd_get_token_from_msg(const DaemonToToken *msg);

/**
 * Frees a generic token structure.
 */
void
scd_token_free(scd_token_t *token);

/**
 * Checks provisioning mode.
 */
bool
scd_in_provisioning_mode(void);

#endif // SCD_H
