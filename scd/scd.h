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

#include "softtoken.h"

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
 * Returns the directory in which the token files are stored.
 * Currently, only softtokens in the form of .p12 files are supported.
 */
const char *scd_get_token_dir(void);

/**
 * Returns the token to use for crypto operations.
 */
softtoken_t *scd_get_token(void);

/**
 * Checks provisioning mode
 */
bool scd_in_provisioning_mode(void);

#endif // SCD_H
