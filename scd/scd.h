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
#include "usbtoken.h"

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
 *  Generic token type
 */
typedef struct scd_token scd_token_t;

/**
 * Choice of supported token types.
 * Must be kept in sync with scd.proto
 */
typedef enum scd_tokentype { NONE, DEVICE, USB } scd_tokentype_t;

/**
 *  generic scd_token.
 */
struct scd_token {
    
    union{
        softtoken_t *softtoken;
        usbtoken_t *usbtoken;
    } int_token;
    
    scd_tokentype_t type;

    int (*lock) (scd_token_t *token);
    int (*unlock) (scd_token_t *token, char *passwd,
				unsigned char *pairing_secret, size_t pairing_sec_len);

    bool (*is_locked) (scd_token_t *token);
    bool (*is_locked_till_reboot) (scd_token_t *token);

    int (*wrap_key) (scd_token_t *token, char *label,
				  unsigned char *plain_key, size_t plain_key_len,
				  unsigned char **wrapped_key, int *wrapped_key_len);

    int (*unwrap_key) (scd_token_t *token, char *label,
                       unsigned char *wrapped_key, size_t wrapped_key_len,
		               unsigned char **plain_key, int *plain_key_len);

    int (*change_passphrase) (scd_token_t *token, const char *oldpass, const char *newpass);
};

/**
 * Returns the type of the token
 */
scd_tokentype_t
scd_proto_to_tokentype(const DaemonToToken *msg);


/**
 * Returns the directory in which the token files are stored.
 * Currently, only softtokens in the form of .p12 files are supported.
 */
const char *
scd_get_token_dir(void);

/**
 * Returns the generic token
 * TODO: needs to be refactored because it may break other code
 *      - in ealier versions this always returned a softtoken_t
 */
scd_token_t *
scd_get_token (const DaemonToToken *msg);

/**
 * Frees a generic token structure.
 */
void 
scd_token_free(scd_token_t *token);


/**
 * Returns the token to use for crypto operations.
 */
softtoken_t *
scd_get_softtoken(void);

/**
 * Checks provisioning mode
 */
bool
scd_in_provisioning_mode(void);

#endif // SCD_H
