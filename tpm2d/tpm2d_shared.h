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

#ifndef TPM2D_SHARED_H
#define TPM2D_SHARED_H

#include "common/sock.h"

#ifndef DEFAULT_BASE_PATH
#define DEFAULT_BASE_PATH "/data/cml"
#endif
#ifndef LOGFILE_DIR
#define LOGFILE_DIR "/data/logs"
#endif

#define TPM2D_BASE_DIR DEFAULT_BASE_PATH "/tpm2d"
#define TPM2D_SESSION_DIR "session"
#define TPM2D_TOKEN_DIR "tokens"

#ifndef TPM2D_NVMCRYPT_ONLY

#define TPM2D_ATT_TSS_FILE TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_tss.pem"
#define TPM2D_ATT_PRIV_FILE TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_priv.bin"
#define TPM2D_ATT_PUB_FILE TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_pub.bin"
#define TPM2D_ATT_PARENT_PUB_FILE TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_pt_pub.bin"
#define TPM2D_ATT_CERT_FILE "/" TPM2D_TOKEN_DIR "/device.cert"

// clang-format off
#define TPM2D_SOCKET SOCK_PATH(tpm2d-control)
// clang-format on

// WARNING overwrite this with proper auth in production builds
#define TPM2D_PRIMARY_STORAGE_KEY_PW NULL
#define TPM2D_ATT_KEY_PW NULL

#endif // ifndef TPM2D_NVMCRYPT_ONLY

#endif // TPM2D_SHARED_H
