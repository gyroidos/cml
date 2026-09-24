/*
 * This file is part of GyroidOS
 * Copyright(c) 2026 Fraunhofer AISEC
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

#ifndef TPM2D_TSS2_H
#define TPM2D_TSS2_H

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>

#define TPM2D_RC TPM2_RC
#define TPM2D_RC_SUCCESS TPM2_RC_SUCCESS
#define TPM2D_RC_AUTH_FAIL TPM2_RC_AUTH_FAIL
#define TPM2D_RC_POLICY_FAIL TPM2_RC_POLICY_FAIL
#define TPM2D_RC_NV_LOCKED TPM2_RC_NV_LOCKED
#define TPM2D_RC_BAD_REFERENCE TSS2_BASE_RC_BAD_REFERENCE

#define TPM2D_ALG_ID TPM2_ALG_ID
#define TPM2D_ALG_NULL TPM2_ALG_NULL
#define TPM2D_ALG_RSA TPM2_ALG_RSA
#define TPM2D_ALG_AES TPM2_ALG_AES
#define TPM2D_ALG_ECC TPM2_ALG_ECC
#define TPM2D_ALG_SHA1 TPM2_ALG_SHA1
#define TPM2D_ALG_SHA256 TPM2_ALG_SHA256
#define TPM2D_ALG_SHA384 TPM2_ALG_SHA384

#define TPM2D_ECC_NIST_P256 TPM2_ECC_NIST_P256

#define TPM2D_TPM_RH_NULL ESYS_TR_RH_NULL
#define TPM2D_TPM_RH_OWNER ESYS_TR_RH_OWNER

#define TPM2D_TPM_SE TPM2_SE
#define TPM2D_TPM_SE_POLICY TPM2_SE_POLICY
#define TPM2D_TPM_SE_TRIAL TPM2_SE_TRIAL

#define TPM2D_TPM_HANDLE TPM2_HANDLE

#define TPM2D_TPM_SU TPM2_SU

#endif // TPM2D_TSS2_H
