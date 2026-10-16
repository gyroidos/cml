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

#ifndef TPM2D_IBMTSS_H
#define TPM2D_IBMTSS_H

#include <ibmtss/tss.h>

typedef TPM_RC TPM2D_RC;

#define TPM2D_RC_SUCCESS TPM_RC_SUCCESS
#define TPM2D_RC_AUTH_FAIL TPM_RC_AUTH_FAIL
#define TPM2D_RC_POLICY_FAIL TPM_RC_POLICY_FAIL
#define TPM2D_RC_NV_LOCKED TPM_RC_NV_LOCKED
#define TPM2D_RC_BAD_REFERENCE TSS_RC_NULL_PARAMETER

typedef TPM_ALG_ID TPM2D_ALG_ID;

#define TPM2D_ALG_NULL TPM_ALG_NULL
#define TPM2D_ALG_RSA TPM_ALG_RSA
#define TPM2D_ALG_AES TPM_ALG_AES
#define TPM2D_ALG_ECC TPM_ALG_ECC
#define TPM2D_ALG_SHA1 TPM_ALG_SHA1
#define TPM2D_ALG_SHA256 TPM_ALG_SHA256
#define TPM2D_ALG_SHA384 TPM_ALG_SHA384

#define TPM2D_ECC_NIST_P256 TPM_ECC_NIST_P256

typedef TPM_SE TPM2D_TPM_SE;

#define TPM2D_TPM_SE_POLICY TPM_SE_POLICY
#define TPM2D_TPM_SE_TRIAL TPM_SE_TRIAL

typedef TPM_HANDLE TPM2D_TPM_HANDLE;

typedef TPM_SU TPM2D_TPM_SU;

typedef TPMI_DH_CONTEXT TPM2D_DH_CONTEXT;
typedef TPMI_DH_OBJECT TPM2D_DH_OBJECT;
typedef TPMI_DH_PCR TPM2D_DH_PCR;
typedef TPMI_DH_PERSISTENT TPM2D_DH_PERSISTENT;
typedef TPMI_RH_NV_INDEX TPM2D_DH_NV_INDEX;

typedef TPMI_SH_AUTH_SESSION TPM2D_SH_AUTH_SESSION;
typedef TPMI_SH_POLICY TPM2D_SH_POLICY;

typedef TPMI_RH_HIERARCHY TPM2D_RH_HIERARCHY;

#define TPM2D_TPM_RH_NULL TPM_RH_NULL
#define TPM2D_TPM_RH_OWNER TPM_RH_OWNER

#define TPM2D_INVALID_HANDLE ((TPM2D_TPM_HANDLE)0) /* no raw TPM object lives at 0 */

#endif // TPM2D_IBMTSS_H
