#ifndef TPM2D_SHARED_H
#define TPM2D_SHARED_H

#include "common/sock.h"

#define TPM2D_BASE_DIR "/data/cml/tpm2d"
#define TPM2D_SESSION_DIR "session"
#define TPM2D_TOKEN_DIR "tokens"

#ifndef TPM2D_NVMCRYPT_ONLY

#define TPM2D_ATT_TSS_FILE		TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_tss.pem"
#define TPM2D_ATT_PRIV_FILE		TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_priv.bin"
#define TPM2D_ATT_PUB_FILE		TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_pub.bin"
#define TPM2D_ATT_PARENT_PUB_FILE	TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR "/attestation_pt_pub.bin"
#define TPM2D_ATT_CERT_FILE		"/data/cml/tokens/device.cert"

// clang-format off
#define TPM2D_SOCKET SOCK_PATH(tpm2d-control)
// clang-format on

// WARNING overwrite this with proper auth in production builds
#define TPM2D_PRIMARY_STORAGE_KEY_PW	NULL
#define TPM2D_ATT_KEY_PW		NULL

#endif // ifndef TPM2D_NVMCRYPT_ONLY

#endif // TPM2D_SHARED_H
