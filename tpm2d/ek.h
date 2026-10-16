#ifndef _EK_H
#define _EK_H

#include "tpm2d.h"

void
ek_set_cert_rsa_nv_handle(TPM2D_DH_NV_INDEX handle);

void
ek_set_cert_ec_nv_handle(TPM2D_DH_NV_INDEX handle);

uint8_t *
ek_get_certificate_new(TPMI_ALG_PUBLIC, size_t *cert_len);

#endif /* _EK_H */
