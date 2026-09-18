#ifndef _EK_H
#define _EK_H

#include "tss_backends.h"
#if TSS_BACKEND == TSS_BACKEND_IBMTSS
#include "tpm2d_ibmtss.h"
#elif TSS_BACKEND == TSS_BACKEND_TPM2_TSS
#include "tpm2d_tss2.h"
#endif

uint8_t *
ek_get_certificate_new(TPMI_ALG_PUBLIC, size_t *cert_len);

#endif /* _EK_H */
