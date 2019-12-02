#ifndef _EK_H
#define _EK_H

#include "tpm2d.h"

uint8_t *ek_get_certificate_new(TPMI_ALG_PUBLIC, size_t *cert_len);

#endif /* _EK_H */
