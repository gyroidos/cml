#include "ek.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "common/mem.h"
#include "common/macro.h"

#define EK_CERT_RSA_INDEX 0x01c00002
#define EK_CERT_EC_INDEX 0x01c0000a

uint8_t *
ek_get_certificate_new(TPMI_ALG_PUBLIC alg, size_t *cert_len)
{
	IF_NULL_RETVAL(cert_len, NULL);

	TPMI_RH_NV_INDEX cert_index;
	switch (alg) {
	case TPM_ALG_RSA:
		cert_index = EK_CERT_RSA_INDEX;
		break;
	case TPM_ALG_ECC:
		cert_index = EK_CERT_EC_INDEX;
		break;
	default:
		ERROR("Algorithm not supported by implementation!");
		return NULL;
	}

	if ((*cert_len = tpm2_nv_get_data_size(cert_index)) == 0) {
		ERROR("Index not defined, no EK certificate on TPM");
		return NULL;
	}

	uint8_t *cert_raw = mem_new0(uint8_t, *cert_len);
	if (tpm2_nv_read(TPM_RH_NULL, cert_index, NULL, cert_raw, cert_len)) {
		ERROR("Reading Index of EK cert failed!");
		mem_free0(cert_raw);
		return NULL;
	}
	const unsigned char *p = cert_raw;
	X509 *certificate = d2i_X509(NULL, &p, *cert_len);
	X509_print_fp(stdout, certificate);

	if (certificate)
		X509_free(certificate);

	return cert_raw;
}
