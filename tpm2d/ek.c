#include "ek.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "common/mem.h"
#include "common/macro.h"

static TPM2D_DH_NV_INDEX ek_cert_rsa_nv = TPM2D_INVALID_HANDLE;
static TPM2D_DH_NV_INDEX ek_cert_ec_nv = TPM2D_INVALID_HANDLE;

void
ek_set_cert_rsa_nv_handle(TPM2D_DH_NV_INDEX handle)
{
	ek_cert_rsa_nv = handle;
}

void
ek_set_cert_ec_nv_handle(TPM2D_DH_NV_INDEX handle)
{
	ek_cert_ec_nv = handle;
}

uint8_t *
ek_get_certificate_new(TPMI_ALG_PUBLIC alg, size_t *cert_len)
{
	IF_NULL_RETVAL(cert_len, NULL);

	TPM2D_DH_NV_INDEX cert_index;
	switch (alg) {
	case TPM2D_ALG_RSA:
		cert_index = ek_cert_rsa_nv;
		break;
	case TPM2D_ALG_ECC:
		cert_index = ek_cert_ec_nv;
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
	if (tpm2_nv_read(TPM2D_TPM_RH_NULL, cert_index, NULL, cert_raw, cert_len)) {
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
