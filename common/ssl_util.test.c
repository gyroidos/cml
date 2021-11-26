#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "munit.h"

#include "macro.h"
#include "file.h"
#include "uuid.h"
#include "ssl_util.h"
#include "mem.h"

static void *
setup(UNUSED const MunitParameter params[], UNUSED void *data)
{
	// Before every test, register a logger so that the logging functionality can run.
	logf_handler_t *logf = logf_register(&logf_test_write, stdout);
	logf_handler_set_prio(logf, LOGF_PRIO_TRACE);

	ssl_init(false, NULL);

	return NULL;
}

static void
tear_down(UNUSED void *fixture)
{
	ssl_free();
}

static int
test_read_certs(const char *cert, const char *sig, const char *data, char **cert_buf,
		off_t *cert_len, unsigned char **sig_buf, off_t *sig_len, unsigned char **data_buf,
		off_t *data_len)
{
	munit_assert(NULL != cert);
	munit_assert(NULL != sig);
	munit_assert(NULL != data);

	munit_assert(NULL != cert_buf);
	munit_assert(NULL != cert_len);
	munit_assert(NULL != sig_buf);
	munit_assert(NULL != sig_len);
	munit_assert(NULL != data_buf);
	munit_assert(NULL != data_len);

	DEBUG("Reading file %s", cert);
	munit_assert(0 < (*cert_len = file_size(cert)));
	*cert_buf = mem_alloc0(*cert_len);

	if (0 > file_read(cert, *cert_buf, *cert_len)) {
		ERROR("Failed to read cert file: %s", cert);
		return -1;
	}

	DEBUG("Reading file %s", sig);
	munit_assert(0 < (*sig_len = file_size(sig)));
	*sig_buf = mem_alloc0(*sig_len);

	if (0 > file_read(sig, (char *)*sig_buf, *sig_len)) {
		ERROR("Failed to read signature file %s", sig);
		return -1;
	}

	DEBUG("Reading file %s", data);
	munit_assert(0 <= (*data_len = file_size(data)));
	*data_buf = mem_alloc0(*data_len);

	if (0 > file_read(data, (char *)*data_buf, *data_len)) {
		ERROR("Failed to read data file %s", data);
		return -1;
	}

	return 0;
}

static UNUSED MunitResult
test_ssl_create_pkcs12_token_ssa(UNUSED const MunitParameter params[], UNUSED void *data)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;

	unlink("tmptoken_ssa.p12");

	int ret = ssl_create_pkcs12_token("tmptoken_ssa.p12", NULL, "trustme", "testuser",
					  RSA_SSA_PADDING);

	munit_assert(0 == ret);

	// read pkcs12 token
	ret = ssl_read_pkcs12_token("tmptoken_ssa.p12", "trustme", &pkey, &cert, &ca);
	munit_assert(0 == ret);

	// read test key
	int plain_key_len;
	unsigned char *plain_key = NULL;
	DEBUG("Reading unwrapped key from testdata/testpki/ssig.key");

	munit_assert(0 <= (plain_key_len = file_size("testdata/testpki/ssig.key")));
	plain_key = mem_alloc0(plain_key_len);

	ret = file_read("testdata/testpki/ssig.key", (char *)plain_key, plain_key_len);

	munit_assert(0 < ret);
	munit_assert(NULL != plain_key);

	// wrap key
	DEBUG("Wrapping key");
	int wrapped_key_len;
	unsigned char *wrapped_key = NULL;

	ret = ssl_wrap_key(pkey, plain_key, plain_key_len, &wrapped_key, &wrapped_key_len);

	munit_assert(0 == ret);
	munit_assert(NULL != wrapped_key);

	// unwrap key
	DEBUG("Unwrapping key");
	int unwrapped_key_len;
	unsigned char *unwrapped_key = NULL;

	ret = ssl_unwrap_key(pkey, wrapped_key, wrapped_key_len, &unwrapped_key,
			     &unwrapped_key_len);

	munit_assert(0 == ret);
	munit_assert(NULL != unwrapped_key);

	// sanity checks
	munit_assert(plain_key_len == unwrapped_key_len);
	munit_assert(0 == memcmp(plain_key, unwrapped_key, plain_key_len));

	unlink("tmptoken_ssa.p12");

	EVP_PKEY_free(pkey);
	X509_free(cert);
	sk_X509_pop_free(ca, X509_free);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_create_pkcs12_token_pss(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_create_pkcs12_token("tmptoken_pss.p12", NULL, "trustme", "testuser",
					  RSA_PSS_PADDING);

	munit_assert(0 == ret);

	unlink("tmptoken_pss.p12");

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_read_pkcs12_token_ssa(UNUSED const MunitParameter params[], UNUSED void *data)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
	int ret = ssl_read_pkcs12_token("testdata/token.p12", "trustme", &pkey, &cert, &ca);

	// Check if verification was successful
	munit_assert(0 == ret);
	munit_assert(NULL != pkey);
	munit_assert(NULL != cert);
	munit_assert(NULL != ca);

	X509_free(cert);
	sk_X509_pop_free(ca, X509_free);
	EVP_PKEY_free(pkey);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_read_pkcs12_token_pss(UNUSED const MunitParameter params[], UNUSED void *data)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
	int ret = ssl_read_pkcs12_token("testdata/token_pss.p12", "trustme", &pkey, &cert, &ca);

	// Check if verification was successful
	munit_assert(0 == ret);
	munit_assert(NULL != pkey);
	munit_assert(NULL != cert);
	munit_assert(NULL != ca);

	X509_free(cert);
	sk_X509_pop_free(ca, X509_free);
	EVP_PKEY_free(pkey);

	return MUNIT_OK;
}

/*
 * These tests ensure, the signature verification results of ssl_verify_signature are as expected w.r.t different padding schemes
 *
 *			 pss-sig	ssa-sig
 *
 * pss-cert	 OK			FAIL
 *
 * ssa-cert	 FAIL		OK
*/
static UNUSED MunitResult
test_ssl_verify_signature_ssa(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_signature("testdata/testpki/ssig.cert", "testdata/sigssa_ssacert",
				       "testdata/test-quote", "SHA256");

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_ssa_sha512(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret =
		ssl_verify_signature("testdata/testpki/ssig.cert", "testdata/sigssa_ssacert_sha512",
				     "testdata/test-quote", "SHA512");

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_pss(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_signature("testdata/testpki/ssig_cml.cert", "testdata/sigpss_psscert",
				       "testdata/test-quote", "SHA256");

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_pss_sha512(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_signature("testdata/testpki/ssig_cml.cert",
				       "testdata/sigpss_psscert_sha512", "testdata/test-quote",
				       "SHA512");

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_ssa_ssacert(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig.cert", "testdata/sigssa_ssacert",
					  "testdata/test-quote", &cert_buf, &cert_len, &sig_buf,
					  &sig_len, &buf, &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len, "SHA256");

	munit_assert(ret == 0);

	if (NULL != cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_ssa_ssacert_sha512(UNUSED const MunitParameter params[],
						      UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig.cert",
					  "testdata/sigssa_ssacert_sha512", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len, "SHA512");

	munit_assert(ret == 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_ssa_psscert(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml.cert",
					  "testdata/sigssa_psscert", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len, "SHA256");

	munit_assert(ret < 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_ssa_psscert_sha512(UNUSED const MunitParameter params[],
						      UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml.cert",
					  "testdata/sigssa_psscert_sha512", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len, "SHA512");

	munit_assert(ret < 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_pss_psscert(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml.cert",
					  "testdata/sigpss_psscert", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len, "SHA256");

	munit_assert(ret == 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_pss_psscert_sha512(UNUSED const MunitParameter params[],
						      UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml.cert",
					  "testdata/sigpss_psscert_sha512", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len, "SHA512");

	munit_assert(ret == 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_pss_ssacert(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig.cert", "testdata/sigpss_ssacert",
					  "testdata/test-quote", &cert_buf, &cert_len, &sig_buf,
					  &sig_len, &buf, &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len, "SHA256");

	munit_assert(ret < 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_pss_ssacert_sha512(UNUSED const MunitParameter params[],
						      UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig.cert",
					  "testdata/sigpss_ssacert_sha512", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len, "SHA512");

	munit_assert(ret < 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static MunitResult
test_ssl_create_csr_openssl_default(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uuid_t *dev_uuid = uuid_new(NULL);
	munit_assert(NULL != dev_uuid);
	const char *uid = uuid_string(dev_uuid);
	munit_assert(NULL != uid);

	munit_assert(0 == ssl_create_csr("testdata/munit-device.csr", "testdata/munit-private.key",
					 NULL, "common_name", uid, false, RSA_SSA_PADDING));

	uuid_free(dev_uuid);
	unlink("testdata/munit-device.csr");
	unlink("testdata/munit-private.key");

	return 0;
}

static MunitResult
test_ssl_create_csr_pss(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uuid_t *dev_uuid = uuid_new(NULL);
	const char *uid;
	if (!dev_uuid || (uid = uuid_string(dev_uuid)) == NULL) {
		FATAL("Could not create device uuid");
	}

	if (ssl_create_csr("testdata/munic-device.csr", "testdata/munit-private.key", NULL,
			   "common_name", uid, false, RSA_PSS_PADDING) != 0) {
		FATAL("Unable to create CSR");
	}
	INFO("Created CSR");

	uuid_free(dev_uuid);
	unlink("testdata/munit-device.csr");
	unlink("testdata/munit-private.key");

	return 0;
}

static MunitResult
test_ssl_verify_signature_from_digest_pss_psscert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml.cert",
					  "testdata/sigpss_psscert", "testdata/test-quote-hash",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_digest(cert_buf, cert_len, (const uint8_t *)sig_buf,
						   sig_len, (const uint8_t *)buf,
						   SHA256_DIGEST_LENGTH, "SHA256");

	// Check if verification was successful
	munit_assert(ret == 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_pss_psscert_sha512(UNUSED const MunitParameter params[],
							 UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml.cert",
					  "testdata/sigpss_psscert_sha512",
					  "testdata/test-quote-hash_sha512", &cert_buf, &cert_len,
					  &sig_buf, &sig_len, &buf, &buf_len));

	int ret = ssl_verify_signature_from_digest(cert_buf, cert_len, (const uint8_t *)sig_buf,
						   sig_len, (const uint8_t *)buf,
						   SHA512_DIGEST_LENGTH, "SHA512");

	// Check if verification was successful
	munit_assert(ret == 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_pss_ssacert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig.cert", "testdata/sigpss_ssacert",
					  "testdata/test-quote-hash", &cert_buf, &cert_len,
					  &sig_buf, &sig_len, &buf, &buf_len));

	int ret = ssl_verify_signature_from_digest(cert_buf, cert_len, (const uint8_t *)sig_buf,
						   sig_len, (const uint8_t *)buf,
						   SHA256_DIGEST_LENGTH, "SHA256");

	// Check if verification was successful
	munit_assert(ret < 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_pss_ssacert_sha512(UNUSED const MunitParameter params[],
							 UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig.cert",
					  "testdata/sigpss_ssacert_sha512",
					  "testdata/test-quote-hash_sha512", &cert_buf, &cert_len,
					  &sig_buf, &sig_len, &buf, &buf_len));

	int ret = ssl_verify_signature_from_digest(cert_buf, cert_len, (const uint8_t *)sig_buf,
						   sig_len, (const uint8_t *)buf,
						   SHA512_DIGEST_LENGTH, "SHA512");

	// Check if verification was successful
	munit_assert(ret < 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_ssa_psscert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml.cert",
					  "testdata/sigssa_psscert", "testdata/test-quote-hash",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_digest(cert_buf, cert_len, (const uint8_t *)sig_buf,
						   sig_len, (const uint8_t *)buf,
						   SHA256_DIGEST_LENGTH, "SHA256");

	// Check if verification was successful
	munit_assert(ret < 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_ssa_psscert_sha512(UNUSED const MunitParameter params[],
							 UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml.cert",
					  "testdata/sigssa_psscert_sha512",
					  "testdata/test-quote-hash_sha512", &cert_buf, &cert_len,
					  &sig_buf, &sig_len, &buf, &buf_len));

	int ret = ssl_verify_signature_from_digest(cert_buf, cert_len, (const uint8_t *)sig_buf,
						   sig_len, (const uint8_t *)buf,
						   SHA256_DIGEST_LENGTH, "SHA512");

	// Check if verification was successful
	munit_assert(ret < 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_ssa_ssacert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig.cert", "testdata/sigssa_ssacert",
					  "testdata/test-quote-hash", &cert_buf, &cert_len,
					  &sig_buf, &sig_len, &buf, &buf_len));

	int ret = ssl_verify_signature_from_digest(cert_buf, cert_len, (const uint8_t *)sig_buf,
						   sig_len, (const uint8_t *)buf,
						   SHA256_DIGEST_LENGTH, "SHA256");

	// Check if verification was successful
	munit_assert(ret == 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_ssa_ssacert_sha512(UNUSED const MunitParameter params[],
							 UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig.cert",
					  "testdata/sigssa_ssacert_sha512",
					  "testdata/test-quote-hash_sha512", &cert_buf, &cert_len,
					  &sig_buf, &sig_len, &buf, &buf_len));

	int ret = ssl_verify_signature_from_digest(cert_buf, cert_len, (const uint8_t *)sig_buf,
						   sig_len, (const uint8_t *)buf,
						   SHA512_DIGEST_LENGTH, "SHA512");

	// Check if verification was successful
	munit_assert(ret == 0);

	if (cert_buf)
		mem_free(cert_buf);
	if (sig_buf)
		mem_free(sig_buf);
	if (buf)
		mem_free(buf);

	return MUNIT_OK;
}

// Test with valid SubCA
static MunitResult
test_ssl_verify_certificate_trusted_subca(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

// Test with untrusted SubCA
static MunitResult
test_ssl_verify_certificate_untrusted_subca(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki_untrusted/ssig_cml.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test with correct RootCA inside testcert
static MunitResult
test_ssl_verify_certificate_combined_correct_root(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml_with_correct_rootca.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

// Test with untrusted RootCA inside testcert
static MunitResult
test_ssl_verify_certificate_combined_untrusted_root(UNUSED const MunitParameter params[],
						    UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml_with_untrusted_rootca.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test with untrusted SubCA appended to ssig_cml.cert
static MunitResult
test_ssl_verify_certificate_ssig_cml_untrusted_subca_appended(UNUSED const MunitParameter params[],
							      UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml_with_untrusted_subca.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

// Test with valid SubCA appended to untrusted software signing certificate
static MunitResult
test_ssl_verify_certificate_valid_subca_with_untrusted_signing_cert(
	UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_certificate(
		"testdata/testpki/valid_subca_with_untrusted_signing_cert.cert",
		"testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test with SubCA removed from ssig_cml.cert
static MunitResult
test_ssl_verify_certificate_ssig_cml_cert_without_subca(UNUSED const MunitParameter params[],
							UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml_without_subca.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test with duplicate certificate chains
static MunitResult
test_ssl_verify_certificate_ssig_cml_duplicate_chain(UNUSED const MunitParameter params[],
						     UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml_duplicate_chains.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

// Test ssig cml cert signed directly with trusted RootCA
static MunitResult
test_ssl_verify_certificate_ssig_cml_rootsigned(UNUSED const MunitParameter params[],
						UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml_rootsigned.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

// Test ssig cml cert signed directly with untrusted RootCA
static MunitResult
test_ssl_verify_certificate_ssig_cml_rootsigned_untrusted(UNUSED const MunitParameter params[],
							  UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki_untrusted/ssig_cml_rootsigned.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test trusted ssig cml cert with appended self-signed cert
static MunitResult
test_ssl_verify_certificate_trusted_ssig_cml_with_selfsigned(UNUSED const MunitParameter params[],
							     UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml_with_selfsigned.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

// Test untrusted ssig cml cert with appended self-signed cert
static MunitResult
test_ssl_verify_certificate_untrusted_ssig_cml_with_selfsigned(UNUSED const MunitParameter params[],
							       UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki_untrusted/ssig_cml_with_selfsigned.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test complete untrusted chain against trusted root CA
static MunitResult
test_ssl_verify_certificate_untrusted_complete_chain(UNUSED const MunitParameter params[],
						     UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki_untrusted/ssig_cml_complete_chain.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test complete untrusted chain against trusted root CA
static MunitResult
test_ssl_verify_certificate_untrusted_complete_chain_null(UNUSED const MunitParameter params[],
							  UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki_untrusted/ssig_cml_complete_chain.cert",
					 NULL, false);

	// Check if verification was successful
	munit_assert(ret == -2);

	return MUNIT_OK;
}

static MunitTest tests[] = {
	{ "test_ssl_verify_signature_from_buf_ssa_ssacert",
	  test_ssl_verify_signature_from_buf_ssa_ssacert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_from_buf_ssa_ssacert_sha512",
	  test_ssl_verify_signature_from_buf_ssa_ssacert_sha512, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_signature_from_buf_ssa_psscert",
	  test_ssl_verify_signature_from_buf_ssa_psscert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_from_buf_ssa_psscert_sha512",
	  test_ssl_verify_signature_from_buf_ssa_psscert_sha512, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_signature_from_buf_pss_psscert",
	  test_ssl_verify_signature_from_buf_pss_psscert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_from_buf_pss_psscert_sha512",
	  test_ssl_verify_signature_from_buf_pss_psscert_sha512, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_signature_from_buf_pss_ssacert",
	  test_ssl_verify_signature_from_buf_pss_ssacert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_from_buf_pss_ssacert_sha512",
	  test_ssl_verify_signature_from_buf_pss_ssacert_sha512, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_signature_ssa", test_ssl_verify_signature_ssa, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_signature_ssa_sha512", test_ssl_verify_signature_ssa_sha512, setup,
	  tear_down, MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_signature_pss", test_ssl_verify_signature_pss, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_signature_pss_sha512", test_ssl_verify_signature_pss_sha512, setup,
	  tear_down, MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigpss_psscert",
	  test_ssl_verify_signature_from_digest_pss_psscert, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigpss_psscert_sha512",
	  test_ssl_verify_signature_from_digest_pss_psscert_sha512, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigpss_ssacert",
	  test_ssl_verify_signature_from_digest_pss_ssacert, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigpss_ssacert_sha512",
	  test_ssl_verify_signature_from_digest_pss_ssacert_sha512, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigssa_psscert",
	  test_ssl_verify_signature_from_digest_ssa_psscert, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigssa_psscert_sha512",
	  test_ssl_verify_signature_from_digest_ssa_psscert_sha512, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigssa_ssacert",
	  test_ssl_verify_signature_from_digest_ssa_ssacert, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigssa_ssacert_sha512",
	  test_ssl_verify_signature_from_digest_ssa_ssacert_sha512, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_create_csr_default", test_ssl_create_csr_openssl_default, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_create_csr_pss", test_ssl_create_csr_pss, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_read_pkcs12_token_ssa", test_ssl_read_pkcs12_token_ssa, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_read_pkcs12_token_pss", test_ssl_read_pkcs12_token_pss, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_create_pkcs12_token_ssa", test_ssl_create_pkcs12_token_ssa, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_trusted_subca", test_ssl_verify_certificate_trusted_subca,
	  setup, tear_down, MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_untrusted_subca",
	  test_ssl_verify_certificate_untrusted_subca, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_certificate_combined_correct_root",
	  test_ssl_verify_certificate_combined_correct_root, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_combined_untrusted_root",
	  test_ssl_verify_certificate_combined_untrusted_root, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_ssig_cml_untrusted_subca_appended",
	  test_ssl_verify_certificate_ssig_cml_untrusted_subca_appended, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_valid_subca_with_untrusted_signing_cert",
	  test_ssl_verify_certificate_valid_subca_with_untrusted_signing_cert, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_ssig_cml_cert_without_subca",
	  test_ssl_verify_certificate_ssig_cml_cert_without_subca, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_ssig_cml_duplicate_chain",
	  test_ssl_verify_certificate_ssig_cml_duplicate_chain, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_ssig_cml_rootsigned",
	  test_ssl_verify_certificate_ssig_cml_rootsigned, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_certificate_ssig_cml_rootsigned_untrusted",
	  test_ssl_verify_certificate_ssig_cml_rootsigned_untrusted, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_trusted_ssig_cml_with_selfsigned",
	  test_ssl_verify_certificate_trusted_ssig_cml_with_selfsigned, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_untrusted_ssig_cml_with_selfsigned",
	  test_ssl_verify_certificate_untrusted_ssig_cml_with_selfsigned, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_untrusted_complete_chain",
	  test_ssl_verify_certificate_untrusted_complete_chain, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_certificate_untrusted_complete_chain_null",
	  test_ssl_verify_certificate_untrusted_complete_chain_null, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },

	// Mark the end of the array with an entry where the test function is NULL
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

MunitSuite ssl_util_suite = {
	"test_ssl_utils: ",	/* name */
	tests,			/* tests */
	NULL,			/* suites */
	1,			/* iterations */
	MUNIT_SUITE_OPTION_NONE /* options */
};
