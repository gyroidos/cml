#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "munit.h"

#include "macro.h"
#include "file.h"
#include "uuid.h"
#include "ssl_util.h"
#include "mem.h"

static const char *
rfs(const char *name)
{
	FILE *f = fopen(name, "rb");
	if (!f) {
		ERROR("Failed to read file");
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *s = malloc(fsize + 1);
	int ret = fread(s, 1, fsize, f);
	if (ret != fsize) {
		ERROR("Failed to read file");
		return NULL;
	}
	fclose(f);

	s[fsize] = 0;

	return s;
}

static uint8_t *
rfb(const char *name, long *size)
{
	FILE *f = fopen(name, "rb");
	if (!f) {
		ERROR("Failed to read file %s", name);
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	uint8_t *b = malloc(fsize);
	if (!b) {
		ERROR("Failed to allocate memory");
		return NULL;
	}
	int ret = fread(b, 1, fsize, f);
	fclose(f);

	*size = ret;
	return b;
}

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

/*
 * These tests ensure, the signature verification results of ssl_verify_signature_from_buf are as expected w.r.t different padding schemes
 *
 *           pss-sig  	ssa-sig
 * 
 * pss-cert     OK		   FAIL
 * 
 * ssa-cert     FAIL	   OK
*/
static UNUSED MunitResult
test_ssl_verify_signature_ssa(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_signature("testdata/testpki_ssa/ssig.cert", "testdata/sigssa_ssacert",
				       "testdata/test-quote", "SHA256");

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_pss(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_signature("testdata/testpki_pss/ssig.cert", "testdata/sigpss_psscert",
				       "testdata/test-quote", "SHA256");

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_create_pkcs11_token_ssa(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_create_pkcs12_token("tmptoken_ssa.p12", NULL, "trustme", "testuser",
					  RSA_SSA_PADDING);

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_create_pkcs11_token_pss(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_create_pkcs12_token("tmptoken_pss.p12", NULL, "trustme", "testuser",
					  RSA_PSS_PADDING);

	munit_assert(0 == ret);

	unlink("tmptoken_pss.p12");

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_read_pkcs11_token_ssa(UNUSED const MunitParameter params[], UNUSED void *data)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
	int ret = ssl_read_pkcs12_token("testdata/testpki_ssa/token.p12", "trustme", &pkey, &cert,
					&ca);

	// Check if verification was successful
	munit_assert(0 == ret);
	munit_assert(NULL != pkey);
	munit_assert(NULL != cert);
	munit_assert(NULL != ca);

	// TODO free

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_read_pkcs11_token_pss(UNUSED const MunitParameter params[], UNUSED void *data)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca = NULL;
	int ret = ssl_read_pkcs12_token("testdata/testpki_pss/token.p12", "trustme", &pkey, &cert,
					&ca);

	// Check if verification was successful
	munit_assert(0 == ret);
	munit_assert(NULL != pkey);
	munit_assert(NULL != cert);
	munit_assert(NULL != ca);

	// TODO free

	return MUNIT_OK;
}

static int
test_read_certs(const char *cert, const char *sig, const char *data, char **cert_buf,
		off_t *cert_len, unsigned char **sig_buf, off_t *sig_len, unsigned char **data_buf,
		off_t *data_len)
{
	munit_assert(NULL != cert);
	munit_assert(NULL != sig);
	munit_assert(NULL != data);

	munit_assert(0 < (*cert_len = file_size(cert)));
	*cert_buf = mem_alloc0(*cert_len);

	if (0 > file_read(cert, *cert_buf, *cert_len)) {
		ERROR("Failed to read cert file: %s", cert);
		return -1;
	}

	munit_assert(0 < (*sig_len = file_size(sig)));
	*sig_buf = mem_alloc0(*sig_len);

	if (0 > file_read(sig, (char *)*sig_buf, *sig_len)) {
		ERROR("Failed to read signature file %s", sig);
		return -1;
	}

	*data_len = file_size(data);
	*data_buf = mem_alloc0(*data_len);

	if (0 > file_read(data, (char *)*data_buf, *data_len)) {
		ERROR("Failed to read data file %s", data);
		return -1;
	}

	return 0;
}

/*
 * These tests ensure, the signature verification results of ssl_verify_signature_from_buf are as expected w.r.t different padding schemes
 *
 *           pss-sig  	ssa-sig
 * 
 * pss-cert     OK		   FAIL
 * 
 * ssa-cert     FAI		   OK
*/
static UNUSED MunitResult
test_ssl_verify_signature_from_buf_ssa_ssacert(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf;
	unsigned char *sig_buf, *buf;

	munit_assert(0 == test_read_certs("testdata/testpki_ssa/ssig.cert",
					  "testdata/sigssa_ssacert", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len);

	munit_assert(ret == 0);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_ssa_psscert(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf;
	unsigned char *sig_buf, *buf;

	munit_assert(0 == test_read_certs("testdata/testpki_pss/ssig.cert",
					  "testdata/sigssa_psscert", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len);

	munit_assert(ret < 0);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_pss_psscert(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf;
	unsigned char *sig_buf, *buf;

	munit_assert(0 == test_read_certs("testdata/testpki_pss/ssig.cert",
					  "testdata/sigpss_psscert", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len);

	munit_assert(ret == 0);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_from_buf_pss_ssacert(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf;
	unsigned char *sig_buf, *buf;

	munit_assert(0 == test_read_certs("testdata/testpki_ssa/ssig.cert",
					  "testdata/sigpss_ssacert", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

	int ret = ssl_verify_signature_from_buf((unsigned char *)cert_buf, cert_len, sig_buf,
						sig_len, (unsigned char *)buf, buf_len);

	munit_assert(ret < 0);

	return MUNIT_OK;
}

static MunitResult
test_ssl_create_csr_openssl_default(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uuid_t *dev_uuid = uuid_new(NULL);
	const char *uid;
	if (!dev_uuid || (uid = uuid_string(dev_uuid)) == NULL) {
		FATAL("Could not create device uuid");
	}

	if (ssl_create_csr("testdata/munic-device.csr", "testdata/munit-private.key", NULL,
			   "common_name", uid, false, RSA_SSA_PADDING) != 0) {
		FATAL("Unable to create CSR");
	}
	INFO("Created CSR");
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
	return 0;
}

/*
 * These tests ensure, the signature verification results are as expected w.r.t different padding schemes
 *
 *           pss-sig  	ssa-sig
 * 
 * pss-cert     OK		   FAIL
 * 
 * ssa-cert     OK		   OK
*/

static MunitResult
test_ssl_verify_signature_from_digest_pss_psscert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	long size_hash;
	long size_sig_pss;

	const char *cert_pss = rfs("testdata/testpki_pss/ssig.cert");

	uint8_t *sigbuf_pss = rfb("testdata/sigpss_psscert", &size_sig_pss);
	uint8_t *hash = rfb("testdata/test-quote-hash", &size_hash);

	int ret = ssl_verify_signature_from_digest(cert_pss, (const uint8_t *)sigbuf_pss,
						   size_sig_pss, (const uint8_t *)hash,
						   SHA256_DIGEST_LENGTH);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_pss_ssacert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	long size_hash;
	long size_sig_pss;

	const char *cert_pss = rfs("testdata/testpki_ssa/ssig.cert");

	uint8_t *sigbuf_pss = rfb("testdata/sigpss_ssacert", &size_sig_pss);
	uint8_t *hash = rfb("testdata/test-quote-hash", &size_hash);

	int ret = ssl_verify_signature_from_digest(cert_pss, (const uint8_t *)sigbuf_pss,
						   size_sig_pss, (const uint8_t *)hash,
						   SHA256_DIGEST_LENGTH);

	// Check if verification was successful
	munit_assert(ret < 0);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_ssa_psscert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	long size_hash;
	long size_sig_pss;

	const char *cert_pss = rfs("testdata/testpki_pss/ssig.cert");

	uint8_t *sigbuf_pss = rfb("testdata/sigssa_psscert", &size_sig_pss);
	uint8_t *hash = rfb("testdata/test-quote-hash", &size_hash);

	int ret = ssl_verify_signature_from_digest(cert_pss, (const uint8_t *)sigbuf_pss,
						   size_sig_pss, (const uint8_t *)hash,
						   SHA256_DIGEST_LENGTH);

	// Check if verification was successful
	munit_assert(ret < 0);

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_ssa_ssacert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	long size_hash;
	long size_sig_pss;

	const char *cert_pss = rfs("testdata/testpki_ssa/ssig.cert");

	uint8_t *sigbuf_pss = rfb("testdata/sigssa_ssacert", &size_sig_pss);
	uint8_t *hash = rfb("testdata/test-quote-hash", &size_hash);

	int ret = ssl_verify_signature_from_digest(cert_pss, (const uint8_t *)sigbuf_pss,
						   size_sig_pss, (const uint8_t *)hash,
						   SHA256_DIGEST_LENGTH);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

static MunitTest tests[] = {
	{ "test_ssl_verify_signature_from_buf_ssa_ssacert",
	  test_ssl_verify_signature_from_buf_ssa_ssacert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_from_buf_ssa_psscert",
	  test_ssl_verify_signature_from_buf_ssa_psscert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_from_buf_pss_psscert",
	  test_ssl_verify_signature_from_buf_pss_psscert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_from_buf_pss_ssacert",
	  test_ssl_verify_signature_from_buf_pss_ssacert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_ssa", test_ssl_verify_signature_ssa, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_signature_pss", test_ssl_verify_signature_pss, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigpss_psscert",
	  test_ssl_verify_signature_from_digest_pss_psscert, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigpss_ssacert",
	  test_ssl_verify_signature_from_digest_pss_ssacert, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_verify_signature_from_digest sigssa_psscert",
	  test_ssl_verify_signature_from_digest_ssa_psscert, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },

	{ "ssl_verify_signature_from_digest sigssa_ssacert",
	  test_ssl_verify_signature_from_digest_ssa_ssacert, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_create_csr_default", test_ssl_create_csr_openssl_default, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "ssl_create_csr_pss", test_ssl_create_csr_pss, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_read_pkcs11_token_ssa", test_ssl_read_pkcs11_token_ssa, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_read_pkcs11_token_pss", test_ssl_read_pkcs11_token_pss, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_create_pkcs11_token_ssa", test_ssl_create_pkcs11_token_ssa, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_create_pkcs11_token_pss", test_ssl_create_pkcs11_token_pss, setup, tear_down,
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
