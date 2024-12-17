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
	int ret = ssl_verify_signature("testdata/testpki/ssig_single.cert",
				       "testdata/sigssa_ssacert_sha256", "testdata/test-quote",
				       "SHA256");

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_ssa_sha512(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_signature("testdata/testpki/ssig_single.cert",
				       "testdata/sigssa_ssacert_sha512", "testdata/test-quote",
				       "SHA512");

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_pss(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_signature("testdata/testpki/ssig_cml_single.cert",
				       "testdata/sigpss_psscert_sha256", "testdata/test-quote",
				       "SHA256");

	munit_assert(0 == ret);

	return MUNIT_OK;
}

static UNUSED MunitResult
test_ssl_verify_signature_pss_sha512(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int ret = ssl_verify_signature("testdata/testpki/ssig_cml_single.cert",
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

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_single.cert",
					  "testdata/sigssa_ssacert_sha256", "testdata/test-quote",
					  &cert_buf, &cert_len, &sig_buf, &sig_len, &buf,
					  &buf_len));

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

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_single.cert",
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
test_ssl_verify_signature_from_buf_pss_psscert(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml_single.cert",
					  "testdata/sigpss_psscert_sha256", "testdata/test-quote",
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

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml_single.cert",
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

	if (ssl_create_csr("testdata/munit-device.csr", "testdata/munit-private.key", NULL,
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
test_get_uid_from_device_cert_default(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uuid_t *dev_uuid = uuid_new(NULL);
	munit_assert(NULL != dev_uuid);
	const char *uid = uuid_string(dev_uuid);
	munit_assert(NULL != uid);

	munit_assert(0 == ssl_create_csr("testdata/munit-device.csr", "testdata/munit-private.key",
					 NULL, "common_name", uid, false, RSA_SSA_PADDING));

	munit_assert(0 == ssl_self_sign_csr("testdata/munit-device.csr",
					    "testdata/munit-device.self.crt",
					    "testdata/munit-private.key", false));

	char *uuid_read = ssl_get_uid_from_cert_new("testdata/munit-device.self.crt");

	munit_assert(NULL != uuid_read);

	INFO("uid='%s', uuid_read='%s'", uid, uuid_read);
	munit_assert(0 == memcmp(uid, uuid_read, strlen(uid)));

	mem_free0(uuid_read);
	uuid_free(dev_uuid);
	unlink("testdata/munit-device.csr");
	unlink("testdata/munit-device.self.crt");
	unlink("testdata/munit-private.key");

	return MUNIT_OK;
}

static MunitResult
test_get_uid_from_device_cert_pss(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uuid_t *dev_uuid = uuid_new(NULL);
	munit_assert(NULL != dev_uuid);
	const char *uid = uuid_string(dev_uuid);
	munit_assert(NULL != uid);

	munit_assert(0 == ssl_create_csr("testdata/munit-device.csr", "testdata/munit-private.key",
					 NULL, "common_name", uid, false, RSA_PSS_PADDING));

	munit_assert(0 == ssl_self_sign_csr("testdata/munit-device.csr",
					    "testdata/munit-device.self.crt",
					    "testdata/munit-private.key", false));

	char *uuid_read = ssl_get_uid_from_cert_new("testdata/munit-device.self.crt");

	munit_assert(NULL != uuid_read);

	INFO("uid = '%s', uuid_read='%s'", uid, uuid_read);
	munit_assert(0 == memcmp(uid, uuid_read, strlen(uid)));

	mem_free0(uuid_read);
	uuid_free(dev_uuid);
	unlink("testdata/munit-device.csr");
	unlink("testdata/munit-device.self.crt");
	unlink("testdata/munit-private.key");

	return MUNIT_OK;
}

static MunitResult
test_ssl_verify_signature_from_digest_pss_psscert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml_single.cert",
					  "testdata/sigpss_psscert_sha256",
					  "testdata/test-quote-hash_sha256", &cert_buf, &cert_len,
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
test_ssl_verify_signature_from_digest_pss_psscert_sha512(UNUSED const MunitParameter params[],
							 UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_cml_single.cert",
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
test_ssl_verify_signature_from_digest_ssa_ssacert(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	off_t cert_len, sig_len, buf_len;
	char *cert_buf = NULL;
	unsigned char *sig_buf = NULL;
	unsigned char *buf = NULL;

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_single.cert",
					  "testdata/sigssa_ssacert_sha256",
					  "testdata/test-quote-hash_sha256", &cert_buf, &cert_len,
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

	munit_assert(0 == test_read_certs("testdata/testpki/ssig_single.cert",
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

// Test <trusted chain> against <trusted rootca>
static MunitResult
test_ssl_verify_cert_trusted_chain_trusted_rootca(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

// Test <untrusted chain> against <trusted rootca>
static MunitResult
test_ssl_verify_cert_untrusted_chain_trusted_rootca(UNUSED const MunitParameter params[],
						    UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki_untrusted/ssig_cml.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test <valid signingcert> without <valid subca>
static MunitResult
test_ssl_verify_cert_ssig_single_trusted_rootca(UNUSED const MunitParameter params[],
						UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_cml_single.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test <trusted subca> against <trusted rootca>
static MunitResult
test_ssl_verify_cert_trusted_subca_trusted_rootca(UNUSED const MunitParameter params[],
						  UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/testpki/ssig_subca.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == 0);

	return MUNIT_OK;
}

// Test <untrusted chain>+<untrusted rootca> against <valid rootca>
static MunitResult
test_ssl_verify_cert_untrusted_complete_chain_trusted_rootca(UNUSED const MunitParameter params[],
							     UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/untrusted_chain_including_rootca.cert",
					 "testdata/testpki/ssig_rootca.cert", false);

	// Check if verification was successful
	munit_assert(ret == -1);

	return MUNIT_OK;
}

// Test <untrusted chain>+<untrusted rootca> with parameter root CA == NULL
static MunitResult
test_ssl_verify_cert_untrusted_complete_chain_null(UNUSED const MunitParameter params[],
						   UNUSED void *data)
{
	int ret = ssl_verify_certificate("testdata/untrusted_chain_including_rootca.cert", NULL,
					 false);

	// Check if verification was successful
	munit_assert(ret == -2);

	return MUNIT_OK;
}

// Test <trusted chain>+<trusted rootca> with test cert == NULL
static MunitResult
test_ssl_verify_cert_null_untrusted_complete_chain(UNUSED const MunitParameter params[],
						   UNUSED void *data)
{
	int ret = ssl_verify_certificate(NULL, "testdata/untrusted_chain_including_rootca.cert",
					 false);

	// Check if verification was successful
	munit_assert(ret == -2);

	return MUNIT_OK;
}

static MunitResult
test_ssl_aes_ecb_pad_success(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uint8_t key[16] = { 0 };
	uint8_t src[] = { 0xde, 0xad, 0xca, 0xfe };
	int src_len = (int)sizeof(src);
	uint8_t ciphertext[100];
	int ciphertext_len = (int)sizeof(ciphertext);
	uint8_t dst[100];
	int dst_len = (int)sizeof(dst);
	int ret;

	TRACE("Encrypting buffer with size %d ", src_len);
	ret = ssl_aes_ecb_encrypt(src, src_len, ciphertext, &ciphertext_len, key, sizeof(key), 1);
	munit_assert(0 == ret);

	TRACE("Decrypting buffer with size %d ", ciphertext_len);
	ret = ssl_aes_ecb_decrypt(ciphertext, ciphertext_len, dst, &dst_len, key, sizeof(key), 1);
	munit_assert(0 == ret);

	TRACE_HEXDUMP(src, sizeof(src), "SRC");
	TRACE_HEXDUMP(ciphertext, ciphertext_len, "ENC");
	TRACE_HEXDUMP(dst, dst_len, "DEC");

	munit_assert_int(src_len, ==, dst_len);
	munit_assert_memory_equal(src_len, src, dst);
	munit_assert_memory_not_equal(src_len, src, ciphertext);
	munit_assert_memory_not_equal(dst_len, dst, ciphertext);

	return MUNIT_OK;
}

static MunitResult
test_ssl_aes_ecb_pad_fail(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uint8_t key[16] = { 0 };
	uint8_t src[] = { 0xde, 0xad, 0xca, 0xfe };
	int src_len = (int)sizeof(src);
	uint8_t ciphertext[100];
	int ciphertext_len = (int)sizeof(ciphertext);
	uint8_t dst[100];
	int dst_len = (int)sizeof(dst);
	int ret;

	TRACE("Encrypting buffer with size %d ", src_len);
	ret = ssl_aes_ecb_encrypt(src, src_len, ciphertext, &ciphertext_len, key, sizeof(key), 1);
	munit_assert(0 == ret);

	// Use different key
	key[0] = 0x1;

	TRACE("Decrypting buffer with size %d ", ciphertext_len);
	ret = ssl_aes_ecb_decrypt(ciphertext, ciphertext_len, dst, &dst_len, key, sizeof(key), 1);
	munit_assert(0 != ret);

	TRACE_HEXDUMP(src, sizeof(src), "SRC");
	TRACE_HEXDUMP(ciphertext, ciphertext_len, "ENC");
	TRACE_HEXDUMP(dst, dst_len, "DEC");

	munit_assert_int(src_len, !=, dst_len);
	munit_assert_memory_not_equal(src_len, src, dst);

	return MUNIT_OK;
}

static MunitResult
test_ssl_aes_ecb_nopad_success(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uint8_t key[16] = { 0 };
	uint8_t src[] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
			  0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
	int src_len = (int)sizeof(src);
	uint8_t ciphertext[100];
	int ciphertext_len = (int)sizeof(ciphertext);
	uint8_t dst[100];
	int dst_len = (int)sizeof(dst);
	int ret;

	TRACE("Encrypting buffer with size %d ", src_len);
	ret = ssl_aes_ecb_encrypt(src, src_len, ciphertext, &ciphertext_len, key, sizeof(key), 0);
	munit_assert(0 == ret);

	TRACE("Decrypting buffer with size %d ", ciphertext_len);
	ret = ssl_aes_ecb_decrypt(ciphertext, ciphertext_len, dst, &dst_len, key, sizeof(key), 0);
	munit_assert(0 == ret);

	INFO_HEXDUMP(src, sizeof(src), "SRC");
	INFO_HEXDUMP(ciphertext, ciphertext_len, "ENC");
	INFO_HEXDUMP(dst, dst_len, "DEC");

	munit_assert_int(src_len, ==, dst_len);
	munit_assert_memory_equal(src_len, src, dst);
	munit_assert_memory_not_equal(src_len, src, ciphertext);
	munit_assert_memory_not_equal(dst_len, dst, ciphertext);

	return MUNIT_OK;
}

static MunitResult
test_ssl_aes_ecb_nopad_fail(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uint8_t key[16] = { 0 };
	uint8_t src[] = {
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe
	};
	int src_len = (int)sizeof(src);
	uint8_t ciphertext[100];
	int ciphertext_len = (int)sizeof(ciphertext);
	uint8_t dst[100];
	int dst_len = (int)sizeof(dst);
	int ret;

	TRACE("Encrypting buffer with size %d ", src_len);
	ret = ssl_aes_ecb_encrypt(src, src_len, ciphertext, &ciphertext_len, key, sizeof(key), 0);
	munit_assert(0 != ret);

	TRACE("Decrypting buffer with size %d ", ciphertext_len);
	ssl_aes_ecb_decrypt(ciphertext, ciphertext_len, dst, &dst_len, key, sizeof(key), 0);

	INFO_HEXDUMP(src, src_len, "SRC");
	INFO_HEXDUMP(ciphertext, ciphertext_len, "ENC");
	INFO_HEXDUMP(dst, dst_len, "DEC");

	munit_assert_int(src_len, !=, dst_len);
	munit_assert_memory_not_equal(src_len, src, dst);

	return MUNIT_OK;
}

static MunitResult
test_ssl_aes_ctr_success(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uint8_t key[16] = { 0 };
	uint8_t src[] = { 0xde, 0xad };
	int src_len = (int)sizeof(src);
	uint8_t ciphertext[100];
	int ciphertext_len = (int)sizeof(ciphertext);
	uint8_t dst[100];
	int dst_len = (int)sizeof(dst);
	int ret = -1;
	ssl_aes_ctx_t *e_ctx, *d_ctx;
	uint8_t iv[16] = { 0x1, 0x2, 0x3, 0x4, 0x0, 0x0, 0x0, 0x0,
			   0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	e_ctx = ssl_aes_ctr_init_encrypt(key, sizeof(key), iv, sizeof(iv));
	munit_assert_not_null(e_ctx);

	d_ctx = ssl_aes_ctr_init_decrypt(key, sizeof(key), iv, sizeof(iv));
	munit_assert_not_null(d_ctx);

	for (int i = 0; i < 24; i++) {
		// FUT: Encrypt
		ret = ssl_aes_ctr_encrypt(e_ctx, src, src_len, ciphertext, &ciphertext_len);
		munit_assert(ret == 0);

		// Update the IV to the expected value after a full block has been encrypted
		// This means (i % 8), as we always encrypt 2 bytes
		if ((i % 8) == 0) {
			iv[15] += 1;
			TRACE_HEXDUMP(iv, sizeof(iv), "IV");
		}

		// Get the actual IV
		uint8_t eiv[16] = { 0 };
		EVP_CIPHER_CTX_get_updated_iv(e_ctx, eiv, sizeof(eiv));

		// Compare
		munit_assert_memory_equal(sizeof(iv), iv, eiv);

		// FUT: Decrypt
		ret = ssl_aes_ctr_decrypt(d_ctx, ciphertext, ciphertext_len, dst, &dst_len);
		munit_assert(ret == 0);

		// Get the actual IV
		uint8_t div[16] = { 0 };
		EVP_CIPHER_CTX_get_updated_iv(d_ctx, div, sizeof(div));

		// Compare
		munit_assert_memory_equal(sizeof(iv), iv, div);

		munit_assert_int(src_len, ==, dst_len);
		munit_assert_memory_equal(src_len, src, dst);
		munit_assert_memory_not_equal(src_len, src, ciphertext);
		munit_assert_memory_not_equal(dst_len, dst, ciphertext);
	}

	ssl_aes_ctr_free(e_ctx);
	ssl_aes_ctr_free(d_ctx);

	return MUNIT_OK;
}

static MunitResult
test_ssl_aes_ctr_fail_iv(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uint8_t key[16] = { 0 };
	uint8_t src[] = { 0xde, 0xad };
	int src_len = sizeof(src);
	uint8_t ciphertext[100];
	int ciphertext_len = (int)sizeof(ciphertext);
	uint8_t dst[100];
	int dst_len = (int)sizeof(dst);
	int ret = -1;
	ssl_aes_ctx_t *e_ctx, *d_ctx;
	uint8_t iv[16] = { 0x1, 0x2, 0x3, 0x4, 0x0, 0x0, 0x0, 0x0,
			   0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	e_ctx = ssl_aes_ctr_init_encrypt(key, sizeof(key), iv, sizeof(iv));
	munit_assert_not_null(e_ctx);

	// Manipulate IV
	iv[15] = 0xa;

	d_ctx = ssl_aes_ctr_init_decrypt(key, sizeof(key), iv, sizeof(iv));
	munit_assert_not_null(d_ctx);

	// FUT: Encrypt
	ret = ssl_aes_ctr_encrypt(e_ctx, src, src_len, ciphertext, &ciphertext_len);
	munit_assert(ret == 0);

	// FUT: Decrypt
	ret = ssl_aes_ctr_decrypt(d_ctx, ciphertext, ciphertext_len, dst, &dst_len);
	munit_assert(ret == 0);

	munit_assert_memory_not_equal(src_len, src, dst);

	ssl_aes_ctr_free(e_ctx);
	ssl_aes_ctr_free(d_ctx);

	return MUNIT_OK;
}

static MunitResult
test_ssl_aes_ctr_fail_key(UNUSED const MunitParameter params[], UNUSED void *data)
{
	uint8_t key[16] = { 0 };
	uint8_t src[] = { 0xde, 0xad };
	int src_len = (int)sizeof(src);
	uint8_t ciphertext[100];
	int ciphertext_len = (int)sizeof(ciphertext);
	uint8_t dst[100];
	int dst_len = (int)sizeof(dst);
	int ret = -1;
	ssl_aes_ctx_t *e_ctx, *d_ctx;
	uint8_t iv[16] = { 0x1, 0x2, 0x3, 0x4, 0x0, 0x0, 0x0, 0x0,
			   0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	e_ctx = ssl_aes_ctr_init_encrypt(key, sizeof(key), iv, sizeof(iv));
	munit_assert_not_null(e_ctx);

	// Manipulate key
	key[0] = 0x1;

	d_ctx = ssl_aes_ctr_init_decrypt(key, sizeof(key), iv, sizeof(iv));
	munit_assert_not_null(d_ctx);

	// FUT: Encrypt
	ret = ssl_aes_ctr_encrypt(e_ctx, src, src_len, ciphertext, &ciphertext_len);
	munit_assert(ret == 0);

	// FUT: Decrypt
	ret = ssl_aes_ctr_decrypt(d_ctx, ciphertext, ciphertext_len, dst, &dst_len);
	munit_assert(ret == 0);

	munit_assert_memory_not_equal(src_len, src, dst);

	ssl_aes_ctr_free(e_ctx);
	ssl_aes_ctr_free(d_ctx);

	return MUNIT_OK;
}

static MunitTest tests[] = {
	{ "test_ssl_verify_signature_from_buf_ssa_ssacert",
	  test_ssl_verify_signature_from_buf_ssa_ssacert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_from_buf_ssa_ssacert_sha512",
	  test_ssl_verify_signature_from_buf_ssa_ssacert_sha512, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_signature_from_buf_pss_psscert",
	  test_ssl_verify_signature_from_buf_pss_psscert, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_signature_from_buf_pss_psscert_sha512",
	  test_ssl_verify_signature_from_buf_pss_psscert_sha512, setup, tear_down,
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
	{ "get_uid_from_device_cert_default", test_get_uid_from_device_cert_default, setup,
	  tear_down, MUNIT_TEST_OPTION_NONE, NULL },
	{ "get_uid_from_device_cert_pss", test_get_uid_from_device_cert_pss, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_read_pkcs12_token_ssa", test_ssl_read_pkcs12_token_ssa, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_read_pkcs12_token_pss", test_ssl_read_pkcs12_token_pss, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_create_pkcs12_token_ssa", test_ssl_create_pkcs12_token_ssa, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_cert_trusted_chain_trusted_rootca",
	  test_ssl_verify_cert_trusted_chain_trusted_rootca, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_cert_untrusted_chain_trusted_rootca",
	  test_ssl_verify_cert_untrusted_chain_trusted_rootca, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_cert_ssig_single_trusted_rootca",
	  test_ssl_verify_cert_ssig_single_trusted_rootca, setup, tear_down, MUNIT_TEST_OPTION_NONE,
	  NULL },
	{ "test_ssl_verify_cert_trusted_subca_trusted_rootca",
	  test_ssl_verify_cert_trusted_subca_trusted_rootca, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_cert_untrusted_complete_chain_trusted_rootca",
	  test_ssl_verify_cert_untrusted_complete_chain_trusted_rootca, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_cert_untrusted_complete_chain_null",
	  test_ssl_verify_cert_untrusted_complete_chain_null, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_verify_cert_null_untrusted_complete_chain",
	  test_ssl_verify_cert_null_untrusted_complete_chain, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_aes_ecb_pad_success", test_ssl_aes_ecb_pad_success, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_aes_ecb_pad_fail", test_ssl_aes_ecb_pad_fail, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_aes_ecb_nopad_success", test_ssl_aes_ecb_nopad_success, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_aes_ecb_nopad_fail", test_ssl_aes_ecb_nopad_fail, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_aes_ctr_success", test_ssl_aes_ctr_success, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_aes_ctr_fail_iv", test_ssl_aes_ctr_fail_iv, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	{ "test_ssl_aes_ctr_fail_key", test_ssl_aes_ctr_fail_key, setup, tear_down,
	  MUNIT_TEST_OPTION_NONE, NULL },
	//Mark the end of the array with an entry where the test function is NULL
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

MunitSuite ssl_util_suite = {
	"test_ssl_utils: ",	/* name */
	tests,			/* tests */
	NULL,			/* suites */
	1,			/* iterations */
	MUNIT_SUITE_OPTION_NONE /* options */
};
