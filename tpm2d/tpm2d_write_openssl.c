/*
 *
 *   Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 *   SPDX-License-Identifier: LGPL-2.1-only
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

//#define TSSINCLUDE(x) < TSS_INCLUDE/x >
//#include TSSINCLUDE(tss.h)
//#include TSSINCLUDE(tssutils.h)
//#include TSSINCLUDE(tssmarshal.h)
//#include TSSINCLUDE(Unmarshal_fp.h)
//#include TSSINCLUDE(tsscrypto.h)
//#include TSSINCLUDE(tsscryptoh.h)
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tss.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssutils.h>

#include "tpm2-asn.h"
//#include "tpm2-common.h"

#include "tpm2d_write_openssl.h"

static int
openssl_write_tpmfile(const char *file, BYTE *pubkey, int pubkey_len, BYTE *privkey, int privkey_len, int empty_auth,
		      TPM_HANDLE parent, STACK_OF(TSSOPTPOLICY) * sk, int version, TPM2B_ENCRYPTED_SECRET *secret)
{
	union {
		TSSLOADABLE tssl;
		TSSPRIVKEY tpk;
	} k;
	BIO *outb;

	/* clear structure so as not to have to set optional parameters */
	memset(&k, 0, sizeof(k));
	if ((outb = BIO_new_file(file, "w")) == NULL) {
		fprintf(stderr, "Error opening file for write: %s\n", file);
		return 1;
	}
	if (version == 0) {
		k.tssl.type = OBJ_txt2obj(OID_OldloadableKey, 1);
		k.tssl.emptyAuth = empty_auth;
		k.tssl.parent = ASN1_INTEGER_new();
		ASN1_INTEGER_set(k.tssl.parent, parent);

		k.tssl.pubkey = ASN1_OCTET_STRING_new();
		ASN1_STRING_set(k.tssl.pubkey, pubkey, pubkey_len);
		k.tssl.privkey = ASN1_OCTET_STRING_new();
		ASN1_STRING_set(k.tssl.privkey, privkey, privkey_len);
		k.tssl.policy = sk;

		PEM_write_bio_TSSLOADABLE(outb, &k.tssl);
	} else {
		if (secret) {
			k.tpk.type = OBJ_txt2obj(OID_importableKey, 1);
			k.tpk.secret = ASN1_OCTET_STRING_new();
			ASN1_STRING_set(k.tpk.secret, secret->t.secret, secret->t.size);
		} else {
			k.tpk.type = OBJ_txt2obj(OID_loadableKey, 1);
		}
		k.tpk.emptyAuth = empty_auth;
		k.tpk.parent = ASN1_INTEGER_new();
		ASN1_INTEGER_set(k.tpk.parent, parent);

		k.tpk.pubkey = ASN1_OCTET_STRING_new();
		ASN1_STRING_set(k.tpk.pubkey, pubkey, pubkey_len);
		k.tpk.privkey = ASN1_OCTET_STRING_new();
		ASN1_STRING_set(k.tpk.privkey, privkey, privkey_len);
		k.tpk.policy = sk;

		PEM_write_bio_TSSPRIVKEY(outb, &k.tpk);
	}

	BIO_free(outb);
	return 0;
}

int
tpm2d_openssl_write_tpmfile(const char *file, BYTE *pubkey, int pubkey_len, BYTE *privkey, int privkey_len,
			    int empty_auth, TPM_HANDLE parent, TPM2B_ENCRYPTED_SECRET *secret)
{
	return openssl_write_tpmfile(file, pubkey, pubkey_len, privkey, privkey_len, empty_auth, parent, NULL, 0,
				     secret);
}
