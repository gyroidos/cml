/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2019 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/pkcs7.h>
#include <openssl/ssl.h>

#include "common/file.h"
#include "common/ssl_util.h"
#include "common/macro.h"
#include "common/mem.h"

#include "modsig.h"

static const char *
asn1_object_to_sig_algo(const ASN1_OBJECT *obj)
{
	// TODO which algorithms shall be supported
	switch (OBJ_obj2nid(obj)) {
	case NID_ecdsa_with_SHA256:
		return "ecdsa_with_SHA256";
	case NID_rsaEncryption:
		return "rsaEncryption";
	case NID_RSA_SHA3_256:
		return "RSA_SHA3_256";
	default:
		return "";
	}
}

static char *
x509_get_common_name_new(X509_NAME *name)
{
	X509_NAME_ENTRY *x509_name_entry;
	ASN1_STRING *asn1_string;
	ASN1_OBJECT *asn1_object;
	bool found = false;

	for (int i = 0; i < X509_NAME_entry_count(name); i++) {
		x509_name_entry = X509_NAME_get_entry(name, i);
		asn1_object = X509_NAME_ENTRY_get_object(x509_name_entry);

		if (OBJ_obj2nid(asn1_object) == NID_commonName) {
			found = true;
			break;
		}
	}

	if (!found) {
		ERROR("Failed to convert X509 name to string");
		return NULL;
	}

	asn1_string = X509_NAME_ENTRY_get_data(x509_name_entry);

	int len = ASN1_STRING_length(asn1_string);
	const char *p = (const char *)ASN1_STRING_get0_data(asn1_string);

	return mem_strndup(p, len);
}

void
modsig_free(sig_info_t *s)
{
	mem_free0(s->key_id);
	mem_free0(s->sig);
	mem_free0(s->signer);
	mem_free0(s);
}

sig_info_t *
modsig_parse_new(const char *pkcs7_raw, size_t len)
{
	PKCS7 *pkcs7;
	STACK_OF(PKCS7_SIGNER_INFO) *stack_signer_info = NULL;
	PKCS7_SIGNER_INFO *signer_info = NULL;
	PKCS7_ISSUER_AND_SERIAL *issuer_and_serial = NULL;
	ASN1_OCTET_STRING *sig = NULL;
	BIGNUM *serial_bn = NULL;
	X509_ALGOR *digest_algo = NULL;
	X509_ALGOR *sig_algo = NULL;
	const ASN1_OBJECT *digest_algo_obj;
	const ASN1_OBJECT *sig_algo_obj;
	BIO *in;
	uint8_t *key_id_str;
	sig_info_t *sig_info = NULL;

	sig_info = (sig_info_t *)mem_alloc0(sizeof(sig_info_t));

	in = BIO_new_mem_buf(pkcs7_raw, len);

	pkcs7 = d2i_PKCS7_bio(in, NULL);
	if (!pkcs7) {
		BIO_free(in);
		return NULL;
	}

	BIO_free(in);

	stack_signer_info = PKCS7_get_signer_info(pkcs7);
	if (!stack_signer_info) {
		goto out;
	}

	signer_info = sk_PKCS7_SIGNER_INFO_value(stack_signer_info, 0);
	if (!signer_info) {
		modsig_free(sig_info);
		goto out;
	}

	issuer_and_serial = signer_info->issuer_and_serial;
	if (!issuer_and_serial) {
		modsig_free(sig_info);
		goto out;
	}

	sig = signer_info->enc_digest;
	if (!sig) {
		modsig_free(sig_info);
		goto out;
	}

	sig_info->sig_len = ASN1_STRING_length(sig);
	const uint8_t *p = ASN1_STRING_get0_data(sig);
	sig_info->sig = mem_memcpy(p, sig_info->sig_len);

	serial_bn = ASN1_INTEGER_to_BN(issuer_and_serial->serial, NULL);
	if (!serial_bn) {
		modsig_free(sig_info);
		goto out;
	}

	key_id_str = (uint8_t *)mem_alloc(BN_num_bytes(serial_bn));

	sig_info->key_id_len = BN_bn2bin(serial_bn, key_id_str);
	sig_info->key_id = key_id_str;

	sig_info->signer = x509_get_common_name_new(issuer_and_serial->issuer);

	PKCS7_SIGNER_INFO_get0_algs(signer_info, NULL, &digest_algo, &sig_algo);

	X509_ALGOR_get0(&digest_algo_obj, NULL, NULL, digest_algo);
	X509_ALGOR_get0(&sig_algo_obj, NULL, NULL, sig_algo);

	sig_info->hash_algo = asn1_object_to_hash_algo(digest_algo_obj);
	sig_info->sig_algo = asn1_object_to_sig_algo(sig_algo_obj);

out:
	PKCS7_free(pkcs7);
	if (serial_bn) {
		BN_free(serial_bn);
	}
	return sig_info;
}