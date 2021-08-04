/*
 * Copyright (c) International Business Machines  Corp., 2008
 * Copyright (C) 2013 Politecnico di Torino, Italy
 *                    TORSEC group -- http://security.polito.it
 *
 * Copyright(c) 2021 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 * Roberto Sassu <roberto.sassu@polito.it>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_measure.c
 *
 * Calculate the SHA1 aggregate-pcr value based on the IMA runtime
 * binary measurements.
 *
 * The file was modified to support the ima-modsig template and
 * stripped of components not required for this project.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/pkcs7.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "common/file.h"
#include "common/ssl_util.h"
#include "common/logf.h"
#include "common/mem.h"
#include "common/macro.h"

#include "hash.h"
#include "modsig.h"
#include "ima_verify.h"

#define TCG_EVENT_NAME_LEN_MAX 255
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/*
 * IMA template descriptor definition
 */
typedef struct {
	char *name;
	char *fmt;
	int num_fields;
	struct ima_template_field **fields;
} ima_template_desc_t;

/*
 * signature format v2 - for using with asymmetric keys - taken from kernel sources
 */
#pragma pack(push, 1)
struct signature_v2_hdr {
	uint8_t type;	   /* xattr type */
	uint8_t version;   /* signature format version */
	uint8_t hash_algo; /* Digest algorithm [enum hash_algo] */
	uint32_t keyid;	   /* IMA key identifier - not X509/PGP specific */
	uint16_t sig_size; /* signature size */
	uint8_t sig[];	   /* signature payload */
} __packed;
#pragma pack(pop)

/*
 * IMA binary_runtime_measurements event entry
 */
struct event {
	struct {
		int32_t pcr;
		uint8_t digest[SHA_DIGEST_LENGTH];
		uint32_t name_len;
	} header;
	char name[TCG_EVENT_NAME_LEN_MAX + 1];
	ima_template_desc_t *ima_template_desc;
	uint32_t template_data_len;
	uint8_t *template_data;
};

// Known IMA template descriptors
static ima_template_desc_t ima_template_desc[] = { { .name = "ima", .fmt = "d|n" },
						   { .name = "ima-ng", .fmt = "d-ng|n-ng" },
						   { .name = "ima-sig", .fmt = "d-ng|n-ng|sig" },
						   { .name = "ima-modsig",
						     .fmt = "d-ng|n-ng|sig|d-modsig|modsig" } };

static int
print_module_name(uint8_t *buffer, size_t len)
{
	// Ensure terminating null
	char *str = mem_alloc0(len + 1);
	IF_NULL_RETVAL_ERROR(str, -1);
	memcpy(str, buffer, len);
	INFO("Parsing Module %s", str);
	free(str);
	return 0;
}

static void
print_data(uint8_t *buf, size_t len, const char *info)
{
	uint32_t l = 2 * len + strlen(info) + 3;
	char s[l];
	uint32_t count = 0;
	if (info) {
		count += snprintf(s + count, sizeof(s) - count, "%s: ", info);
	}
	for (uint32_t i = 0; i < len; i++) {
		count += snprintf(s + count, sizeof(s) - count, "%02x", buf[i]);
	}
	TRACE("%s", s);
}

static int
buf_read(void *dest, uint8_t **ptr, size_t size, size_t *remain)
{
	if (size > *remain) {
		return -1;
	}

	memcpy(dest, *ptr, size);
	*ptr += size;
	*remain -= size;
	return 0;
}

static int
verify_template_data(struct event *template, const char *cert)
{
	int offset = 0;
	size_t i;
	int is_ima_template;
	char *template_fmt, *template_fmt_ptr, *f;
	uint32_t digest_len = 0;
	uint8_t *digest = NULL;
	int ret = 0;

	is_ima_template = strcmp(template->name, "ima") == 0 ? 1 : 0;
	template->ima_template_desc = NULL;

	for (i = 0; i < ARRAY_SIZE(ima_template_desc); i++) {
		if (strcmp(template->name, ima_template_desc[i].name) == 0) {
			template->ima_template_desc = ima_template_desc + i;
			break;
		}
	}

	if (template->ima_template_desc == NULL) {
		i = ARRAY_SIZE(ima_template_desc) - 1;
		template->ima_template_desc = ima_template_desc + i;
		template->ima_template_desc->fmt = template->name;
	}

	template_fmt = strdup(template->ima_template_desc->fmt);
	IF_NULL_RETVAL_ERROR(template_fmt, -1);

	template_fmt_ptr = template_fmt;
	for (i = 0; (f = strsep(&template_fmt_ptr, "|")) != NULL; i++) {
		uint32_t field_len = 0;

		TRACE("field is: %s", f);

		if (is_ima_template && strcmp(f, "d") == 0)
			field_len = SHA_DIGEST_LENGTH;
		else if (is_ima_template && strcmp(f, "n") == 0)
			field_len = strlen((const char *)template->template_data + offset);
		else {
			memcpy(&field_len, template->template_data + offset, sizeof(uint32_t));
			offset += sizeof(uint32_t);
		}

		if (strncmp(template->name, "ima-sig", 7) == 0) {
			if (strncmp(f, "d-ng", 4) == 0) {
				int algo_len = strlen((char *)template->template_data + offset) + 1;

				digest = template->template_data + offset + algo_len;
				digest_len = field_len - algo_len;

			} else if (strncmp(f, "sig", 3) == 0) {
				if (template->template_data_len <= (uint32_t)offset) {
					WARN("%s: No signature present", f);
					continue;
				}

				uint8_t *field_buf = template->template_data + offset;

				if (*field_buf != 0x03) {
					WARN("%s: No signature present", f);
					continue;
				}

				struct signature_v2_hdr *sig =
					(struct signature_v2_hdr *)(template->template_data +
								    offset);

				print_data(digest, digest_len, "Digest");
				print_data(sig->sig, field_len - sizeof(struct signature_v2_hdr),
					   "Signature");

				int retssl = ssl_verify_signature_from_digest(
					(const char *)cert,
					strlen(cert) +
						1, //keep the NULL terminator to preserve previous behaviour
					sig->sig, field_len - sizeof(struct signature_v2_hdr),
					digest, digest_len, "SHA256");
				if (retssl != 0) {
					ERROR("Signature verification FAILED for %s", f);
					ret = -1;
					goto out;
				} else {
					INFO("Signature verification SUCCESSFUL for %s", f);
				}

			} else if (strncmp(f, "n-ng", 4) == 0) {
				print_module_name(template->template_data + offset, field_len);
			}

		} else if (strncmp(template->name, "ima-modsig", 10) == 0) {
			if (strncmp(f, "d-ng", 4) == 0) {
				TRACE("Field %s not evaluated at the moment", f);

			} else if (strncmp(f, "d-modsig", 8) == 0) {
				int algo_len = strlen((char *)template->template_data + offset) + 1;
				digest = template->template_data + offset + algo_len;
				digest_len = field_len - algo_len;

			} else if (strcmp(f, "modsig") == 0) {
				sig_info_t *sig_info = NULL;
				sig_info = modsig_parse_new(
					(const char *)(template->template_data + offset),
					field_len);
				if (!sig_info) {
					ERROR("Failed to parse module signature");
					ret = -1;
					goto out;
				}

				print_data(digest, digest_len, "Digest");
				print_data(sig_info->sig, sig_info->sig_len, "Signature");

				int retssl = ssl_verify_signature_from_digest(
					(const char *)cert,
					strlen(cert) +
						1, //keep the NULL terminator to preserve previous behaviour
					(const uint8_t *)sig_info->sig, sig_info->sig_len, digest,
					digest_len, "SHA256");
				if (retssl != 0) {
					ERROR("Signature verification FAILED for %s", f);
					ret = -1;
					goto out;
				} else {
					INFO("Signature verification SUCCESSFUL for %s", f);
				}

				modsig_free(sig_info);

			} else if (strncmp(f, "n-ng", 4) == 0) {
				print_module_name(template->template_data + offset, field_len);
			}
		}

		offset += field_len;
	}

	ret = 0;

out:
	free(template_fmt);
	return ret;
}

static int
read_template_data(struct event *template, uint8_t **buf, size_t *remain)
{
	int len, is_ima_template;

	is_ima_template = strcmp(template->name, "ima") == 0 ? 1 : 0;
	if (!is_ima_template) {
		buf_read(&template->template_data_len, buf, sizeof(uint32_t), remain);
		len = template->template_data_len;
	} else {
		template->template_data_len = SHA_DIGEST_LENGTH + TCG_EVENT_NAME_LEN_MAX + 1;
		/*
		 * Read the digest only as the event name length
		 * is not known in advance.
		 */
		len = SHA_DIGEST_LENGTH;
	}

	template->template_data = calloc(template->template_data_len, sizeof(uint8_t));
	IF_NULL_RETVAL_ERROR(template->template_data, -1);

	buf_read(template->template_data, buf, len, remain);
	if (is_ima_template) { /* finish 'ima' template data read */
		uint32_t field_len = 0;

		buf_read(&field_len, buf, sizeof(uint32_t), remain);
		buf_read(template->template_data + SHA_DIGEST_LENGTH, buf, field_len, remain);
	}
	return 0;
}

static int
verify_template_hash(struct event *template)
{
	uint8_t digest[SHA_DIGEST_LENGTH];

	hash_sha1(digest, template->template_data, template->template_data_len);
	if (memcmp(digest, template->header.digest, sizeof digest) == 0) {
		return 0;
	}
	return -1;
}

int
ima_verify_binary_runtime_measurements(uint8_t *buf, size_t size, const char *cert,
				       hash_algo_t template_hash_algo, uint8_t *pcr_tpm)
{
	ASSERT(buf);
	ASSERT(cert);
	ASSERT(pcr_tpm);

	struct event template;
	uint8_t *ptr = buf;
	size_t remain = size;

	int hash_size = hash_algo_to_size(template_hash_algo);
	IF_FALSE_RETVAL_ERROR(hash_size > 0, -1);

	uint8_t pcr[hash_size];

	// PCRs are initialized with zero's
	memset(pcr, 0, hash_size);

	while (!buf_read(&template.header, &ptr, sizeof(template.header), &remain)) {
		TRACE("PCR %02d Measurement:", template.header.pcr);

		IF_TRUE_RETVAL(template.header.name_len > TCG_EVENT_NAME_LEN_MAX, -1);

		memset(template.name, 0, sizeof template.name);
		buf_read(template.name, &ptr, template.header.name_len, &remain);
		TRACE("Template: %s", template.name);

		if (read_template_data(&template, &ptr, &remain) < 0) {
			ERROR("Failed to read measurement entry %s", template.name);
			return -1;
		}

		if (verify_template_hash(&template) != 0) {
			ERROR("Failed to verify template hash for %s", template.name);
			return -1;
		}

		if (verify_template_data(&template, cert) != 0) {
			ERROR("Failed to parse measurement entry %s", template.name);
			return -1;
		}

		if (template_hash_algo == HASH_ALGO_SHA256) {
			// Even in case of SHA256 PCRs, the template hash is a SHA1 hash and cannot be used,
			// instead, the SHA256 hash of the template must be manually calculated to
			// extend the simulated PCR
			uint8_t template_hash[SHA256_DIGEST_LENGTH];
			hash_sha256(template_hash, template.template_data,
				    template.template_data_len);

			EVP_MD_CTX *c_256 = EVP_MD_CTX_new();
			EVP_DigestInit(c_256, EVP_sha256());
			EVP_DigestUpdate(c_256, pcr, SHA256_DIGEST_LENGTH);
			EVP_DigestUpdate(c_256, template_hash, SHA256_DIGEST_LENGTH);
			EVP_DigestFinal(c_256, pcr, NULL);
			EVP_MD_CTX_free(c_256);

		} else {
			ERROR("Hash algorithm not supported");
			return -1;
		}

		free(template.template_data);
	}

	if (memcmp(pcr, pcr_tpm, hash_size) != 0) {
		ERROR("Failed to verify the TPM PCR");
		return -1;
	}

	INFO("Verify IMA TPM PCR (kernel modules) SUCCESSFUL");

	return 0;
}
